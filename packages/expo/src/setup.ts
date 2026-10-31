/**
 * One call to get a ready client on a device: the secret store, the storage key, the SQLCipher
 * database and `open()`, wired the way the profile (section 3) describes. Everything is kept per
 * account name, so two accounts on one device never share a database or a secret. The individual
 * adapters stay exported for apps that need a different arrangement.
 */
import { KavachError, open, type Client, type RecoveryProvider, type ResetTrustConfig, type RetentionPolicy } from "@kavach/core";
import { randomBytes, type SecretStore, type Transport } from "@kavach/core/adapters";
import { ExpoSecretStore, type SecureStoreLike } from "./secretStore.js";
import { SqliteStore, expoSqliteDriver, type ExpoSqliteDatabaseLike, type SqlDriver } from "./sqliteStore.js";

/** The subset of `expo-sqlite` the helper uses. */
export interface ExpoSqliteLike {
  openDatabaseSync(name: string, options?: { useNewConnection?: boolean }): ExpoSqliteDatabaseLike;
}

export interface KavachSetupOptions {
  readonly accountName: string;
  readonly transport: Transport;
  readonly recoveryProvider: RecoveryProvider;
  readonly retentionPolicy: RetentionPolicy;
  readonly resetTrust: ResetTrustConfig;
  /**
   * Where secrets live: `expo-secure-store` with its device-only constant (the helper namespaces
   * the keys by account), or a ready `SecretStore` (tests, or an app with its own arrangement).
   */
  readonly secrets: { readonly secureStore: SecureStoreLike; readonly thisDeviceOnly: unknown; readonly keychainService?: string } | SecretStore;
  /** Where the database lives: `expo-sqlite`, or a driver factory given the database file name (tests). */
  readonly database: ExpoSqliteLike | ((fileName: string) => SqlDriver);
  /**
   * Which JavaScript context this is. Only the foreground app creates the storage key on first
   * run; a background task that finds none stops with `LOCKED` instead of minting its own, so two
   * contexts can never race to provision one database under two keys.
   */
  readonly context: "foreground" | "background";
  /** Prefix of database file names and secret keys. Defaults to `kavach`. */
  readonly namespace?: string;
  /** Finite: a waiting writer fails with `LOCKED` after this. Default 5,000 ms. */
  readonly busyTimeoutMs?: number;
  readonly now?: () => bigint;
}

export interface KavachSetup {
  readonly client: Client;
  readonly store: SqliteStore;
  readonly secretStore: SecretStore;
  /** The database file to exclude from backups, with its `-wal` and `-shm` companions. */
  readonly databaseFileName: string;
}

const NAME_RULE = /^[A-Za-z0-9_-]{1,64}$/;

/** First-run provisioning in flight per account, so concurrent opens in one context share one key. */
const provisioning = new Map<string, Promise<Uint8Array>>();

async function storageKeyFor(secretStore: SecretStore, slot: string, context: "foreground" | "background"): Promise<Uint8Array> {
  const existing = await secretStore.get("storageKey");
  if (existing) return existing;
  if (context !== "foreground") throw new KavachError("LOCKED", "openKavach", "no storage key yet: the foreground app provisions it");
  let inflight = provisioning.get(slot);
  if (!inflight) {
    // One chain: the cleanup rides on the promise every caller awaits, so a failed write rejects
    // exactly once, to the callers, and never as a stray unhandled rejection.
    inflight = (async () => {
      const again = await secretStore.get("storageKey");
      if (again) return again;
      const key = randomBytes(32);
      await secretStore.set("storageKey", key);
      return key;
    })().finally(() => provisioning.delete(slot));
    provisioning.set(slot, inflight);
  }
  return inflight;
}

/** The database file name for an account under a namespace, also what the backup exclusion needs. */
export function databaseFileName(accountName: string, namespace = "kavach"): string {
  if (!NAME_RULE.test(accountName)) throw new KavachError("MALFORMED", "openKavach", "account name");
  return `${namespace}-${accountName}.db`;
}

/**
 * Open the client for one account. The storage key is read from the secret store; the foreground
 * app creates one when there is none, serialised per account, and stores it before the database
 * is opened, so a crash in between leaves a key and no database, never a database under a lost
 * key. A background context that finds no key stops with `LOCKED` and tries again on its next
 * wake. When the database exists but its key is gone (the secret store was cleared while the file
 * survived), SQLCipher refuses the new key and this throws `RECOVERY_REQUIRED`: the app deletes
 * the file and restores the account from its recovery provider.
 */
export async function openKavach(options: KavachSetupOptions): Promise<KavachSetup> {
  const namespace = options.namespace ?? "kavach";
  const fileName = databaseFileName(options.accountName, namespace);
  const secretStore =
    "secureStore" in options.secrets
      ? new ExpoSecretStore(options.secrets.secureStore, { thisDeviceOnly: options.secrets.thisDeviceOnly, namespace: `${namespace}.${options.accountName}`, ...(options.secrets.keychainService ? { keychainService: options.secrets.keychainService } : {}) })
      : options.secrets;
  const storageKey = await storageKeyFor(secretStore, `${namespace}.${options.accountName}`, options.context);
  const driver = typeof options.database === "function" ? options.database(fileName) : expoSqliteDriver(options.database.openDatabaseSync(fileName, { useNewConnection: true }));
  const store = SqliteStore.open({ driver, storageKey, ...(options.busyTimeoutMs !== undefined ? { busyTimeoutMs: options.busyTimeoutMs } : {}) });
  const client = await open({
    accountName: options.accountName,
    retentionPolicy: options.retentionPolicy,
    recoveryProvider: options.recoveryProvider,
    resetTrust: options.resetTrust,
    secretStore,
    store,
    transport: options.transport,
    ...(options.now ? { now: options.now } : {})
  });
  return { client, store, secretStore, databaseFileName: fileName };
}
