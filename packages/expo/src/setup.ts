/**
 * One call to get a ready client on a device: the secret store, the storage key, the SQLCipher
 * database and `open()`, wired the way the profile (section 3) describes. Everything is kept per
 * account name, so two accounts on one device never share a database or a secret. The individual
 * adapters stay exported for apps that need a different arrangement.
 */
import { KavachError, open, type Client, type ClientEvent, type RecoveryProvider, type ResetTrustConfig, type RetentionPolicy } from "@plane31/blind-relay";
import { SECRET_NAMES, randomBytes, type SecretStore, type Transport } from "@plane31/blind-relay/adapters";
import { ExpoSecretStore, type SecureStoreLike } from "./secretStore.js";
import { SqliteStore, expoSqliteDriver, type ExpoSqliteDatabaseLike, type SqlDriver } from "./sqliteStore.js";

/** The subset of `expo-sqlite` the helper uses. */
export interface ExpoSqliteLike {
  openDatabaseSync(name: string, options?: { useNewConnection?: boolean }): ExpoSqliteDatabaseLike;
  /** Delete a database file and its journal; `eraseKavach` needs it. */
  deleteDatabaseSync?(name: string): void;
}

export interface KavachSetupOptions {
  readonly accountName: string;
  readonly transport: Transport;
  /** Required when the retention policy enables identity continuity; a recovery-only profile may omit it (core enforces this at open). */
  readonly recoveryProvider?: RecoveryProvider;
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
  /** Forwarded to `open()`: called when a subscriber throws, which is otherwise silent. */
  readonly onListenerError?: (error: unknown, event: ClientEvent) => void;
  /**
   * The secure random source for Hermes, which has no `crypto.getRandomValues`: pass
   * `expo-crypto`'s `getRandomValues`. Installed on the global once when none exists, left alone
   * when one does. Without it, and with no global, opening fails with `INVALID_KEY` before any
   * key is made; nothing ever falls back to a weaker source.
   */
  readonly getRandomValues?: GetRandomValues;
}

export type GetRandomValues = <T extends ArrayBufferView>(array: T) => T;

/**
 * Install `getRandomValues` as the Web Crypto global when the runtime has none (Hermes), and
 * leave an existing one untouched. `scope` is the global object; tests pass their own.
 */
export function installWebCrypto(getRandomValues: GetRandomValues | undefined, scope: { crypto?: { getRandomValues?: unknown } } = globalThis as { crypto?: { getRandomValues?: unknown } }): void {
  if (typeof scope.crypto?.getRandomValues === "function") return;
  if (!getRandomValues) throw new KavachError("INVALID_KEY", "openKavach", "no crypto.getRandomValues: pass expo-crypto's getRandomValues");
  if (scope.crypto) scope.crypto.getRandomValues = getRandomValues;
  else scope.crypto = { getRandomValues };
}

export interface KavachSetup {
  readonly client: Client;
  readonly store: SqliteStore;
  readonly secretStore: SecretStore;
  /** The database file to exclude from backups, with its `-wal` and `-shm` companions. */
  readonly databaseFileName: string;
  /** Close the client (operations in flight finish, nothing is emitted afterwards), then the database connection this call opened. Idempotent. */
  close(): Promise<void>;
}

export interface KavachEraseOptions {
  readonly accountName: string;
  readonly secrets: KavachSetupOptions["secrets"];
  /** `expo-sqlite` (its `deleteDatabaseSync` removes the file), or the test driver factory with `deleteDatabase` beside it. */
  readonly database: ExpoSqliteLike | ((fileName: string) => SqlDriver);
  /** With a driver factory: how to remove the database file and its `-wal` and `-shm` companions. */
  readonly deleteDatabase?: (fileName: string) => void;
  readonly namespace?: string;
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
  installWebCrypto(options.getRandomValues);
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
    ...(options.recoveryProvider ? { recoveryProvider: options.recoveryProvider } : {}),
    resetTrust: options.resetTrust,
    secretStore,
    store,
    transport: options.transport,
    ...(options.now ? { now: options.now } : {}),
    ...(options.onListenerError ? { onListenerError: options.onListenerError } : {})
  });
  let closed: Promise<void> | undefined;
  const close = (): Promise<void> => {
    closed ??= (async () => {
      await client.close();
      await store.close();
    })();
    return closed;
  };
  return { client, store, secretStore, databaseFileName: fileName, close };
}

/**
 * Erase one account from this device: every secret the SDK keeps for it, then its database with
 * the journal files. Close the account's `KavachSetup` first; this touches nothing it did not
 * open and nothing of another account, and never the platform's synced recovery item. The
 * account's roots go first and the storage key last, so an erasure interrupted halfway leaves a
 * database that refuses to open (`RECOVERY_REQUIRED`) rather than secrets that would re-enroll
 * under old roots; running it again finishes it. Idempotent.
 */
export async function eraseKavach(options: KavachEraseOptions): Promise<void> {
  const namespace = options.namespace ?? "kavach";
  const fileName = databaseFileName(options.accountName, namespace);
  const secretStore =
    "secureStore" in options.secrets
      ? new ExpoSecretStore(options.secrets.secureStore, { thisDeviceOnly: options.secrets.thisDeviceOnly, namespace: `${namespace}.${options.accountName}`, ...(options.secrets.keychainService ? { keychainService: options.secrets.keychainService } : {}) })
      : options.secrets;
  for (const name of SECRET_NAMES) await secretStore.delete(name);
  const database = options.database;
  const remove = typeof database === "function" ? options.deleteDatabase : database.deleteDatabaseSync ? (name: string) => database.deleteDatabaseSync?.(name) : undefined;
  if (!remove) throw new KavachError("MALFORMED", "eraseKavach", "no way to delete the database: pass expo-sqlite, or deleteDatabase with a driver factory");
  try {
    remove(fileName);
  } catch {
    /* already gone */
  }
}
