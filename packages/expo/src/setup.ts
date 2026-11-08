/**
 * One call to get a ready client on a device: the secret store, the storage key, the SQLCipher
 * database and `open()`, wired the way the profile (section 3) describes. Everything is kept per
 * account name, so two accounts on one device never share a database or a secret. The individual
 * adapters stay exported for apps that need a different arrangement.
 */
import { KavachError, open, setCryptoBackend, type Client, type ClientEvent, type RecoveryProvider, type ResetTrustConfig, type RetentionPolicy } from "@plane31/blind-relay";
import { SECRET_NAMES, backendName, buildSodiumBackend, currentBackend, nobleBackend, randomBytes, type CryptoBackend, type SecretStore, type SodiumBackendReport, type SodiumLike, type Transport } from "@plane31/blind-relay/adapters";
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
  /**
   * A native libsodium binding (`react-native-libsodium`, over JSI; import it as a namespace,
   * since its default export lacks `crypto_sign_seed_keypair`) to run the cipher suite on instead
   * of the portable pure-JavaScript backend: Ed25519 signatures and X25519 boxes are many times
   * faster, which is what a record and an epoch's sealed boxes cost. Awaited (`ready`) and
   * installed process-wide before the client opens; absent, the portable backend stays. See
   * `installNativeCrypto` for what stays portable on a given binding, and `cryptoFallback` for a
   * binding that cannot be used.
   */
  readonly crypto?: SodiumLike & { readonly ready?: Promise<unknown> };
  /**
   * What happens when `crypto` cannot be used (a function missing because the binding's native
   * side never installed, one that disagrees with the portable implementation, or `ready`
   * rejecting). `portable`, the default: the client opens on the portable backend, which is the
   * reference the binding is checked against and reads and writes the same bytes, and
   * `KavachSetup.cryptoBackend` names the reason, so a performance option never keeps the app
   * from opening. `refuse`: `openKavach` throws the `INVALID_KEY` (or the rejection) instead.
   */
  readonly cryptoFallback?: "portable" | "refuse";
}

/**
 * Which cipher-suite backend the client opened on, read from the process, not from the options:
 * the backend is process-wide, so an app that called `installNativeCrypto` itself and opens
 * without `crypto` is `native` too. `native` carries the per-function split when the binding
 * went through `installNativeCrypto` (a backend set by other means has none); `portable` carries
 * a `reason` when this call was given a binding and could not use it. A release build logs this
 * once to know what it runs.
 */
export type CryptoBackendStatus = { readonly kind: "native"; readonly report?: SodiumBackendReport } | { readonly kind: "portable"; readonly reason?: string };

/** The backend `installNativeCrypto` last installed, with its report: the report is only ever attached to that instance. */
let installed: { readonly backend: CryptoBackend; readonly report: SodiumBackendReport } | undefined;

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
  /** The cipher-suite backend in use: native with its split, or portable, with the reason when a binding was refused. */
  readonly cryptoBackend: CryptoBackendStatus;
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
/**
 * Run the cipher suite on a native libsodium binding. Process-wide, like the Web Crypto install;
 * `openKavach` calls it when given `crypto`. Each function the binding provides is checked once
 * against the portable implementation; what it lacks, or cannot do on the protocol's binary
 * inputs, stays portable, and the report says which (react-native-libsodium 1.7 runs the AEAD,
 * X25519 agreement and the validity check portable, signatures and boxes native). A binding that
 * answers differently on the same input is refused with `INVALID_KEY`. Nothing on the wire changes.
 */
export async function installNativeCrypto(sodium: SodiumLike & { readonly ready?: Promise<unknown> }): Promise<SodiumBackendReport> {
  if (sodium.ready) await sodium.ready;
  const { backend, report } = buildSodiumBackend(sodium);
  setCryptoBackend(backend);
  installed = { backend, report };
  return report;
}

/**
 * `openKavach`'s use of `installNativeCrypto`, with the fallback, then the status read from the
 * active backend. On a refused binding the portable backend is installed explicitly, so the
 * status is what the process runs on, whatever an earlier call installed.
 */
async function selectCryptoBackend(options: Pick<KavachSetupOptions, "crypto" | "cryptoFallback">): Promise<CryptoBackendStatus> {
  let reason: string | undefined;
  if (options.crypto) {
    try {
      await installNativeCrypto(options.crypto);
    } catch (e) {
      if (options.cryptoFallback === "refuse") throw e;
      setCryptoBackend(nobleBackend);
      reason = e instanceof Error ? e.message : String(e);
    }
  }
  // The report belongs to one backend instance; a sodium backend installed by other means (another binding, the Node entry) gets none.
  if (backendName() === "sodium") return installed && installed.backend === currentBackend() ? { kind: "native", report: installed.report } : { kind: "native" };
  return reason === undefined ? { kind: "portable" } : { kind: "portable", reason };
}

export async function openKavach(options: KavachSetupOptions): Promise<KavachSetup> {
  installWebCrypto(options.getRandomValues);
  const cryptoBackend = await selectCryptoBackend(options);
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
  return { client, store, secretStore, databaseFileName: fileName, close, cryptoBackend };
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
  // The capability first, before anything is deleted: an erasure that cannot finish must not start.
  const database = options.database;
  const remove = typeof database === "function" ? options.deleteDatabase : database.deleteDatabaseSync ? (name: string) => database.deleteDatabaseSync?.(name) : undefined;
  if (!remove) throw new KavachError("MALFORMED", "eraseKavach", "no way to delete the database: pass expo-sqlite, or deleteDatabase with a driver factory");
  for (const name of SECRET_NAMES) await secretStore.delete(name);
  try {
    remove(fileName);
  } catch (e) {
    // Only a file that is already gone is success. Anything else (permissions, a busy file) is
    // reported; the secrets are gone, the database stays unreadable, and running this again finishes.
    if (isMissingFile(e)) return;
    throw new KavachError("STORAGE_FAILURE", "eraseKavach", `the database could not be deleted (${e instanceof Error ? e.message : String(e)}); run eraseKavach again`);
  }
}

function isMissingFile(e: unknown): boolean {
  const code = typeof e === "object" && e !== null && "code" in e ? String((e as { code: unknown }).code) : "";
  const message = e instanceof Error ? e.message : String(e);
  return code === "ENOENT" || /no such file|not found|does not exist|doesn't exist/i.test(message);
}
