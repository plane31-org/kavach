# @kavach/expo

The adapters an Expo app supplies to `@kavach/core`, as the Moyo implementation profile (Part II of `spec/Kavach-v1.md`, section 3) describes them. Each adapter is written against a small structural interface so it can be tested in Node with a fake, and driven on a device by the real module.

| Adapter | Over | Status |
| --- | --- | --- |
| `ExpoSecretStore` | `expo-secure-store`, `WHEN_UNLOCKED_THIS_DEVICE_ONLY`, no authentication prompt | complete |
| `SqliteStore` | `expo-sqlite` with SQLCipher (`PRAGMA key`, WAL, `synchronous = FULL`, finite `busy_timeout`, `BEGIN IMMEDIATE`) | complete; tested on Node's SQLite, SQLCipher keying tested by recorded statements |
| `BlockStoreRecoveryProvider` | Android Block Store through a native module implementing `BlockStoreLike` | logic complete; native module is a dev-build task |
| `AppleKeychainRecoveryProvider` | a synchronizable Keychain item through a native module implementing `SyncedKeychainLike` | logic complete; native module and config plugin are a dev-build task |
| `TrustedClock` | the platform clock with a durable high-water mark | complete |

## Wiring on a device

One call per account opens everything: the secret store namespaced by account, the storage key (read, or created and stored before the database is opened), the SQLCipher database under `kavach-<account>.db`, and the client.

```ts
import * as Crypto from "expo-crypto";
import * as SecureStore from "expo-secure-store";
import * as SQLite from "expo-sqlite";
import { openKavach, BlockStoreRecoveryProvider, AppleKeychainRecoveryProvider } from "@kavach/expo";

const { client, databaseFileName } = await openKavach({
  accountName,
  transport,          // the app's authenticated fetch and sockets, a `Transport` from "@kavach/core/adapters"
  recoveryProvider,   // BlockStoreRecoveryProvider on Android, AppleKeychainRecoveryProvider on iOS
  retentionPolicy,    // the global windows plus `kinds`: one { kind, retentionMs, queue, history, newest } per record kind the app uses
  resetTrust,
  secrets: { secureStore: SecureStore, thisDeviceOnly: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY, keychainService: "app.getmoyo" },
  database: SQLite,
  context: "foreground", // "background" in the location task
  getRandomValues: Crypto.getRandomValues, // Hermes has no Web Crypto; installed once, never a weaker fallback
  onListenerError: (e, event) => log(event.kind, e) // a throwing subscriber never reaches the protocol
});
```

Hermes has no `crypto.getRandomValues`, which the SDK's portable cipher suite draws its randomness from. `openKavach` installs the one you pass on the global when none exists and leaves an existing one alone; without either, opening fails with `INVALID_KEY` before any key is made. An app wiring the adapters by hand calls `installWebCrypto(Crypto.getRandomValues)` first.

The SDK knows no product kinds: the app declares its kinds in the policy and sends bytes with `client.enqueue(kind, payload, { eventTime, idempotencyKey })`. `client.newest(identityId, kind)` answers for the phone's own identity too: an enqueued record takes the own slot under the same rules a reader applies, and one `recordStored` event fires for self as for anyone. Payload codecs, typed helpers and the background location task belong to the app's profile, not to this package.

`client.sync()` returns a report whose `errors` list every step it worked around, each with the operation, the protocol code, the stage and whether a retry may succeed; `NETWORK` means the host was unreachable. Reading is bounded (500 records or 5 seconds by default, `sync({ catchUp: { maxRecords, maxMs } })` to change it) and `report.inbox.hasMore` says the relay still holds records: sync again at once. A keyed enqueue that returns has committed its record; the same key from a retry or the other runtime returns that record with `duplicate: true` for the delivery window. `eventTime` is what readers order a kind's newest slot by, clamped to the send time. Read history with `client.historyPage({ authorIdentityId, order: "desc", limit })` and pass its `cursor` back for the next page; `client.newestEntry(query)` gives the newest history entry.

Two accounts on one device never share a database or a secret. Only the foreground app creates the storage key on first run; a background task that finds none stops with `LOCKED` and tries again on its next wake, so two contexts can never provision one database under two different keys. Enable SQLCipher through the `expo-sqlite` config plugin (`useSQLCipher: true`), and exclude `databaseFileName` with its `-wal` and `-shm` companions from iCloud backup and Android auto-backup. Call `openKavach` once per JavaScript context: the foreground app and the background task each get their own connection, and SQLite's file lock serialises them.

When the database file survives but its key is gone (the secret store was cleared), SQLCipher refuses the new key and `openKavach` throws `RECOVERY_REQUIRED`: delete the file and restore the account through `client.restoreAccount()` on a fresh open.

### Advanced: the adapters one by one

`openKavach` is these steps; an app with a different arrangement (a shared database, its own key management) uses the adapters directly:

```ts
import { open } from "@kavach/core";
import { randomBytes } from "@kavach/core/adapters";
import { ExpoSecretStore, SqliteStore, expoSqliteDriver, installWebCrypto } from "@kavach/expo";

installWebCrypto(Crypto.getRandomValues);
const secretStore = new ExpoSecretStore(SecureStore, { thisDeviceOnly: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY, namespace: `kavach.${accountName}`, keychainService: "app.getmoyo" });
let storageKey = await secretStore.get("storageKey");
if (!storageKey) { storageKey = randomBytes(32); await secretStore.set("storageKey", storageKey); }
const db = SQLite.openDatabaseSync(`kavach-${accountName}.db`, { useNewConnection: true });
const store = SqliteStore.open({ driver: expoSqliteDriver(db), storageKey, busyTimeoutMs: 5000 });
const client = await open({ accountName, retentionPolicy, recoveryProvider, resetTrust, secretStore, store, transport });
```

## What the device tests must show (step 14 of the build sequence)

Foreground and background tasks write concurrently without a shared counter and the handoff race does not reproduce; the database refuses to open without the key; the recovery providers report the five statuses with sync off, locked and unavailable services; enrollment completes with the provider unavailable; a clock rollback yields `RESET_CLOCK_UNTRUSTED` without pausing sharing. The Android cloud-restore test to a second device is a release gate; record its device and Play services versions.

## Cipher suite backend

`@kavach/core` runs on the portable backend (the noble libraries, pure JavaScript) unless told otherwise, which is what Hermes needs: it has no WebAssembly. On Node, `import { loadSodiumBackend } from "@kavach/core/sodium"` and `setCryptoBackend(await loadSodiumBackend())` before `open()` selects libsodium. Both backends pass the same vectors.

`test/faults.sqlite.test.ts` runs the core's crash and lost-response sweeps over SQLite files on Node, as close to the phone's store as a test without the development build can get; the on-device run on SQLCipher is Moyo's gate.
