# @plane31/blind-relay-expo

The adapters an Expo app supplies to `@plane31/blind-relay`, as a product's implementation profile describes them (`spec/Profile-template.md`, section 4, lists what a profile decides). Each adapter is written against a small structural interface so it can be tested in Node with a fake, and driven on a device by the real module.

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
import { openKavach, BlockStoreRecoveryProvider, AppleKeychainRecoveryProvider } from "@plane31/blind-relay-expo";

const { client, databaseFileName } = await openKavach({
  accountName,
  transport,          // the app's authenticated fetch and sockets, a `Transport` from "@plane31/blind-relay/adapters"
  recoveryProvider,   // BlockStoreRecoveryProvider on Android, AppleKeychainRecoveryProvider on iOS
  retentionPolicy,    // the global windows plus `kinds`: one { kind, retentionMs, queue, history, newest } per record kind the app uses
  resetTrust,
  secrets: { secureStore: SecureStore, thisDeviceOnly: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY, keychainService: "com.example.app" },
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

When the database file survives but its key is gone (the secret store was cleared), SQLCipher refuses the new key and `openKavach` throws `RECOVERY_REQUIRED`: erase the account from the device (below) and set it up again.

**Closing and erasing.** `openKavach` returns `close()`: it closes the client (new operations are refused with `CLOSED`, the ones in flight finish, nothing is emitted afterwards), then the database connection it opened. To remove one account from the device, for instance a phone that another phone replaced, close it and call `eraseKavach({ accountName, secrets, database: SQLite })`: every secret the SDK keeps for the account and its database with the journal files go; another account on the device and the platform's synced recovery item stay. It is idempotent, and an erasure interrupted halfway is finished by running it again. Do not keep your own list of the SDK's secret names; `SECRET_NAMES` from `@plane31/blind-relay/adapters` is it.

**Syncing until done and replacing a phone.** `client.syncUntilDrained({ catchUp, maxRounds, maxMs })` repeats `sync` while the relay still holds records or bootstrap has circles left, within bounds, and returns the merged report with `rounds`, `stoppedBecause` and `remaining`; use it in the foreground and in a background wake instead of your own loop. On a new phone with no secret from the old one, `client.replaceDevice({ authorize })` runs account recovery end to end under the protocol's retry rules; `authorize` posts the proposal to your backend after a fresh sign-in and returns the token, or `"reauthenticate"` when the user must sign in first. It returns `activated`, `pending` (call again), `conflict` (sign in again; the next call prepares anew) or `reauthenticate`.

### Advanced: the adapters one by one

`openKavach` is these steps; an app with a different arrangement (a shared database, its own key management) uses the adapters directly:

```ts
import { open } from "@plane31/blind-relay";
import { randomBytes } from "@plane31/blind-relay/adapters";
import { ExpoSecretStore, SqliteStore, expoSqliteDriver, installWebCrypto } from "@plane31/blind-relay-expo";

installWebCrypto(Crypto.getRandomValues);
const secretStore = new ExpoSecretStore(SecureStore, { thisDeviceOnly: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY, namespace: `kavach.${accountName}`, keychainService: "com.example.app" });
let storageKey = await secretStore.get("storageKey");
if (!storageKey) { storageKey = randomBytes(32); await secretStore.set("storageKey", storageKey); }
const db = SQLite.openDatabaseSync(`kavach-${accountName}.db`, { useNewConnection: true });
const store = SqliteStore.open({ driver: expoSqliteDriver(db), storageKey, busyTimeoutMs: 5000 });
const client = await open({ accountName, retentionPolicy, recoveryProvider, resetTrust, secretStore, store, transport });
```

## What the device tests must show (step 14 of the build sequence)

Foreground and background tasks write concurrently without a shared counter and the handoff race does not reproduce; the database refuses to open without the key; the recovery providers report the five statuses with sync off, locked and unavailable services; enrollment completes with the provider unavailable; a clock rollback yields `RESET_CLOCK_UNTRUSTED` without pausing sharing. The Android cloud-restore test to a second device is a release gate; record its device and Play services versions.

## Cipher suite backend

`@plane31/blind-relay` runs on the portable backend (the noble libraries, pure JavaScript) unless told otherwise. Both backends pass the same vectors, so the choice changes nothing on the wire, only the time a signature, a verification or an epoch's sealed boxes take: Ed25519 and X25519 in pure JavaScript cost milliseconds each on a phone, and a rotation in a large circle seals one box per member.

**On a device, pass a native libsodium binding.** Install `react-native-libsodium` (libsodium over JSI) and hand it to `openKavach` as `crypto`; the helper awaits its `ready` and installs the backend process-wide before the client opens. An app wiring the adapters by hand calls `installNativeCrypto(sodium)` first; it returns which operations run on the binding and which stayed portable. Import the binding as a namespace: its default export lacks `crypto_sign_seed_keypair`, and the backend refuses a binding without it. The namespace is assignable to `crypto` as the binding types it, with no cast.

```ts
import * as sodium from "react-native-libsodium";
const setup = await openKavach({ ..., getRandomValues: Crypto.getRandomValues, crypto: sodium });
console.log(setup.cryptoBackend); // { kind: "native", report?: { native: [...], portable: [...] } } or { kind: "portable", reason?: string }
```

Each function the binding provides is checked once, at install, against the portable implementation on known inputs. What the binding lacks, or cannot do on the protocol's inputs, stays portable with the same rule. A binding that cannot be used at all, because a required function is missing (its native side never installed), because one disagrees with the portable implementation, or because `ready` rejected, is never used: by default the client opens on the portable backend, which is the reference the binding is checked against and reads and writes the same bytes, and `setup.cryptoBackend` carries the reason, so a performance option never keeps the app from opening. Pass `cryptoFallback: "refuse"` to make it fatal instead (`openKavach` throws the `INVALID_KEY`). `cryptoBackend` reads the process's active backend, so an app that calls `installNativeCrypto` itself and opens without `crypto` sees `native` too. Log it once in a release build to know what it runs. Nothing on the wire depends on the split. Without `crypto`, the portable backend stays.

With react-native-libsodium 1.7 the signatures, the boxes and the hash run native, which is where the time goes; the AEAD stays portable because that binding accepts only string associated data while the protocol's is binary, and the X25519 agreement, the validity check and `memzero` stay portable because the binding does not expose them at run time (its type declarations list them).

**Tested where.** The SDK's own tests run the backend on Node over `libsodium-wrappers-sumo` 0.7.16, with the binding's shape (which functions are absent, string-only associated data) reproduced in a test double; the self-check at install is what makes a real binding safe to use. On devices the first product reported react-native-libsodium 1.7.0 on Expo SDK 58 and React Native 0.88: Android works as installed; iOS does not build, because `ios/Libsodium.mm` casts the bridge to `RCTCxxBridge`, which 0.88 removed, and a naive fix compiles but never installs the JSI functions under bridgeless mode (the `bridge` is an `RCTBridgeProxy`, an `NSProxy`, so `respondsToSelector:` answers NO for `runtime`; checking with `class_respondsToSelector(object_getClass(bridge), @selector(runtime))` works). Until the binding ships a TurboModule fix, patch it (`patch-package`) and keep the default fallback, which turns a binding that failed to install into a slower app rather than one that does not open. Report the versions you run to the SDK's issue tracker so this list stays current.

**pnpm 10 skips the binding's postinstall**, which unpacks its prebuilt libraries (the iOS podspec unpacks on its own; the gap is Android). In a pnpm workspace, allow it in `pnpm-workspace.yaml`:

```yaml
onlyBuiltDependencies:
  - react-native-libsodium
```

On Node, `import { loadSodiumBackend } from "@plane31/blind-relay/sodium"` and `setCryptoBackend(await loadSodiumBackend())` before `open()` selects the wasm build of libsodium.

`test/faults.sqlite.test.ts` runs the core's crash and lost-response sweeps over SQLite files on Node, as close to the phone's store as a test without the development build can get; the on-device run on SQLCipher is the product's release gate.
