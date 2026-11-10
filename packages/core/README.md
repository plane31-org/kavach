# @plane31/blind-relay

The Kavach v1 protocol in pure TypeScript: end-to-end encrypted, relayed, durable records between a person's devices and the devices of the people they share with, for circles of up to 100 accounts, through a server that stores only what it cannot open and deletes each record once every reader has it. The package is product-agnostic: a product declares its record kinds and keeps its payload codecs in its own profile. The specification is `spec/Kavach-v1.md` in the repository; `spec/Profile-template.md` lists what a product decides.

Status: protocol revision 11, package 0.x. The primitives are audited libraries; the composition is not yet independently reviewed, and nothing here is production-ready. The API may change between 0.x minor versions; the protocol revision is tracked separately in the specification.

```
pnpm add @plane31/blind-relay
```

## Entry points

- `@plane31/blind-relay`: `open` and the `Client` with `enqueue`, `newest`, `historyPage`, `sync`, the circles API, `subscribe` and `inspect`; the `KindDeclaration` and `RetentionPolicy` a product passes to `open`; `KavachError` and `ErrorCode`; the `RecoveryProvider` contract; `toHex`, `fromHex` and `equalBytes`.
- `@plane31/blind-relay/adapters`: the `Store`, `Tx`, `SecretStore`, `Transport`, `Directory` and `Relay` contracts an adapter or host implements, with the table and row types; `MemoryStore` and `MemorySecretStore` as the behavioural reference; the signed-document codec a host verifies with; `buildResetKeyList` and `buildResetReceipt` for a host's key tooling.
- `@plane31/blind-relay/testing`: the fault harness (a fake host, a crashing store, a malicious transport, the crash and lost-response sweeps) and the fixtures a test builds protocol state with.
- `@plane31/blind-relay/sodium`: the optional libsodium backend for Node (wasm). The default backend is portable JavaScript; `sodiumBackend(sodium)` from the adapters entry builds the libsodium backend over any object with libsodium's API, which is how a phone runs the cipher suite natively (`@plane31/blind-relay-expo` wires `react-native-libsodium` through `openKavach`'s `crypto` option).

Randomness comes from the Web Crypto global. A runtime without one (Hermes) installs it first; `@plane31/blind-relay-expo` does that from `expo-crypto`.

## Using it well

**A heartbeat is an empty record of a slot kind.** To say "still here" without publishing anything, declare a kind with `queue: "latestWins"`, `history: false`, `newest: true` and `headerClass: 2` (silent: no notification, no wake-up), and enqueue it with an empty payload. It is still end-to-end encrypted and peer-authenticated, costs about 160 bytes on the wire, collapses in the outbox when several are queued, is kept as one slot row per author on the reader with no history, and is deleted by the relay once every reader has it. There is no separate presence primitive, on purpose: anything peers could not authenticate would be the first such thing in the protocol.

**High-frequency transient signals are slot kinds too.** Live position, speed, heading, battery: declare the kind `latestWins` with `history: false`, and only the newest frame per author is stored; the relay keeps a frame only until every reader has it. Nothing in the host needs to overwrite records in place, and nothing could, since the relay cannot open them or know who already holds one. The record counter stays monotonic because replay protection depends on it; it costs nothing.

**Short background windows.** `sync({ catchUp: { maxRecords, maxMs }, skipMaintenance: true })` reads within a budget and leaves the retention purge, the periodic reset-key-list re-check and the recovery-key re-save to the next foreground sync (`report.maintenance` says which). `syncUntilDrained({ maxRounds, maxMs, skipMaintenance })` runs rounds within a soft time bound and says why it stopped. `report.timings` gives wall-clock milliseconds per phase and the bytes moved, so a budget overrun can be attributed. Opening the encrypted store in a fresh background context is the platform's cost, not the SDK's; measure it separately.

**Header classes 4 to 7 (revision 11).** The class is three header bits the relay may see, 0 to 7, with no meaning in the protocol: the product's host decides which values wake readers and how it stores each. A reader or host before revision 11 rejects a class above 3 as malformed, and the SDK cannot know when the field has moved, so the order is: the host first, then every reader on a revision 11 SDK with no kind above 3, then senders declaring the new values.

**Introducing a record kind.** Ship the readers first where you can, but a reader that meets a kind its policy does not declare is not in trouble: the record authenticated and opened, so it is an authorized author's and the author's app is newer. The reader skips it, counts it (`report.inbox.unknownKind`) and emits `unknownKind` with the author, which is the moment to suggest an update. No `securityError` is raised; those are for records that fail authentication or equivocate. An enqueue of a kind the sender did not declare is still `MALFORMED`.

**What to do on each error.** `KavachError.code` is a closed union and `retryable` says whether the same call may succeed later unchanged; `stage` is for logs, never for branching.

| Code | Meaning | What the app does |
| --- | --- | --- |
| `NETWORK` | The host could not be reached or did not answer in time | Nothing now; retry on the next wake |
| `RATE_LIMITED` | The host asked for a pause; `retryAfterMs` says how long when it said | Back off at least that long |
| `LOCKED` | Another context holds the store, or a background task found no storage key yet | Retry later; the foreground provisions the key |
| `CLOSED` | The client was closed | Open a new one |
| `SUPERSEDED_DEVICE` | Another phone is the account's device now; the state is `retired` | Sign the user out of this phone; offer to set it up again |
| `ACCOUNT_RECOVERY_REQUIRED` | No account on this device, or recovery found nothing | Enroll, restore (continuity) or replace (recovery) |
| `AUTHORIZATION_REQUIRED` | The host refused the replacement authorization | Obtain a fresh one for the same proposal (`replaceDevice` does this) |
| `REPLACEMENT_CONFLICT` | The account moved under the proposal | Fresh sign-in, then `replaceDevice` again |
| `SUCCESSION_PENDING` | The replacement's outcome is unknown | Call again with the same proposal |
| `METADATA_REQUIRED`, `KEY_PENDING`, `RESET_KEYS_REQUIRED` | Something the host has not served yet | Nothing; the next sync retries |
| `ROTATION_REQUIRED`, `QUEUE_FULL` | The outbox cannot take this record now | Sync, then enqueue again |
| `EQUIVOCATION`, `ROLLBACK`, `BAD_SIGNATURE`, `ACCOUNT_KEY_CHANGED` | The host or a peer served something that does not verify | Show the security notice the profile defines; do not retry blindly |
| `RECOVERY_REQUIRED` | The local store and the secret store no longer match | Erase the account from the device and set it up again |

Waiting on another person is not an error: `ClientState.waitingFor` lists authors whose current epoch has not reached this device yet, and the `waiting` event fires as it happens.

## Development

```
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

The test suite runs under both cipher-suite backends and against the frozen conformance vectors. Apache-2.0.
