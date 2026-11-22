# @plane31/blind-relay

The Kavach v1 protocol in pure TypeScript: end-to-end encrypted, relayed, durable records between a person's devices and the devices of the people they share with, for circles of up to 100 accounts, through a server that stores only what it cannot open and deletes each record once every reader has it. The package is product-agnostic: a product declares its record kinds and keeps its payload codecs in its own profile. The specification is `spec/Kavach-v1.md` in the repository; `spec/Profile-template.md` lists what a product decides.

Status: protocol revision 13, package 0.x. The primitives are audited libraries; the composition is not yet independently reviewed, and nothing here is production-ready. The API may change between 0.x minor versions; the protocol revision is tracked separately in the specification.

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

**Quick syncs (revision 12).** For a routine wake-up, `sync({ mode: "quick" })` skips the membership and key metadata and reads only the streams the host's change check (`relay.syncState`) shows something new for; on a typical phone that is two or three requests instead of eight. It needs `fullSyncEveryMs` in `open()` (no default) and a transport with `syncState`. It runs full by itself, and says so in `report.promotedBecause`, when unfinished work needs the metadata, after the host refused records as `AUDIENCE_STALE`, before the first full sync, and once the last full sync is older than `fullSyncEveryMs`. Choose that period knowing what it delays: a removal and a contact's new key are learned at the next full sync. Keep `sync()` (full) for the foreground.

**When the host fences a stale audience.** A host may refuse an append whose epoch still addresses someone who left (`AUDIENCE_STALE`). Nothing is lost: the records are held (`report.outbox.held`, the `audienceStale` event), the next sync runs full and rotates, and each record is sealed once more under the new epoch with a new id. The `resealed` event names the old and the new id; an app that kept record ids follows it. A record refused a second time is cancelled with reason `AUDIENCE_STALE`. The outbox keeps payloads until acceptance to make this possible.

**Track a record by its local id (0.9.0).** `enqueue` returns a `localId` that names the record for its whole life: on `queued`, `accepted`, `cancelled` and `resealed`, with the idempotency key when you gave one, and in `client.delivery(localId)`, which answers `queued`, `held`, `accepted`, `cancelled` with its reason, or `unknown`, from the store, so any runtime sharing it can ask. Keep the local id, not the record id: a deferred seal and a reseal change the record id under it. Events fire only in the runtime that did the work; the delivery query is how the other runtime learns the outcome.

**Nothing queued is lost to an audience change (revision 13).** A membership change, a member's new phone or a hygiene rotation holds the records still queued and seals them again under an epoch that may carry them: first a catch-up epoch to the earlier audience when someone joined, so a joiner never reads what was queued before it, then the epoch to everyone. A record already sent once is retried as it is. `delivery(localId)` shows such a record as `held` until it goes out. What is still given up (past its window, superseded, on a retired device) is reported with `cancelled`.

**`enqueue` does not fail for a rotation.** When no epoch is usable now (a rotation pending, metadata missing, an `AUDIENCE_STALE` fence, the host unreachable), the record is queued unsealed and sealed at the next sync, in order; `recordId` is then absent from the result and arrives with `accepted`. An unsealed record is not yet in your own history or newest slot. `RECIPIENT_LIMIT` and `QUEUE_FULL` stay errors. No retry wrapper is needed.

**One drain at a time.** `syncUntilDrained` shares a running drain the way `sync` shares a running sync: a quick request shares any, a full one shares a full one and otherwise runs after the quick one. Each report has an `opId`; a transport that implements `attach` sees it on every call, with the current device. Debouncing stays with the app.

**The HTTP transport.** `import { httpTransport } from "@plane31/blind-relay/http"` with `baseUrl` set to where the reference routes are mounted (`https://host/v1`, or `${API_URL}/v1/kavach`). `headers` returns your authentication, synchronously; the transport adds `x-kavach-device`, `x-kavach-op` and, on appends, `kavach-revision`, and types failures as the transport error contract says, naming the host's `x-request-id`.

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
| `UNSUPPORTED_OPERATION` | The host lacks an operation the client needs (a quick sync against a host without `sync-state`) | A deployment mismatch: ship the host first, or sync full; never retry |

Waiting on another person is not an error: `ClientState.waitingFor` lists authors whose current epoch has not reached this device yet, and the `waiting` event fires as it happens.

## Development

```
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

The test suite runs under both cipher-suite backends and against the frozen conformance vectors. Apache-2.0.
