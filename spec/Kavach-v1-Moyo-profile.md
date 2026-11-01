# Kavach v1: Moyo implementation profile

How Moyo's Expo app and Cloudflare Worker implement the Kavach v1 protocol (`spec/Kavach-v1.md`, revision 8): the record kinds and payload codecs, platform adapters, server mapping, retention values, product behaviour and release gates. The protocol specification names no product concept; everything here is Moyo's, and this document belongs with Moyo. It is kept in the SDK repository only until it moves to Moyo's repository; the SDK keeps `spec/Profile-template.md`, which lists what any profile must decide.

**Contents**

- 1. What this profile decides
- 2. Retention policy
- 2a. Record kinds, codecs and notifications
- 3. Client adapters (Expo)
- 4. Server (Cloudflare Worker)
- 5. Product behaviour the protocol depends on
- 6. Release gates and device tests
- 7. Build order

### 1. What this profile decides

The protocol specification states requirements and leaves the host to choose how to meet them. Moyo's choices are:

| Decision left to the host | Moyo's choice |
| --- | --- |
| Protected secret store | Expo SecureStore with device-only accessibility for `accountSeed`, `deviceSeed`, `recoveryKey`, `storageKey` and the store instance id. |
| Encrypted transactional store | Expo SQLite with SQLCipher, keyed by `storageKey`, WAL, `synchronous = FULL`. Write transactions use `BEGIN IMMEDIATE`; the outbound handoff is initiated inside the transaction. |
| Cross-process writer lock | SQLite's own file lock under `BEGIN IMMEDIATE`. No native lock module. |
| Platform recovery provider | Apple synced Keychain on iOS. Android Block Store with the end-to-end encryption check on Android, required for release. |
| Directory and relay | A Cloudflare Worker: D1 for the directory, one `UserDO` per author as the relay, `CircleDO` for presence and wake-ups. |
| Notifications | Expo push. Visible for a join request (to the owner) and a check-in (to each recipient); silent otherwise. |
| Reset authority | An operational key as a Worker secret; a management key kept offline that signs a new key list every 14 days with a 30-day lifetime. |
| Retention | The values in section 2, supplied to `open()` as a versioned policy. |
| Sync interval | 60 seconds while the app is online and running, plus hints and background wake-ups. |

Everything the protocol forbids remains forbidden here. Where this document and the protocol disagree, the protocol wins and this document has a bug.

### 2. Retention policy

Moyo passes the following `RetentionPolicy` to `open()`. The values are proposals to confirm before release; the shape is fixed by the protocol.

| Field | Proposed value | Meaning |
| --- | --- | --- |
| `deliveryWindowMs` | 24 hours | How long the relay keeps a record for readers that have not acknowledged it, from acceptance. One window for locations and check-ins keeps expiry a prefix per stream. A reader away longer returns to an empty trail until the next update, which arrives within a minute from an online author. The phone also remembers an enqueue idempotency key for this long. |
| `appendRetryWindowMs` | 7 days | How long the relay keeps the last-append outcome per stream, so a phone that was offline can finish an uncertain upload with the original result. |
| `hygieneRotationMs` | 30 days | Rotate an epoch that nothing else has rotated. Daily was rejected: a re-wrap to every recipient every day for no realistic threat. |
| `maxOutboxRecords` | 2,000 | Backpressure on the outbox. |
| `maxOutboxBytes` | 4 MiB | Backpressure on the outbox. |

And the three kinds Moyo declares in the same policy:

| Kind | Number | `retentionMs` | `queue` | `history` | `newest` |
| --- | --- | --- | --- | --- | --- |
| Location | 0 | 24 hours | `keepAll` | yes | yes (the live pin) |
| Check-in | 1 | 30 days | `keepAll` | yes | no: every check-in is news |
| Status | 2 | 24 hours | `latestWins` | no | yes |

Delivery deadlines use the relay's acceptance time plus the window; the Worker enforces it. History retention counts from `sentAt`; the encrypted `capturedAt` is what the user sees and what chooses the live pin within a device generation. The pin is the location kind's newest slot, so a pin older than the location kind's `retentionMs` leaves the map and the person shows as last seen with no position. Acknowledgements are coalesced: at most one `ackThrough` per stream per fetch batch, delayed at most 60 seconds, which is a Moyo setting and not a policy field. Changing the policy purges only data outside the new windows, with an explicit disposition for undelivered records. Past days in R2 and the server-side trail in the user's Durable Object disappear from Moyo's backend; the trail a reader sees is the one its own phone received.

### 2a. Record kinds, codecs and notifications

Moyo declares three kinds (the table in section 2). Their meaning, codecs and the rules the app builds on the SDK's generic calls are stated here; the SDK knows none of it.

#### Location (kind 0, header class 0)

A position: history and a newest slot, kept 24 hours, every queued one sent. The app sends it with `enqueue(0, encodeLocation(fix), { eventTime: fix.capturedAt, idempotencyKey })`, so the reader's slot orders by the fix time; the slot for an author is "where they are", read with `newest(identityId, 0)`, and the trail is `historyPage({ authorIdentityId, kind: 0 })`.

#### Location codec

The 22-byte payload, versioned by Moyo:

```
plaintext = payloadVersion:u8 = 1 || latitudeE7:i32 || longitudeE7:i32 || accuracyMm:u32 || capturedAt:u64 || status:u8   -- 22 bytes
```

Latitude in -900,000,000 to 900,000,000; longitude in -1,800,000,000 to 1,800,000,000; accuracy 0 to 100,000,000 millimetres. `capturedAt` is the encrypted capture time, shown to the reader as fix age. Status 0 normal, 1 stale, 2 unavailable; unavailable requires all-zero coordinates and accuracy. Unknown versions or statuses and trailing bytes are `BAD_PAYLOAD`. The codec carries no names, addresses or device identifiers. The byte API accepts any opaque payload up to 4,096 bytes.

#### Check-in (kind 1, header class 1)

A check-in is an event: history with no slot, kept 30 days, every queued one sent, and every stored one news to the reader. Its `recordId` is its stable event id. It may carry the location codec or an application payload, sent with `enqueue(1, payload, { eventTime })`. Each accepted check-in is durably queued and retried until server acceptance, explicit security cancellation or configured expiry; a later record never replaces it, in the outbox, on the relay or on the reader. The Worker notifies each recipient of a check-in visibly, from header class 1 alone, with no record content; the protocol does not promise that every person saw it.

#### Status (kind 2, header class 2)

A status is a state: a slot only, latest wins while queued, kept 24 hours. It is the sender's small current state, in an application payload the host defines and versions, which the protocol does not parse. Only the newest matters, which gives it four properties. In the outbox, latest wins: a status still queued when a newer one is enqueued is cancelled with reason `superseded` and never sent; a status already handed to the network is not recalled, and a check-in is never dropped this way. On the reader, the newest status per author is kept, by (generation, epoch, counter) order, since a status carries no measurement time, and only from the author's current device; an older one changes nothing, and a different body under a retained status id is `EQUIVOCATION`. A status never moves the live pin, never counts as a check-in and is never history, on the sender or the reader: there is one slot per author, read as `newest(identityId, 2)` and sent with `enqueue(2, payload)` with no event time, replaced in place and dropped with the author's keys when the author leaves. It expires with its kind's `retentionMs` after `sentAt`: the payload is dropped and `newest` returns nothing, while the slot keeps its order so an older status replayed later cannot become current. A status carries no notification and needs no wake-up; readers pick it up on their next sync.

The status payload and send rules are in section 5.

#### Notifications by header class

The Worker sees the header class and nothing else of a record. Class 1 (a check-in) is a visible push to each recipient with the sender's name and generic wording; class 0 (a location) is a silent wake-up; class 2 (a status) sends nothing. A join request is a visible push to the owner. No push carries a coordinate or a payload.

#### Typed helpers and the background task

Moyo's profile package wraps the generic calls: `enqueueLocation(client, fix)`, `enqueueCheckIn(client, payloadOrFix)`, `enqueueStatus(client, bytes)`, `latest(client, identityId)` and `latestStatus(client, identityId)`, each a one-line call to `enqueue` or `newest` with the kind and the event time filled in; `decodeLocation` reads history plaintext. The background location task (formerly `@plane31/blind-relay-expo`'s `handleBackgroundLocations` and `defineLocationTask`, now Moyo's) sorts a batch from `expo-location` by timestamp, skips samples at or below its high-water mark, sends each as kind 0 with the fix time as the event time, status 2 for an unusable sample, and the idempotency key `bg:<timestamp>`, so a batch the OS redelivers to a fresh process makes no second record, then calls `sync()` and syncs again while the report says `hasMore`. One `recordStored` subscription serves self and others; `refresh` is answered with the next location and a status.

### 3. Client adapters (Expo)

#### Secrets

`accountSeed`, `deviceSeed`, `recoveryKey`, `storageKey` and the 16-byte store instance id live in Expo SecureStore with device-only accessibility. Only the `recoveryKey` is ever placed in a synced platform item, through the recovery provider below. Only the foreground app creates the `storageKey` on first run, and one creation at a time per account; a background context that finds none stops with `LOCKED` and tries again on its next wake, so two contexts can never key one database differently. The database file, device seed, counters and outbox are excluded from iCloud backup and Android Auto Backup.

#### Store

One SQLite database opened through Expo SQLite with SQLCipher, keyed by the hex `storageKey`, in WAL mode with `synchronous = FULL`. SQLCipher gives encryption at rest for every row, so there is no second per-value encryption layer. The `meta` row binds schema version 1, the store instance id, `identityId` and the current `certificateHash`, as the protocol requires, and marks the history index as built; a database from before the index is indexed once on open. Every logical table is a key-value table of JSON rows, and the ordered key range the protocol's bounded reads need is one indexed SQL query with a limit.

Every SDK write runs inside `BEGIN IMMEDIATE`. SQLite's file lock then serialises writers across the foreground app, the background location task and any headless context, without a native module. The adapter's `transaction(fn)` lets the callback start the transport's `send` before the transaction commits, which is what the protocol's handoff rule (T6h) needs; the callback is synchronous and never awaits the response inside. The busy timeout is finite, and a writer that cannot acquire the lock fails with `LOCKED`, which is retryable.

#### Recovery providers

**iOS.** A native Keychain generic-password item with `kSecAttrSynchronizable` true, `kSecAttrAccessibleWhenUnlocked` and the app's access group, keyed by account name plus identity id, holding the 32-byte `recoveryKey`, through a small config plugin. Ordinary Expo SecureStore does not establish iCloud sync. Logout erases local access without deleting the shared item; `eraseLocalAccess()` never means delete the cloud entry. Reset saves a new entry under the new identity id.

**Android.** A native Block Store provider, required before the Android release. The entry is named `"ss5.recovery." || hex(identityId)` with value `u8(1) || B(accountName) || identityId[32] || recoveryKey[32]`. Before enabling cloud backup, await `isEndToEndEncryptionAvailable()`; only `true` permits `storeBytes` with cloud backup. On false, error or absent services the existing entry is left untouched and a visible reason is returned; never retry by writing the same entry without cloud backup, which can delete a prior cloud copy. A successful store reports `backupState = pending`. The provider never advertises Keystore or SecureStore as synced recovery and never places the secret in unprotected Auto Backup.

#### Clock, background work and transport

Randomness is the Web Crypto global, which Hermes lacks: the app passes `expo-crypto`'s `getRandomValues` to the setup helper, which installs it once and never substitutes a weaker source; without one, opening fails before any key is made. A clock adapter keeps a durable time high-water mark and monotonic elapsed time for the reset-key list rules. The background location task, Moyo's own code on top of `enqueue`, sends each new sample as kind 0 with its fix time as the event time and an idempotency key derived from the sample's timestamp so a batch the OS redelivers to a fresh process makes no second record, and then `sync` under the SDK's default budget of 500 records and 5 seconds; while the report says `hasMore`, the app syncs again at once, in the background task as in the foreground. A sync report's `errors` are logged by operation and code, never by content. The transport is Moyo's authenticated fetch and sockets; its `send` queues the bytes synchronously and returns a promise, so it can be initiated inside T6h. Connectivity and push hints stay in the app, which calls `sync` when they arrive.

### 4. Server (Cloudflare Worker)

| Component | Responsibility |
| --- | --- |
| Directory (D1) | Accounts keyed by `accountName` with the current certificate pointer and generation; immutable certificates by hash; snapshots by `circleId` with compare-and-swap on revision and hash; vaults by account with compare-and-swap on revision and hash; pending join and leave requests by circle and account, expiring after 7 days; reset receipts by `resetId`; the current reset-key list. Sessions authenticate the account and its current device; a superseded device is refused every write. Activation emits a metadata hint to every circle the account is in. `registerAccount` answers `ALREADY_COMMITTED` for a name that already carries exactly the submitted certificate, and `resetAccount` checks the `resetId` before the identity. |
| Relay (`UserDO`) | One Durable Object per author: current epoch and fence; the author's retained records keyed by `deliverySeq` with their acceptance time; one subscription row per reader device with its `ackCursor`; the `expiredThrough` watermark; the manifests and wraps of every epoch that is current or still referenced by a retained record; the per-stream high-water (epoch, counter) pair and last-append outcome. `readRecords` filters by the subscription's certificate. `appendRecord`, `readRecords` and `ackThrough` run here. Deletion on a cursor advance runs inline in the same transaction; the expiry prefix advances on an alarm. The Durable Object's single-threaded storage transaction gives the serialisation the protocol requires without extra locking. |
| Fan-out (`CircleDO`) | Presence and wake-ups only: on append, notify each recipient's socket that its mailbox has new sequence numbers. It stores no record. |
| Notifications | Silent pushes wake a closed app for locations and key handoffs; a status append sends nothing. Two events are visible notifications through Expo push: a join request, sent to the owner with the requester's name, and a check-in, sent to each recipient with the sender's name and the app's generic wording. Neither carries a coordinate or a payload. Notification permission is asked for these two and the app's own alerts. |
| Reset authority | An endpoint that, after fresh re-authentication, signs the type 7 receipt with the active operational key held as a Worker secret. The management key signs a new type 8 list offline every 14 days with a 30-day lifetime; `app.config.ts` pins the management public key and the minimum list version. A standby operational key stays offline until the active one is retired by a new list. |
| Removed | The server-side trail in the user's Durable Object, past days in R2, device lists, pending devices, key requests, archives and the circle log tables. The Worker keeps no location after delivery. |

`./scripts/seed.sh` creates two accounts and a circle against the local Worker. The reference host in the SDK repository's `examples/host-worker` is the pattern for these endpoints and is tested in workerd.

### 5. Product behaviour the protocol depends on

- **Signup never asks for the recovery code.** The account is created, the provider saves the key, and the Account screen shows a recovery status from `backupState`: backed up to iCloud, backed up to Google, or not backed up yet. Only in the last case does the app later prompt, gently, to save the code. The code is always available in settings behind local authentication.
- **A new phone shows people as they arrive.** After `restoreAccount`, the map shows each circle member as "waiting for their phone" while that author's current epoch has no key for the new device, until the author's next sync delivers one. Online authors arrive within a minute; offline ones when they wake. The app never shows a blank map or a stale pin as live.
- **A pin older than a day leaves the map.** With a 24-hour history and a 24-hour delivery window, a person silent for a day shows as last seen with no position rather than a day-old dot. A reader back after a weekend sees each person again on their next update.
- **Join requests notify the owner.** The owner's approval screen opens from the notification. Approval is one tap; the requester starts sharing on approval unless they turned that off when requesting.
- **Check-ins notify recipients visibly.** The notification carries the sender's name and generic wording; the app decrypts the check-in when opened. Locations and statuses never notify.
- **Phone facts travel as statuses.** Battery, charging, Low Power Mode, mock location and location permission are a status record (kind 2) with the payload and send rules below, shown next to the person's pin with its age. A reader who just joined sees them with the first location after admission, because the app sends a status whenever the SDK asks it for a fresh location.

#### Status payload and send rules

```
payload = version:u8 = 1 || batteryPercent:u8 (0-100, 255 unknown) || flags:u8 || permission:u8   -- 4 bytes
flags   : bit 0 charging, bit 1 Low Power Mode, bit 2 mock location, bit 3 precise location; bits 4-7 zero
permission : 0 unknown, 1 denied, 2 while in use, 3 always
```

Unknown versions are shown as "no details" and never rejected: the SDK does not parse the payload, and a newer phone's status must not break an older reader. The app sends on change, with thresholds that make change rare, and a slow floor so a fresh reader is never left with nothing:

| Trigger | When |
| --- | --- |
| Battery level | When it crosses a 5 percent step, and immediately at 20 and 10 percent |
| Charging started or stopped | Immediately |
| Low Power Mode on or off | Immediately |
| Location permission or precision changed | Immediately, since it explains a dot that stops moving |
| The SDK asks for fresh records (`refresh`) | With the next location, so a new member or a new epoch starts with the phone facts |
| Floor | Once per app start, and at most every 6 hours if nothing changed |
| Ceiling | Never more than one per minute; the outbox collapses bursts anyway |

That is five to fifteen statuses per phone per day against a few hundred locations.
- **Leaving a circle takes effect locally at once.** The leaver stops sending and stops seeing that circle's members immediately; the owner's removal follows when the owner is next online.
- **One active phone.** Setting up the app on a second phone retires the first. The settings screen says so before activation.
- **Reset is a last resort with a warning.** The reset screen states that circles owned by this account will close and that every other circle will need to re-admit the account.

### 6. Release gates and device tests

These tests are in addition to the protocol's conformance package and scenario list. Each is run on real devices and its result recorded with device, OS and Play services versions.

| Gate | Evidence required |
| --- | --- |
| Android recovery | Restore the Play-distributed app and its Block Store entry to a second supported Android device through cloud restore, with no old phone and no code. Decrypt the vault, preserve owner and member identity, activate fresh device keys, receive future updates. Also exercise end-to-end check false and error, absent Play services, no screen lock, backup disabled or delayed, wrong Google account, wrong Moyo account, missing entry, capacity exhaustion, process death during save, and retirement without deleting the shared entry. |
| iOS recovery | The same restore through synced Keychain to a second iPhone, with iCloud Keychain off and delayed, wrong Apple account, app reinstall and biometric changes. |
| Durable state | The SDK's crash and lost-response sweeps (`@plane31/blind-relay/testing`) against the real SQLCipher database on both platforms, so the protocol's crash outcomes hold there. Race the foreground app and the background location task through `BEGIN IMMEDIATE`. The handoff race with the real transport adapter: an authorization change committed by one context while the other is between its check and its send never produces an upload sealed for the old audience. |
| Lost phone | With the complete old-phone state in the attacker's hands, after activation and every author's rotation the attacker opens nothing new. |
| Relay | In workerd: a record is deleted when the last required reader's cursor passes it and at the window without one; an equal or older cursor writes nothing; expiry advances as a prefix; a retried append inside the window returns the original outcome after deletion; a stale append is refused without reinsertion; a cursor above the tail is rejected; a replacement device's subscription excludes records sealed to the old certificate; members get subscriptions when an author opens a new stream; epoch blobs go only when no record references them and the epoch is not current; a check-in survives a later location; a join request and a check-in each produce exactly one visible notification with no coordinate. Measured: Durable Object writes per delivered record at 1, 10 and 100 readers, recorded before and after acknowledgement coalescing. |
| Performance | On one mid-range iOS and one mid-range Android device: full 100-account rotation, 100-person receiving load, cold start, activation and time to a full map with five authors online, storage growth, memory and battery, p50 and p95 recorded. No unmeasured speed claim appears in release notes. |
| End to end | Maestro flows for create, join with the owner's notification, approve, phone replacement on a second emulator with per-person waiting pins that fill in, removal and a check-in notification. |

An independent review of the composed protocol, the recovery flows, the store binding, the handoff serialisation and the Worker's atomicity precedes production.

### 7. Build order

The SDK's build sequence document lists nineteen steps from primitives to Moyo integration, each with what to write, what to test and what comes next. The order is: primitives and codec against the vectors; identity, vault, membership and audience; epochs, records, the store and the two sides of delivery; reset; the client; the Expo adapters; the reference host; the fault harness; benchmarks; and finally the Moyo integration, which replaces `packages/sealed`, reshapes `UserDO` and `CircleDO`, removes the server-side history, and adds the Account settings entries for recovery status and the recovery code.
