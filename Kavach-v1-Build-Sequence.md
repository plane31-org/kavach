# Kavach v1: build sequence for a new repository

One module at a time: write it, test it against the frozen vectors or a scenario, then move on. Nothing in the existing Moyo repository changes until step 18. The protocol is Part I of `spec/Kavach-v1.md` (protocol revision 6, wire version 5, formerly SealedStream SS5); Moyo's choices are Part II. The vectors are `spec/vectors.json` with `spec/verify_vectors.py`: the SS5 revision 2 package (kept unchanged in `spec/vectors-rev2/`) regenerated once for revision 4: K19 at 30 days, the maximum-size record re-derived with flag bit 0 reserved, type 5 retired, the 49-byte vault entry. The wire labels keep the `SealedStream/5/` prefix on purpose.

Packages: `@kavach/core` (protocol, pure TypeScript, no platform imports) and `@kavach/expo` (SecureStore, SQLite with SQLCipher, Keychain and Block Store recovery providers, clock, background task glue). A reference host lives in `examples/host-worker` and is not published.

Estimated size: core about 3,200 lines, expo about 800, host example about 650, tests roughly twice the core. The latest cell, the pending inbox, the transfer token and the urgent flag are gone; nothing in this sequence builds them.

## Step 0: repository and tooling

Write: pnpm workspace, TypeScript strict, vitest, eslint, `packages/core`, `packages/expo`, `examples/host-worker`, `spec/` holding the specification, `vectors.json` and `verify_vectors.py` regenerated once for revision 4 from the revision 2 package: K19 at 30 days, the maximum-size record with flag bit 0 reserved, type 5 retired, the 49-byte vault entry. A `scripts/vectors.sh` that runs the Python checker in a venv with pinned dependencies.

Test: the Python checker passes on a clean checkout, the unchanged revision 2 package still passes its own checker, and the section diff between the two fixtures touches only the profile string, the type 5 document, the two added negative vectors, the maximum-size record, the recovery vault and the K19 wire. CI runs typecheck, lint, unit tests and the checker.

Next: primitives.

## Step 1: primitives and labels

Write: `core/src/crypto.ts` over libsodium-wrappers-sumo: `H`, `C(label)`, `D(seed, label)`, Ed25519 sign and verify with canonical-signature and small-order rejection, XChaCha20-Poly1305 seal and open, `crypto_box_seal` and `crypto_box_seal_open`, `crypto_box_seed_keypair`, `crypto_sign_seed_keypair`, CSPRNG. Key derivation: `AK` from `accountSeed`, `DSK` from `D(deviceSeed, "device-sign")`, `DEK` from `crypto_box_seed_keypair(D(deviceSeed, "device-box"))`. Nothing derives from the account seed except `AK`. `core/src/bytes.ts`: big-endian readers and writers using BigInt for u64, `B(name)` with the name rule, a bounded reader that refuses trailing bytes.

Test: Vector A reproduces every derived key, identity id and stream id. N13 and N16 reject. X25519 public keys equal the fixture's. Two devices of one account derive different `DEK`s.

Next: the codec.

## Step 2: document codec, types 1 to 4 and 6 to 8

Write: `core/src/codec.ts`: parse and build for AccountDevice, CircleSnapshot, EpochManifest, EncryptedRecord (flag bit 0 reserved, bit 1 kind), AccountVault, AccountResetReceipt and ResetKeyList. Each parser enforces the ranges, sort orders, counts, nonzero rules and the 16,384-byte limit before any signature check; the key-list lifetime limit is 30 days. `verify(wire, key)` applies the label by type. `bodyHash`, `recordId`.

Test: Vector B, C, D and E wires rebuild byte for byte; all 21 negative vectors return the expected error; the 100-account boundary fixture parses with sizes 3,324, 9,808, 8,000 and 4,255; the three key lists are 187, 139 and 91 bytes. The location codec round-trips and rejects N14 and N15.

Next: identity.

## Step 3: account, certificate and generation rules

Write: `core/src/identity.ts`: create an account from a seed, build a certificate at a generation, `acceptCertificate(current, candidate)` returning accepted, duplicate, `DEVICE_ROLLBACK`, `EQUIVOCATION`, `DEVICE_ID_REUSED` or `ACCOUNT_KEY_CHANGED`. Per-account pin store interface: `AK`, highest generation, certificate hash, pinned `DSK` and `DEK.public`. An accepted higher certificate reports that the audience must change.

Test: Vector E's device rejections; a generation 3 certificate after 2 is accepted and reports a rotation; a gap from 2 to 5 is accepted; the quarantine path for a changed `AK` never touches circle state.

Next: the vault.

## Step 4: vault and recovery code

Write: `core/src/vault.ts`: build and open the type 6 vault, entry sort and uniqueness, the revision rule, `SS5R-` code encode and decode with strict base64url. A `RecoveryProvider` interface with the five statuses and `backupState`. The recovery order: provider, code, then `ACCOUNT_RECOVERY_REQUIRED`.

Test: the recovery fixture opens with the right key and fails with the wrong key as `DECRYPT_FAILED`; the code is 48 characters; an in-memory provider drives the recovery order; opening the vault yields no encryption key.

Next: membership.

## Step 5: snapshots and join requests

Write: `core/src/circle.ts`: `acceptSnapshot(pinned, candidate)` returning accepted, duplicate, `ROLLBACK` or `EQUIVOCATION`; owner-side `approve(circleId, accountName)` resolving and pinning the requester through the directory and building the successor from local state; `requestJoin` (vault entry first, then the host call), `leave` (which also stops opening that circle's authors locally and files a leave request), `remove`, `closeCircle`. No signed request document and no replay list.

Test: state vectors S07 to S10; a duplicate approval is idempotent; a snapshot with two keys for one name is rejected; an expired or withdrawn request cannot block an unrelated approval; a recovering device learns admitted or waiting from the current snapshot, not from the vault; the owner's device replacement leaves the revision unchanged.

Next: audience.

## Step 6: audience and desired revision

Write: `core/src/audience.ts`: eligible circles, deduplicated union capped at 100 with `RECIPIENT_LIMIT`, resolution of each identity to (`identityId`, `certificateHash`, `DEK.public`), `METADATA_REQUIRED` when anything is missing, `desiredRevision` increment rules, and the invalidation it triggers (active epoch cleared, counters burned, obsolete outbox rows cancelled, `paused(rotation)`).

Test: remove then rejoin between syncs increments the revision; an unchanged member set with a new snapshot revision increments; a recipient's device replacement increments; identical reprocessing does not; 101 distinct accounts pause with `RECIPIENT_LIMIT`; a self-only audience reports zero recipients.

Next: epochs.

## Step 7: epochs, wraps and publication

Write: `core/src/epoch.ts`: prepare (fresh `SK`, wraps, manifest, captured revision), publish with identical-byte retry and lookup on uncertainty, commit, conditional promote, obsolete, the `hygieneRotationMs`, clock-reversal and counter-exhaustion triggers, reader-side `openEpoch` with every check from protocol section 8. Reader retention: keep `SK` until every held record of its epoch is opened or expired.

Test: Vector C opens for Alice and Bob; W01 to W03 reject; state vectors S01 to S06; a wrap addressed to the old device fails on the new one (Vector E); a different valid body at a published epoch is `EQUIVOCATION`; an epoch older than the configured hygiene interval returns `ROTATION_REQUIRED` on the next enqueue.

Next: records.

## Step 8: records, location codec and check-ins

Write: `core/src/record.ts`: seal with the active `SK`, fresh nonce, counter allocation, the kind bit; open with certificate and manifest resolution, `SUPERSEDED_DEVICE` for a retired author's new records; the 22-byte codec with the floating-point helper; check-in sealing with the same counter.

Test: Vector D and the check-in fixture reproduce exactly; N05 to N09, N12, N19 reject; S14 and S15 cover the final counter and exhaustion; a check-in followed by two locations yields three distinct record ids.

Next: the store.

## Step 9: local store and transactions

Write: `core/src/store.ts`: a `Store` interface with `transaction(fn)` whose callback may initiate a transport send before commit, plus the minimum logical records of protocol section 11 as tables, including the reset-trust rows and the in-flight mark on outbox rows. The `meta` row binding, the `INITIALIZING` and `ACTIVE` marker, and `RECOVERY_REQUIRED` on a mismatch. An in-memory implementation for Node tests with the same transaction semantics. The ten transaction boundaries T1 to T9 and T6h as named functions.

Test: each T function commits or leaves nothing; the marker protocol survives a simulated crash between the secret store write and the store write; a mismatched header pauses rather than inventing counters; two in-memory contexts cannot interleave a T3 between a T6h check and its send.

Next: outbound.

## Step 10: outbox and sender

Write: `core/src/outbox.ts`: `enqueue` (T6) with queue limits and `QUEUE_FULL`; the single serialised sender in (epoch, counter) order that, for each row, opens T6h, re-checks eligibility, marks the row in flight, calls the transport's send inside the transaction, commits, then awaits the response and records the outcome in a new transaction that revalidates first; one record in flight per stream, the next handoff waiting for a durable outcome; identical-byte retry; `STALE_APPEND` recorded as `acceptanceUnknown` with a `needsLocation` for a location and no automatic re-creation of a check-in; cancellation with `cancelled(recordId, reason)` on a known change; a synchronous send failure rolls the in-flight mark back.

Test: S03, S05, S06, S17; crash after T6 before send retries the exact wire; crash after T6h with a lost response resolves by lookup and never resends under a changed audience; a membership change cancels obsolete rows and keeps local history; the handoff race scenario passes with a transport adapter that records call order.

Next: inbound.

## Step 11: receiver, history, acknowledgement and the live pin

Write: `core/src/inbox.ts`: `receive` (T7) with the result set of protocol section 10, epoch fetch through `getEpoch` when the manifest or wrap is not local, dispositions and body hashes, the live pin advancing only on a greater (generation, epoch, counter) for kind 0, expiry and `CLOCK_SKEW` rules, `history(query)` and `latest(identityId)`. Per author stream a local acknowledged prefix advances only across a contiguous run in which every record addressed to this device is durably stored or the relay declared expired; a `keyPending` record holds it while later records are still stored; the relay returns only records addressed to this subscription, and a returned record not addressed to this device is `invalid(NOT_AUTHORIZED)` and does not hold it. One `ackThrough` per stream per batch, coalesced. There is no pending inbox.

Test: S11 to S13, S16; counters 7 then 6 keep the pin at 7; a record that cannot be opened offline holds the prefix while later records flow and opens after the next sync re-reads it; a returned record not addressed to this device never holds the prefix; crossing an expired prefix stores nothing and claims nothing; a superseded device's record lands in history only; a check-in never selects the pin.

Next: reset.

## Step 12: reset keys and last-resort reset

Write: `core/src/reset.ts`: key-list acceptance (management signature, version rules, 30-day lifetime, trusted-clock rules with a durable time high-water mark, `RESET_KEYS_REQUIRED`, `RESET_CLOCK_UNTRUSTED`, `EQUIVOCATION`, `ROLLBACK`, empty list disables resets), receipt verification against the current list (`RESET_KEY_REVOKED`, `RESET_BINDING`), persisted `resetId`, accepted receipt hashes and retired identities, re-attestation under a current key, peer behaviour, and the quarantine of a bare directory key change.

Test: K01 to K22 with K19 at 30 days; the reset fixture applies once and is a no-op on replay; a wrong key, a binding mismatch and a conflicting `resetId` reject; an expired list defers a reset and does not pause sharing; a directory key change without a receipt closes nothing.

Next: the client.

## Step 13: client state machine and public API

Write: `core/src/client.ts`: `open` (with `retentionPolicy` and `resetTrust`), `initializeAccount` (never blocks on the recovery code), `recoveryStatus`, `recoveryCode`, `restoreAccount`, `enqueueLocation`, `enqueueCheckIn`, `enqueue`, `sync`, `receive`, `history`, `latest`, `inspect`, `circles.*`, `resetAccount`, `subscribe`, `close`. The visible states, the events (`deviceChanged`, `needsLocation`, `cancelled`, `latestUpdated`, per-person waiting state) and the error families of protocol section 14, the safe log fields, and the policy validation at `open`.

Test: the full scenario list in the protocol appendix against the in-memory store and a fake transport, except the platform recovery scenario and the relay scenarios, which come later. Every state transition is emitted only after its durable commit.

Next: the Expo package.

## Step 14: Expo adapters

Write: `expo/src/secretStore.ts` (SecureStore, device-only accessibility); `expo/src/store.ts` (Expo SQLite with SQLCipher keyed by `storageKey`, WAL, `synchronous = FULL`, `BEGIN IMMEDIATE` transactions with a finite busy timeout, backup exclusion, a `transaction(fn)` whose callback may start a fetch before commit); `expo/src/recovery/apple.ts` (synchronizable Keychain item through a small config plugin); `expo/src/recovery/android.ts` (Block Store with the end-to-end check, named entry, no silent downgrade, `backupState = pending`); `expo/src/clock.ts`; `expo/src/background.ts` (the location task calling `enqueueLocation` then `sync`). Notifications are the host's.

Test: on a development build, foreground and background tasks write concurrently without a shared counter and the handoff race does not reproduce; the database refuses to open without the key; recovery providers report the five statuses with sync off, locked, and unavailable services; enrollment completes with the provider unavailable; a clock rollback yields `RESET_CLOCK_UNTRUSTED` without pausing sharing. The Android cloud-restore test to a second device is a release gate; record its device and Play services versions.

Next: the reference host.

## Step 15: reference host (an SDK example, not published)

Why it is in the SDK repository: the SDK ships no server, but its cursor, deletion, checkpoint and fence rules are only promises until a relay executes them. The reference host makes the directory and relay contract of protocol section 13 executable, so the SDK repository can run its own end-to-end tests, and it is the template the Moyo Worker is built from in step 18. It is a test fixture and a pattern, never a product; Moyo's production Worker lives in the Moyo repository.

Write: `examples/host-worker`: directory tables with compare-and-swap on certificate hash, snapshot revision and vault revision; the current reset-key list and a receipt signer using an operational key from the environment; a per-author relay object holding retained records by `deliverySeq` with acceptance times, one subscription row per reader device with its `ackCursor`, the `expiredThrough` watermark, the per-stream high-water pair and last-append outcome, subscription-filtered reads, the epoch material of every epoch that is current or referenced by a retained record, deletion in the same transaction as a cursor advance and an alarm that advances the expiry prefix; a notification hook that emits a visible notification for a join request (to the owner) and a check-in append (to each recipient) and a silent wake-up otherwise; an activation hint to every circle of the account. The in-memory host in `packages/core/src/testing` is the behavioural reference it must match.

Test (workerd): the relay scenarios from the protocol appendix and the profile's gate table: the last required reader's cursor deletes the record; the window deletes unacknowledged records as a prefix and never a newer one; an equal or older cursor writes nothing; a cursor above the tail is rejected; a retried append inside the window returns the original outcome after deletion; a stale append is refused without reinsertion; members get subscriptions when an author opens a new stream; a replacement device's subscription starts at activation; epoch blobs go only when nothing references them and the epoch is not current; a check-in survives a later location; a join request and a check-in each produce exactly one visible notification with no coordinate. Fences reject a superseded device and an older epoch. The core's scenario suite runs unchanged against it.

Next: faults.

## Step 16: fault harness

Write: a test harness that injects time, randomness, dropped responses after committed writes, duplicate deliveries, crashes between every T boundary including T6h, and concurrent writers; a malicious transport that withholds, replays, reorders and forks documents, serves an older vault, and replays an unexpired key list.

Test: every crash outcome in protocol section 11 holds against the real SQLCipher database on a device; every malicious-transport case ends in the typed error the protocol names and never in a plaintext fallback or a silent reset; the lost-device scenario runs with the attacker holding the complete old-device state.

Done, with these notes. Time is injected through `now`; randomness is not, because every check compares the bytes the store holds with the bytes the host holds, which is stronger than replaying a random stream. The crash sweep runs on the in-memory store and on SQLite files in Node (real `BEGIN IMMEDIATE`, WAL, `synchronous = FULL`); the same sweep on SQLCipher on a phone is Moyo's durable-state gate in step 18, since it needs the development build. The sweep found and fixed four client gaps: an enrollment interrupted after the host registered the account could not resume (the retry got a conflict and gave up); a replacement interrupted after the host activated the device allocated a third device on retry; a process that died between activation and the provider's save left the account unbacked with nothing retrying; and a record whose epoch the host served tampered was discarded instead of held as key-pending with the error named. Equivocation by the author (two signed bodies for one record id, two snapshots at one revision) is covered at module level in the inbox and circle tests; the transport-level fork knobs cover what a host can do alone.

Next: measurement.

## Step 17: SDK benchmarks

What belongs here is what the SDK claims for itself: the cost of a full 100-account rotation (key, wraps, manifest, signature), a 100-person receiving load (verify, open the epoch, decrypt, store), storage growth at one record a minute per author for a day, and the time of one `enqueue` and one `receive`. Cold start, activation, time to a full map, memory and battery depend on the app's screens and scheduling and are measured by Moyo in step 18.

Write: `packages/core/bench`: the four measurements above on Node against the in-memory store and the SQLite store, printing p50 and p95; and a small screen in the Expo example app that runs the same four on a device.

Test: numbers exist on Node and on one mid-range iOS and one mid-range Android device before any speed claim is written down. None of them appears in the specification or the README without the device, OS and date next to it.

Next: Moyo.

## Step 18: Moyo integration

Write: in the Moyo repository, replace `packages/sealed` with `@kavach/core` and `@kavach/expo`; implement the directory, relay, notification, key-list and reset endpoints in the Worker on the pattern of the reference host (`UserDO` becomes the per-author relay, `CircleDO` keeps presence and wake-ups only); send the join-request and check-in notifications as visible pushes with the app's generic wording; remove the server-side trail, R2 history, device lists, pending devices, key requests, archives and circle log tables; generate the management key offline and two operational keys, pin the management public key and minimum list version in `app.config.ts`, hold the active operational key as a Worker secret, and schedule the 14-day list signing; wire the recovery providers and the retention policy from the profile; add the Account settings entries for recovery status and the recovery code.

Test: `pnpm typecheck`, `pnpm test`, the Maestro flows for create, join with the owner's notification, approve, phone replacement on a second emulator with per-person waiting pins that fill in, removal and a check-in notification. The app-level measurements of the profile's performance gate (cold start, activation, time to a full map with five authors online, memory and battery) are taken here, on one mid-range iOS and one mid-range Android device.

Next: the external review named in protocol section 16.
