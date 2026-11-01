# Kavach v1: implementation profile template

The protocol specification (`spec/Kavach-v1.md`) names no product concept. A product that ships on Kavach writes an implementation profile that decides everything the protocol leaves to it. Where a profile and the protocol disagree, the protocol wins. This template lists what every profile must state; a product keeps its profile in its own repository.

## 1. Record kinds

One row per kind the product uses, as declared in the retention policy passed to `open()`:

| Kind | Number | Meaning | `retentionMs` | `queue` | `history` | `newest` | `headerClass` | Event time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| | 0 to 255 | what the record means to the product | how long a reader keeps it, from `sentAt` | `keepAll` or `latestWins` | kept in pageable history | one newest-per-author slot | 0 to 3, what the relay may see | what `eventTime` the product passes, or none |

For each kind: the payload codec (byte layout, version byte, bounds, what it must never carry), how the product sends it (`enqueue(kind, payload, { eventTime, idempotencyKey })`) and how it reads it (`newest(identityId, kind)`, `historyPage`), and how the product answers `recordStored` and `refresh`.

## 1a. Replacement model

Which replacement models the product enables, `continuity`, `recovery` or `both` (specification section 4, from amendment A1), and the resulting promise in one sentence; where the authority key is custodied and how fresh authentication is enforced before it signs, when `recovery` or `both` is enabled; and the product's record of amendment decisions D1 to D5. These are the product's decisions and live here, never in the SDK.

## 2. Notifications by header class

For each header class the kinds use: visible push, silent wake-up, or nothing; the wording of a visible push, which never carries content; and the join-request notification to an owner.

## 3. Retention policy

The global windows with their values and reasons: `deliveryWindowMs`, `appendRetryWindowMs`, `hygieneRotationMs`, `maxOutboxRecords`, `maxOutboxBytes`; and where the policy comes from (packaged, or published by the host).

## 4. Client adapters

The secret store and its accessibility class; the encrypted transactional store and its cross-process writer lock, with who provisions the storage key; the secure random source (Web Crypto, or what the runtime lacks and how it is installed); the recovery provider per platform and its five statuses; the trusted clock for the reset-key rules; the transport, with a `send` that can be initiated inside a transaction; the sync schedule (foreground, push, background, and the repeat while `hasMore`), and which process runs background work.

## 5. Server

How the host implements the directory and relay contract (protocol section 13): storage, atomicity of cursor advance and deletion, the expiry alarm, the append checkpoint, subscription creation, authentication and the device binding, the reset authority and the signing of the key list, and what the host never stores.

## 6. Product behaviour the protocol depends on

What the interface shows for a waiting author, an expired slot, a replaced device and a reset; how recovery is presented without blocking signup on a code; how joins and approvals surface; anything the product sends on a schedule (floors and ceilings) that the protocol relies on for freshness.

## 7. Release gates and device tests

Per platform: recovery restore to a second device, the SDK's crash and lost-response sweeps against the real store, the handoff race with the real transport, the lost-device test, the relay gates in the host's own runtime, performance numbers with device, OS and date, and end-to-end flows.
