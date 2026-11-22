# Amendment A2: records readable by one circle

Status: **adopted for protocol revision 14; implementation in this change, not published.** This document records the decisions and limits. The normative protocol is `spec/Kavach-v1.md`.

## 1. Model and public API

An author keeps the existing device stream, whose audience is the union of enabled circles. A circle-scoped kind uses a separate stream per (author device, circle). Each stream reuses the same epoch, counter, outbox, catch-up, subscription, cursor and deletion machinery. There is no second key hierarchy and no extra package.

A kind declares `scope: "author" | "circle"` in the retention policy. Absent means `"author"`. A kind has exactly one scope; changing a deployed kind's scope requires a coordinated product-policy rollout.

- `enqueue(kind, payload, { circleId })`: the circle is required for a circle kind and refused for an author kind (`MALFORMED`). A circle id is 16 bytes. The author must have a verified, joined, enabled circle; an unknown or disabled circle is `NOT_AUTHORIZED`.
- `newest(identityId, kind, { circleId })`: the same scope validation. Slots are keyed by (author account, circle, kind), or (author account, kind) for author kinds.
- `historyPage({ circleId })` and `history({ circleId })` filter through a circle index. Without that filter, results deliberately aggregate readable circles and author-scoped records in time order. Every scoped entry carries `circleId`.
- `queued`, `accepted`, `cancelled`, `resealed` and `recordStored` carry `circleId` for scoped records. Stable `localId` and `delivery(localId)` retain their meaning.
- A record belongs to exactly one stream. Sending to two circles is two explicit enqueues.

Queue replacement is per (stream, kind): Family's latest-wins record never replaces Work's. Idempotency keys remain account-wide; callers must use distinct keys for distinct sends, including copies sent to different circles. Queue record and byte limits are account-wide, across every stream. History retention and the delivery window do not change.

## 2. Stream identity and reader verification

`scopedStreamId = H(C("scoped-stream") || identityId || deviceId || circleId)`.

Here `identityId` is the **key identity derived from the signing certificate**, not the stable account id after a host-authorized succession. The manifest author and circle membership still use the stable account id. The domain label is new; wire version 5 and existing document layouts are unchanged.

The reader derives candidate scoped ids from its locally verified circle ids and verified author certificates. It accepts a binding only when the derived id equals the stream id. Host subscription labels are not authority for a circle binding. Thus `listSubscriptions` and `syncState` retain their shapes. A previously unknown circle must first be learned and verified through full metadata sync; an unknown stream is not acknowledged as valid content.

Epoch and record verification use the certificate's signing key with this derived stream id. Receiving requires the reader and author to be members of that specific circle, not merely to share some other circle. A decrypted circle kind on an author stream, or an author kind on a scoped stream, is rejected. Old-device signatures retain the existing supersession rules.

## 3. Audience, rotation and resumption

The audience is the author plus the eligible members of the selected circle, at their greatest verified certificates. Retired accounts and unresolved succession chains follow the existing rules. Each actual epoch independently enforces the 100-account bound; a scoped stream does not depend on resolving the union audience.

A verified snapshot/preference change for X invalidates X's sending epoch atomically. A member device change invalidates the scoped streams whose circles contain that member. Hygiene and counter exhaustion apply independently per stream. An unrelated circle's change does not rotate X. The author stream keeps its existing union behavior.

Streams are created locally on the first scoped enqueue and registered with the host when an epoch can be published. They are **suspended, not deleted**, on disable, leave, closure or `gone`. No new scoped record is accepted for a suspended circle; queued records remain subject to expiration. No unsent record is handed off while the local circle is suspended. Already-started network requests cannot be recalled.

If sharing resumes or a verified circle returns/rejoins on the same device, reuse its deterministic stream id and durable epoch high-water mark. Never reset epoch numbers/counters or reuse epoch keys. Retain local history for its normal retention window. A new device derives new streams and follows ordinary replacement and bootstrap; it does not import the previous device's sending counters.

## 4. Precise privacy boundary for backlog

The audience boundary is **first sealing, not event time or enqueue time**.

- A record already sealed before a join is held on rotation and resealed only to the intersection of its earlier recipients and the current eligible audience. Revision 13's catch-up epochs apply independently per stream. A new member gets no wrap for that backlog.
- A record queued **unsealed**, including first-use while offline or without usable metadata, has no earlier cryptographic audience. Its first seal uses the verified audience at that time. A member who joined while it waited may receive it. Products needing enqueue-time membership semantics must not treat this as that guarantee.
- Current members cannot read records for another circle without being recipients of that circle's epoch. Removed members receive no newly sealed record after the author's verified removal/rotation. Previously disclosed keys and plaintext cannot be revoked.
- Host subscriptions do not expose pre-admission records to a newly admitted device; epoch wraps also exclude accounts that were not recipients. A malicious host can withhold membership updates, as in the existing protocol.

This supplies private delivery, **not persistent shared state**. A saved-places product must separately publish its current state for newly admitted members; scoped history is not automatically replayed to them.

## 5. Host contract

The optional directory capability `openScopedStream(circleId, streamId, certificateHash)` becomes required when a product uses scoped kinds. It is idempotent, authenticated, and returns the existing mutation outcomes. Missing capability fails explicitly with `UNSUPPORTED_OPERATION`.

The host verifies current-device authentication, current circle membership, the certificate hash and the deterministic scoped id. The registration is immutable and preserves counters/cursors on repeated calls. The HTTP binding is `POST /circles/{circleId}/streams` with hex `streamId` and `certificateHash` in the JSON body, relative to the configured base URL.

On scoped epoch publication, the host verifies the registered author/device/stream binding and never distributes wraps to recipients outside the current circle. A subset is allowed for catch-up epochs. Publication retries first resolve an identical committed manifest, even if its audience has since changed. If a new, correctly sequenced manifest has a stale audience, the host commits its exact manifest as a permanently fenced epoch, with no wraps or new subscriptions, and returns `COMMITTED`. This consumes the prepared number without reusing it or exposing keys. New appends under that epoch return `AUDIENCE_STALE`, even if the former members rejoin; earlier epochs remain fenced by the normal epoch high-water mark. The client settles the pending publication through its existing T5 checks and rotates after learning the membership change. Registration and publication still require the current author device to be a current member. Publication creates subscriptions for addressed recipient devices at the current tail; no old record is added to a new recipient's required-reader set. A subscription may therefore be materialized lazily at the first epoch addressing that device.

Append checkpoints remain first: retrying an accepted record does not send it twice. For a new append, the scoped audience fence checks against the scoped circle, not the union; removal since publication returns `AUDIENCE_STALE`. Current-device checks still apply. Notifications follow header class and go only to actual recipient accounts of that epoch, never to the whole union or to joiners excluded from a catch-up epoch.

`appendRecord`, `readRecords`, `ackThrough`, `listSubscriptions` and `syncState` retain their interfaces. The SDK and host distinguish streams by id. One blocked stream does not prevent the sync from attempting the others; each pass uses the existing bounded per-stream drain. Global queue limits bound durable pending work.

## 6. Metadata and cost

The host learns the scoped circle id and per-circle sending activity. It still receives no payload, plaintext kind or event time. Header classes and traffic patterns may permit inferences; this amendment does not hide them. Accepting circle-visible metadata is a product decision, not a new SDK option.

| Work | Cost |
| --- | --- |
| Record | One append to its selected stream |
| Streams per author device | One union stream plus each circle used for scoped sends |
| Normal change to one circle | Union rotation plus that circle's active scoped rotation, if any |
| Backlog across joins | Additional catch-up publications for affected earlier audiences |
| Member device replacement | May rotate several shared scoped streams, plus the union |
| Subscriptions | One per author stream plus the scoped author/circle streams used |
| Wraps | Per recipient in each published epoch |

Lazy creation avoids unused streams. It does not eliminate growth with circle count, overlapping membership or catch-up work. Do not promise an absolute two-rotation maximum or device performance from fake-host counts. Measure device latency, storage and network calls with the product's actual circles and traffic.

## 7. Implementation and rollout

Use a single parameterized sending state machine. Namespace sending epochs, counters and revisions by scoped stream id; keep stable local ids, account-wide limits and the shared reader implementation. Preserve existing author-stream keys and behavior.

Ship the host capability first, then revision-14 readers, then enable scoped kinds on senders. Earlier readers do not recognize scoped stream ids. No npm publication or host deployment is implied by this implementation.

Conformance covers independent stream-id/manifest vectors, no crossing, scope/type rejection, per-circle queue replacement and newest slots, indexed history, late sealed backlog across a join, unsealed first-use semantics, removal, disable/resume without counter reuse, global limits, and the actual HTTP host path. Existing author-scoped, replacement and fault tests remain applicable.
