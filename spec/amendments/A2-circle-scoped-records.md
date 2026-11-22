# Amendment A2: records readable by one circle

Status: **proposed (November 2026), for review.** Nothing here is implemented. It would be protocol revision 14 if adopted. Section numbers refer to `spec/Kavach-v1.md` at revision 13.

## 0. What this changes, in one paragraph

Today an author has one stream per device, and its epoch is sealed to the union of every circle the author shares with (section 7). Every record the author sends is readable by all of them. That fits continuous sharing, where one position goes to everyone who may see it. It does not fit a record that belongs to one circle: a check-in made "in Family" that Work must not read, or a circle's saved places. This amendment adds a **scoped stream** per author device per circle, beside the existing stream. A kind the product declares `scope: "circle"` is sent on the scoped stream of the circle the caller names, and only that circle's members can open it. Everything the protocol already does per stream applies unchanged: epochs, manifests, the reseal rule, subscriptions, acknowledgement, deletion and the audience fence.

## 1. Decisions this amendment needs before adoption

| # | Decision | Recommendation |
| --- | --- | --- |
| D1 | How to scope a record to one circle | A scoped stream per (author device, circle), not several audiences inside one stream. Section 8 says why |
| D2 | Accept that the host learns which circle each scoped record is for | Accept, and state it in section 15. The host already knows every circle's members; it does not learn the payload, the kind or the event time |
| D3 | Which kinds are scoped | Declared per kind in the retention policy: `scope: "author"` (today's behaviour, the default) or `scope: "circle"`. A kind is one or the other, never both |
| D4 | What "newest" and history mean for a scoped kind | The newest slot is per (author, kind, circle). History entries carry the circle id, and history paging filters by it |
| D5 | Whether a scoped stream exists before its first record | No: it is opened at the author's first scoped record for that circle, and retired when the circle is closed, left or gone |

## 2. The scoped stream

**Identity.** `scopedStreamId = H(C("scoped-stream") || identityId || deviceId || circleId)`. It is derived like the existing stream id, with the circle id added, so a reader can recompute it and the host cannot substitute one circle's stream for another's.

**Audience.** The epoch of a scoped stream for circle X is sealed to the members of X, at their current certificates, the author included. This is the same rule as section 7, applied to one circle instead of the union: eligibility, retirement after a reset, unfinished succession chains and the 100-account limit all apply. A circle the author has disabled sharing to, has left, or that is closed or `gone`, has no usable scoped stream. Its queued records are held under the reseal rule and given up with `cancelled` when their window passes.

**Rotation.** A scoped stream rotates on the changes that touch its circle:
- a snapshot of X,
- a device change of one of X's members,
- the author's sharing preference for X,
- the hygiene period and counter exhaustion, as today.

A change in another circle does not rotate it. The existing stream still rotates on every change, as today.

**The author's own replacement.** A new device opens its own scoped streams, as it opens its own stream (section 4). A reader pins the scoped stream ids under the new certificate, exactly as for the existing stream.

## 3. Sending

- `enqueue(kind, payload, { circleId })`. `circleId` is required for a kind declared `scope: "circle"` and refused for an author-scoped kind, both with `MALFORMED`.
- Each scoped stream has its own epochs, counter and outbox order. T6 and T6h run per stream exactly as today.
- The reseal rule of revision 13 applies per stream. So does the catch-up epoch when the circle has gained a member, and so does the `AUDIENCE_STALE` fence: the host checks the scoped epoch against the circle's own snapshot.
- One record is one write to one stream. Nothing is duplicated across circles. An app that wants the same thing in two circles sends two records.

## 4. Receiving

- The host subscribes each member of X to every member's scoped stream for X when that member is admitted, and when an author opens or rotates the stream. A subscription starts at the admission boundary, as for the existing stream. A member who joins later never receives a scoped record appended before they joined, and the catch-up epoch keeps that true for a backlog the author sends late.
- A record that opens under a scoped stream carries its circle implicitly: the reader knows which stream it read. History rows gain `circleId`. `historyPage({ circleId })` filters by it, and without a filter a page merges the author's records across the circles this device can read, in the same time order.
- `newest(identityId, kind, { circleId })` reads the slot for that circle. For a scoped kind `circleId` is required.
- `recordStored` and the lifecycle events gain `circleId` for scoped records. `delivery(localId)` is unchanged.

## 5. The host

The relay stores, serves and deletes scoped streams like any stream; `appendRecord`, `readRecords`, `ackThrough` and `syncState` need no change. The directory gains one operation and one check:

- `openScopedStream(circleId, streamId, certificateHash)`, idempotent. The host verifies that the caller is a member of the circle under its current snapshot and that the stream id derives from the caller's identity, device and the circle. It records the stream as belonging to the circle and subscribes the circle's members.
- On `publishEpoch` for a scoped stream, the host refuses a manifest that addresses an account outside the circle's current members. That is the scoped form of the audience fence.

Notifications follow the header class, as today, and go to that circle's members only. This is what lets a check-in made in Family wake Family and nobody else.

## 6. Security consequences (for section 15)

**What holds.**
- **Pre-join history.** A member reads no scoped record appended before they joined: their subscription starts at admission, and the reseal rule keeps a late backlog off their epoch.
- **Removal.** A removed member reads no scoped record sealed after the circle's next rotation, the same bound as section 15's limit 2, per circle.
- **No crossing.** A member of Work who is not in Family can open no Family record. The scoped stream's epochs never address them, and the host refuses a manifest that would.

**What the host learns, beyond today.**
- Which circle each scoped record is for.
- Per circle, when and how often each author sends scoped records.

Today the union stream hides which circle a record concerns. A product that needs that hidden should not use scoped kinds for it.

**What does not change.** The host still learns no payload, kind or event time, and still holds no key.

## 7. Cost, for an author in one to five circles

| | Today (union stream only) | With scoped kinds in use |
| --- | --- | --- |
| Writes per scoped record | n/a | 1, to one stream |
| Wraps per epoch | members of the union | the union stream: as today; a scoped stream: members of that circle |
| Rotations when circle X changes | 1 (the union stream) | 1 (union) + 1 (X's scoped stream, if the author has one) |
| Rotations when circle Y changes | 1 | 1 (union) + 0 for X's stream |
| Streams per author device | 1 | 1 + the circles the author has sent scoped records in |
| Subscriptions per reader | one per author | one per author, plus one per author per shared circle with scoped records |

The extra cost grows with use, not as a multiple: an author who never sends a scoped record in a circle has no stream for it. For the expected case of 1 to 3 circles, a membership change costs at most two rotations instead of one. A scoped epoch has fewer wraps than the union epoch, because a circle is never larger than the union.

## 8. Alternatives considered

| Alternative | Why not |
| --- | --- |
| Several audiences in one stream: a record names an epoch from a per-circle series | Breaks "one current epoch per stream", which the append fence, the checkpoint, acknowledgement prefixes and deletion all rely on; every one of them would need a per-series variant |
| A circle group key: the owner shares a key with the members and scoped payloads are encrypted under it inside the union stream | The union still receives and stores every record; a removal needs the owner online to rekey; the host's notifications reach the whole union; and it adds a second key hierarchy beside the epochs |
| A scoped record sealed per recipient (one box per member) | One write per member and no deletion by cursor; cost grows with circle size per record, not per rotation |
| A separate account per circle | Multiplies identities, recovery and replacement by the circle count; the user would be several people |

## 9. Open questions for review

1. A history page without a circle filter merges circles. Should it instead require a filter for scoped kinds, so an app can never mix them by accident?
2. Should leaving a circle erase its scoped history on this device, or keep it for the retention window as history does today? The recommendation is to keep it, as today.
3. Is per-circle send timing (section 6) acceptable as host-visible metadata for the products that would use scoped kinds?
4. Should the 100-account limit count a scoped stream's audience separately from the union's? It cannot be larger, so the recommendation is that it needs no separate limit.

## 10. Delivery, if adopted

1. Specification text for sections 7, 9, 10, 13 and 15, the revision 14 note, and fixture vectors for a scoped stream id and a scoped epoch manifest.
2. The policy's `scope`, `enqueue`'s `circleId`, scoped streams in the store and outbox, and the reader's history and slot changes.
3. `openScopedStream` and the scoped manifest check in the fake host and the reference worker.
4. Conformance tests: no crossing between circles; no pre-join history, including a late backlog; removal per circle; a scoped kind refused without a circle; the cost table measured on the fake host.
