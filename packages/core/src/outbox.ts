/**
 * The outbox and the sender (protocol section 10, publishing; transactions T6 and T6h).
 */
import { fromHex, toHex } from "./bytes.js";
import { rotationReason, MAX_COUNTER } from "./epoch.js";
import { bodyHash, randomBytes, recordId as deriveRecordId } from "./crypto.js";
import { KavachError } from "./errors.js";
import { indexHistory, unindexHistory } from "./historyIndex.js";
import { kindOf, type RetentionPolicy } from "./policy.js";
import { PROTOCOL_REVISION } from "./revision.js";
import { clampEventTime, slotKey, takeSlot } from "./slots.js";
import { sealRecord } from "./record.js";
import { big, unbig } from "./rows.js";
import type { EpochRow, HistoryRow, OutboxRow, Store, Tx } from "./store.js";
import { META, REVISION, STREAM, currentRevision, t3ApplyChange } from "./transactions.js";
import type { AppendOutcome, Relay } from "./transport.js";
import { DocumentType, expectType, parseDocument, recordWireBytes, type EpochManifest, type RecordKind } from "./codec.js";

/** Which record an event is about: its local id, which never changes, its current record id when sealed, and its idempotency key. */
export interface RecordRef {
  readonly localId: Uint8Array;
  readonly recordId: Uint8Array | undefined;
  readonly idempotencyKey: string | undefined;
}

export function refOf(key: string, row: OutboxRow): RecordRef {
  return { localId: fromHex(key), recordId: row.recordId ? fromHex(row.recordId) : undefined, idempotencyKey: row.idempotencyKey };
}

export interface OutboxEvents {
  queued?(ref: RecordRef, kind: RecordKind): void;
  /** The sender's own record was sealed and stored under its rules: at enqueue, or at the sync that sealed a deferred one. */
  sealed?(ref: RecordRef, kind: RecordKind, tookSlot: boolean): void;
  accepted?(ref: RecordRef): void;
  cancelled?(ref: RecordRef, reason: string): void;
  /** A record of a kind with a newest slot was cancelled or is in doubt: the app may resend its current state of that kind. */
  refresh?(reason: string): void;
  securityError?(code: string, detail: string): void;
  /** The host refused records as AUDIENCE_STALE: they are held, and the next sync runs full. */
  audienceStale?(held: number): void;
  /** A held record was sealed again under a new epoch: `ref.recordId` is the new id, and the old one is gone. */
  resealed?(ref: RecordRef, oldRecordId: Uint8Array): void;
}

export interface OutboxDeps {
  readonly store: Store;
  readonly relay: Relay;
  readonly policy: RetentionPolicy;
  readonly now: () => bigint;
  readonly author: () => { streamId: Uint8Array; signingSecretKey: Uint8Array; generation: bigint; identityId: Uint8Array };
  readonly events?: OutboxEvents;
}

function requireReady(tx: Pick<Tx, "get">): void {
  const meta = tx.get("meta", META);
  if (!meta) throw new KavachError("RECOVERY_REQUIRED", "enqueue", "no header");
  if (meta.state === "RETIRED") throw new KavachError("SUPERSEDED_DEVICE", "enqueue", "this device is retired");
  if (meta.state !== "ACTIVE") throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", "enqueue", `store is ${meta.state}`);
}

export interface EnqueueOptions {
  /**
   * A caller-chosen key for this hand-over, derived from the sample itself (its fix time and
   * source, say). The guarantee: a keyed enqueue that returns has committed its record and the
   * key in one transaction; a second enqueue under the same key, from a retry after a crash or
   * from another runtime on the same store, returns that record with `duplicate: true` and seals
   * nothing, concurrent calls included, since the store's writer lock orders them; a refused
   * enqueue stores no key, so its retry is checked again. The key is kept for the delivery
   * window and covers the hand-over, not delivery: the record it names can still be cancelled by
   * a rotation, which the `cancelled` event reports as for any record. Up to 128 characters.
   */
  readonly idempotencyKey?: string;
  /**
   * The event time of what the record describes (a fix time, say), carried in the encrypted
   * envelope. A reader orders the kind's newest slot by it, clamped to the send time. Absent for a
   * kind with no natural event time; the slot then orders by send time. Zero means absent: the
   * envelope has no other way to say "none", and the sender's own slot follows the same reading.
   */
  readonly eventTime?: bigint;
}

export interface Enqueued {
  /** The record's local id: stable for its whole life, across a deferred seal and a reseal. */
  localId: Uint8Array;
  /** The record id, when the record was sealed at enqueue; absent when sealing was deferred. */
  recordId: Uint8Array | undefined;
  /** True when the idempotency key matched an earlier enqueue and this call made no record. */
  duplicate: boolean;
  /** True when this record took the sender's own newest slot for its kind. */
  own: boolean;
  /** True when this enqueue retired the epoch (hygiene or the last counter); rows queued under it were cancelled. */
  rotated: boolean;
}

export const MAX_IDEMPOTENCY_KEY = 128;

/**
 * T6: require a usable active epoch under the current desired revision, enforce the queue limits,
 * seal once, write the outbox row and the own history row, and advance the counter. The record
 * id is returned only after commit. A kind declared latestWins cancels a queued record of the same
 * kind when a newer one is enqueued, never a sent one; a slot-only kind writes no history row. An
 * idempotency key is answered before any check: its record is already durable, whatever has
 * happened to the queue since.
 */
export async function enqueue(deps: OutboxDeps, kind: RecordKind, payload: Uint8Array, options: EnqueueOptions = {}): Promise<Enqueued> {
  const stage = "enqueue";
  const declared = kindOf(deps.policy, kind);
  if (!declared) throw new KavachError("MALFORMED", stage, `kind ${kind} is not declared in the retention policy`);
  const key = options.idempotencyKey;
  if (key !== undefined && (key.length === 0 || key.length > MAX_IDEMPOTENCY_KEY)) throw new KavachError("MALFORMED", stage, "idempotency key must be 1 to 128 characters");
  // One reading of the event time for the envelope, the own slot and the history row: zero is none.
  const eventTime = options.eventTime === undefined || options.eventTime === 0n ? undefined : options.eventTime;
  if (eventTime !== undefined && eventTime < 0n) throw new KavachError("MALFORMED", stage, "event time before the epoch");
  const superseded: RecordRef[] = [];
  const result = await deps.store.transaction((tx): Enqueued => {
    requireReady(tx);
    if (key !== undefined) {
      const seen = tx.get("enqueueKeys", key);
      if (seen) return { localId: fromHex(seen.localId ?? seen.recordId), recordId: seen.recordId ? fromHex(seen.recordId) : undefined, duplicate: true, own: false, rotated: false };
    }
    const revision = tx.get("revision", REVISION);
    if (revision?.paused === "limit") throw new KavachError("RECIPIENT_LIMIT", stage);
    const now = deps.now();
    // A usable epoch seals the record now; without one (a rotation pending or due, metadata
    // missing, an AUDIENCE_STALE fence) the record is queued unsealed and sealed at the next sync.
    // The rotation reasons are read on the active epoch itself, exhausted or not, so a spent
    // counter retires the epoch (T3) here rather than leaving it active and unusable.
    let epoch = activeEpochIn(tx);
    let rotated = false;
    // A catch-up epoch carries held records only (revision 13): a new record waits for the next one.
    if (epoch?.catchUpFor !== undefined) epoch = undefined;
    if (epoch) {
      const reason = rotationReason({ createdAt: unbig(epoch.createdAt), nextCounter: epoch.nextCounter, lastSentAt: epoch.lastSentAt === undefined ? undefined : unbig(epoch.lastSentAt) }, now, deps.policy.hygieneRotationMs);
      if (reason) {
        t3ApplyChange(tx, { kind: reason }); // T3: the epoch is retired; this record waits for the next one
        epoch = undefined;
        rotated = true;
      }
    }
    let count = 0;
    let bytes = 0;
    for (const [k, row] of tx.list("outbox")) {
      if (declared.queue === "latestWins" && row.kind === kind && (row.status === "queued" || row.status === "held" || row.status === "unsealed")) {
        tx.put("outbox", k, terminal(row, "cancelled", "superseded"));
        superseded.push(refOf(k, row));
        continue;
      }
      if (row.status === "queued" || row.status === "inflight" || row.status === "held" || row.status === "unsealed") {
        count++;
        bytes += row.wire ? row.wire.length / 2 : recordWireBytes((row.payload?.length ?? 0) / 2);
      }
    }
    if (count >= deps.policy.maxOutboxRecords || bytes + recordWireBytes(payload.length) > deps.policy.maxOutboxBytes) throw new KavachError("QUEUE_FULL", stage);
    const a = deps.author();
    // The local id: the record id it is sealed with now, or a fresh one when sealing waits.
    const localId = epoch ? toHex(deriveRecordId(a.streamId, epoch.epoch, epoch.nextCounter)) : toHex(randomBytes(32)); // 32 bytes, like a record id
    const base: OutboxRow = {
      recordId: "",
      wire: "",
      epoch: 0,
      counter: 0,
      kind,
      sentAt: big(now),
      desiredRevision: big(currentRevision(tx)),
      status: "unsealed",
      attempts: 0,
      reason: undefined,
      // Kept until acceptance, so a deferred record can be sealed and a refused one resealed.
      payload: toHex(payload),
      ...(eventTime === undefined ? {} : { eventTime: big(eventTime) }),
      ...(key === undefined ? {} : { idempotencyKey: key })
    };
    tx.put("outbox", localId, base);
    if (key !== undefined) tx.put("enqueueKeys", key, { localId, recordId: "", epoch: 0, counter: 0, sentAt: big(now) });
    if (!epoch) return { localId: fromHex(localId), recordId: undefined, duplicate: false, own: false, rotated };
    const sealed = firstSealIn(tx, deps, localId, base, epoch, now);
    return { localId: fromHex(localId), recordId: fromHex(sealed.recordId), duplicate: false, own: sealed.own, rotated };
  });
  if (result.duplicate) return result;
  for (const ref of superseded) deps.events?.cancelled?.(ref, "superseded");
  const ref: RecordRef = { localId: result.localId, recordId: result.recordId, idempotencyKey: key };
  deps.events?.queued?.(ref, kind);
  if (result.recordId) deps.events?.sealed?.(ref, kind, result.own);
  return result;
}

/**
 * The active epoch a record may be sealed under now: active, unpaused (rotation, metadata, an
 * audience limit), outside an AUDIENCE_STALE fence and with a counter left. A hygiene rotation that
 * is due is the caller's to apply.
 */
/** The account ids an epoch's manifest addresses, the author's own included. */
export function recipientsOf(row: EpochRow | undefined): Set<string> {
  if (!row) return new Set();
  return new Set(expectType<EpochManifest>(parseDocument(fromHex(row.manifest)), DocumentType.EpochManifest).audience.map((r) => toHex(r.identityId)));
}

/**
 * Whether `target` may carry a held record (revision 13): it is newer than the epoch the record was
 * sealed under, and every account it addresses could already read the record then. An account
 * added since is never a recipient of a record from before it; one removed is never in `target`.
 */
export function servesHeld(tx: Pick<Tx, "get">, target: EpochRow, row: OutboxRow): boolean {
  const from = row.heldEpoch ?? row.epoch;
  if (target.epoch <= from) return false;
  // A catch-up epoch carries the records of the epoch it was made for and no others: a record held
  // from a later, larger epoch would otherwise reach fewer people than it was sealed for.
  if (target.catchUpFor !== undefined && target.catchUpFor !== from) return false;
  const before = recipientsOf(tx.get("epochs", String(from)));
  for (const id of recipientsOf(target)) if (!before.has(id)) return false;
  return true;
}

/** Whether a catch-up epoch still has work: held records it may carry, or records sealed under it not yet out. */
export function catchUpBusy(tx: Pick<Tx, "get" | "list">, epoch: EpochRow): boolean {
  for (const [, r] of tx.list("outbox")) {
    if ((r.status === "queued" || r.status === "inflight") && r.epoch === epoch.epoch) return true;
    if (r.status === "held" && r.payload !== undefined && servesHeld(tx, epoch, r)) return true;
  }
  return false;
}

/** The active epoch outside a fence or a pause, whether or not its counter is spent. */
function activeEpochIn(tx: Pick<Tx, "get">): EpochRow | undefined {
  const meta = tx.get("meta", META);
  if (meta?.fullSyncDue) return undefined;
  const revision = tx.get("revision", REVISION);
  if (revision?.paused === "metadata" || revision?.paused === "limit" || revision?.paused === "rotation") return undefined;
  const stream = tx.get("stream", STREAM);
  if (!stream || stream.activeEpoch === undefined) return undefined;
  const epoch = tx.get("epochs", String(stream.activeEpoch));
  return epoch && epoch.status === "active" ? epoch : undefined;
}

/**
 * Seal a record for the first time under `epoch` (T6), at its local id `key`: the wire, the
 * sender's own history row and newest slot under the reader's rules (section 10), the idempotency
 * key's record id, and the epoch's counter, in the caller's transaction. Used by `enqueue` with a
 * usable epoch and by the sender for a record enqueued unsealed.
 */
function firstSealIn(tx: Tx, deps: OutboxDeps, key: string, row: OutboxRow, epoch: EpochRow, now: bigint): { epoch: EpochRow; recordId: string; own: boolean } {
  const declared = kindOf(deps.policy, row.kind);
  if (!declared || row.payload === undefined) throw new KavachError("MALFORMED", "enqueue", "kind not declared or payload gone");
  const a = deps.author();
  const eventTime = row.eventTime === undefined ? undefined : unbig(row.eventTime);
  const payload = fromHex(row.payload);
  const sealed = sealRecord({
    streamId: a.streamId,
    epoch: epoch.epoch,
    nextCounter: epoch.nextCounter,
    kind: row.kind,
    eventTime,
    headerClass: declared.headerClass,
    payload,
    sentAt: now,
    epochKey: fromHex(epoch.epochKey),
    signingSecretKey: a.signingSecretKey
  });
  const id = toHex(sealed.recordId);
  tx.put("outbox", key, { ...row, recordId: id, wire: toHex(sealed.wire), epoch: epoch.epoch, counter: sealed.counter, sentAt: big(now), desiredRevision: big(currentRevision(tx)), status: "queued" });
  if (row.idempotencyKey !== undefined) {
    const k = tx.get("enqueueKeys", row.idempotencyKey);
    if (k) tx.put("enqueueKeys", row.idempotencyKey, { ...k, localId: key, recordId: id, epoch: epoch.epoch, counter: sealed.counter });
  }
  const self = toHex(a.identityId);
  const hash = toHex(bodyHash(sealed.wire.subarray(0, sealed.wire.length - 64)));
  const own = declared.newest ? takeSlot(tx, self, row.kind, { generation: a.generation, eventTime: clampEventTime(eventTime, now), epoch: epoch.epoch, counter: sealed.counter, recordId: id, bodyHash: hash, sentAt: now, receivedAt: now, payload }, toHex) : false;
  if (declared.history) {
    const ownRow: HistoryRow = {
      recordId: id,
      authorIdentityId: self,
      streamId: toHex(a.streamId),
      generation: big(a.generation),
      epoch: epoch.epoch,
      counter: sealed.counter,
      kind: row.kind,
      sentAt: big(now),
      receivedAt: big(now),
      plaintext: row.payload,
      superseded: false,
      own: true,
      ...(eventTime === undefined ? {} : { eventTime: big(eventTime) })
    };
    tx.put("history", id, ownRow);
    indexHistory(tx, ownRow);
  }
  const next: EpochRow = { ...epoch, nextCounter: epoch.nextCounter + 1, lastSentAt: big(now) };
  tx.put("epochs", String(epoch.epoch), next);
  return { epoch: next, recordId: id, own };
}

export interface DrainSummary {
  sent: number;
  accepted: number;
  cancelled: number;
  unknown: number;
  retry: number;
  /** Records the host refused as AUDIENCE_STALE in this drain, now held for the next epoch. */
  held: number;
  /** Held records sealed again under a new epoch in this drain. */
  resealed: number;
  /** The local ids of the records the relay accepted in this drain. */
  acceptedLocalIds: string[];
  /** Record bytes handed to the relay by this drain. */
  bytes: number;
  /** The error that ended the drain early, when a send failed before or without an answer (NETWORK, RATE_LIMITED); its record stays queued. */
  blocked?: KavachError;
}

/** "none": nothing to send, the drain ends. "skipped": a row was cancelled, the next one is tried. */
type HandoffStep = { kind: "none" } | { kind: "skipped" } | { kind: "sent"; key: string; row: OutboxRow; outcome: Promise<AppendOutcome> };

/**
 * The single serialised sender: one record in flight per stream, drained in (epoch, counter)
 * order. Each handoff is T6h: re-check eligibility, mark in flight, start the send inside the
 * transaction, commit; the response is awaited outside and recorded in a new transaction that
 * revalidates first.
 */
export async function drain(deps: OutboxDeps, maxRecords = 1000): Promise<DrainSummary> {
  const summary: DrainSummary = { sent: 0, accepted: 0, cancelled: 0, unknown: 0, retry: 0, held: 0, resealed: 0, acceptedLocalIds: [], bytes: 0 };
  for (let i = 0; i < maxRecords; i++) {
    const step = await handoffNext(deps, summary);
    if (step.kind === "none") break;
    if (step.kind === "skipped") continue; // a cancelled row counts against the limit, never ends the drain
    summary.sent++;
    summary.bytes += step.row.wire.length / 2;
    let outcome: AppendOutcome | undefined;
    try {
      outcome = await step.outcome;
    } catch (e) {
      outcome = undefined; // no answer: the identical bytes are retried, the relay answers from its checkpoint
      if (e instanceof KavachError) summary.blocked ??= e; // and the reason reaches the report
    }
    const final = await recordOutcome(deps, step.key, outcome, summary);
    if (final === "accepted") {
      summary.accepted++;
      summary.acceptedLocalIds.push(step.key);
    }
    else if (final === "cancelled") summary.cancelled++;
    else if (final === "unknown") summary.unknown++;
    else if (final === "held") break; // the epoch is refused: nothing more goes out until the next one
    else {
      summary.retry++;
      break; // a retryable failure ends this drain; the next sync re-enters T6h
    }
  }
  return summary;
}

/** Dead rows cancelled per handoff transaction; a larger backlog is finished over the next handoffs. */
const CANCEL_BATCH = 500;

/** A row that will not be sent again keeps its summary and sheds the ciphertext and the payload. */
export function terminal(row: OutboxRow, status: "cancelled" | "unknown", reason: string): OutboxRow {
  const { payload: _payload, eventTime: _eventTime, heldEpoch: _heldEpoch, ...rest } = row;
  void _payload;
  void _eventTime;
  void _heldEpoch;
  return { ...rest, wire: "", status, reason };
}

/**
 * Seal a held record again under `epoch`, with the next counter: a new record with a new id. The
 * row, the sender's own history row and slot, and an idempotency key that named the old id all
 * move to the new one, in this transaction. The epoch row's counter advances; the caller passes
 * the returned epoch row to the next reseal.
 */
function resealIn(tx: Tx, deps: OutboxDeps, key: string, row: OutboxRow, epoch: EpochRow, now: bigint): { epoch: EpochRow; oldId: string; newId: string } | undefined {
  const declared = kindOf(deps.policy, row.kind);
  if (!declared || row.payload === undefined) return undefined;
  const a = deps.author();
  const eventTime = row.eventTime === undefined ? undefined : unbig(row.eventTime);
  const sealed = sealRecord({
    streamId: a.streamId,
    epoch: epoch.epoch,
    nextCounter: epoch.nextCounter,
    kind: row.kind,
    eventTime,
    headerClass: declared.headerClass,
    payload: fromHex(row.payload),
    sentAt: now,
    epochKey: fromHex(epoch.epochKey),
    signingSecretKey: a.signingSecretKey
  });
  const oldId = row.recordId;
  const newId = toHex(sealed.recordId);
  const { heldEpoch: _held, ...rest } = row;
  void _held;
  // The row stays at its local id: only the record id moves.
  // Only a reseal after AUDIENCE_STALE counts toward its once-only rule; one after a rotation does not.
  const { staleHeld: _stale, ...unmarked } = rest;
  void _stale;
  tx.put("outbox", key, { ...unmarked, recordId: newId, wire: toHex(sealed.wire), epoch: epoch.epoch, counter: sealed.counter, sentAt: big(now), desiredRevision: big(currentRevision(tx)), status: "queued", attempts: 0, reason: undefined, ...(row.staleHeld || row.resealed ? { resealed: true } : {}) });
  const next: EpochRow = { ...epoch, nextCounter: epoch.nextCounter + 1, lastSentAt: big(now) };
  tx.put("epochs", String(epoch.epoch), next);
  const history = tx.get("history", oldId);
  if (history) {
    unindexHistory(tx, history);
    tx.delete("history", oldId);
    const moved: HistoryRow = { ...history, recordId: newId, epoch: epoch.epoch, counter: sealed.counter, sentAt: big(now) };
    tx.put("history", newId, moved);
    indexHistory(tx, moved);
  }
  const slot = slotKey(toHex(a.identityId), row.kind);
  const own = tx.get("newest", slot);
  if (own?.recordId === oldId) {
    tx.put("newest", slot, { ...own, recordId: newId, epoch: epoch.epoch, counter: sealed.counter, sentAt: big(now), eventTime: big(clampEventTime(eventTime, now)), bodyHash: toHex(bodyHash(sealed.wire.subarray(0, sealed.wire.length - 64))) });
  }
  if (row.idempotencyKey !== undefined) {
    const k = tx.get("enqueueKeys", row.idempotencyKey);
    if (k) tx.put("enqueueKeys", row.idempotencyKey, { ...k, localId: k.localId ?? key, recordId: newId, epoch: epoch.epoch, counter: sealed.counter });
  } else for (const [k, e] of tx.list("enqueueKeys")) if (e.recordId === oldId) tx.put("enqueueKeys", k, { ...e, localId: e.localId ?? key, recordId: newId, epoch: epoch.epoch, counter: sealed.counter });
  return { epoch: next, oldId, newId };
}

/**
 * Records waiting for an epoch, oldest first: past their window they are cancelled; under a usable
 * epoch a held one is sealed again once (never under the epoch it was refused in) and an unsealed
 * one is sealed for the first time. Returns how many were cancelled; events go to `after`.
 */
function sealWaitingIn(tx: Tx, deps: OutboxDeps, now: bigint, summary: Pick<DrainSummary, "resealed">, after: (() => void)[]): number {
  // Records waiting for an epoch first, oldest first: past their window they are cancelled. A held
  // one is sealed again under the active epoch only when every recipient of that epoch could read
  // it before (revision 13): no one added since sees it, and anyone removed is already out. An
  // unsealed one is sealed for the first time under a normal epoch, never a catch-up one.
  let target = activeEpochIn(tx);
  let cancelled = 0;
  const waiting = [...tx.list("outbox")].filter(([, r]) => r.status === "held" || r.status === "unsealed").sort(([, a], [, b]) => (a.status === b.status ? 0 : a.status === "held" ? -1 : 1) || a.epoch - b.epoch || a.counter - b.counter || (a.sentAt < b.sentAt ? -1 : a.sentAt > b.sentAt ? 1 : 0));
  for (const [key, row] of waiting) {
    if (unbig(row.sentAt) + deps.policy.deliveryWindowMs <= now) {
      tx.put("outbox", key, terminal(row, "cancelled", "expired"));
      cancelled++;
      after.push(() => deps.events?.cancelled?.(refOf(key, row), "expired"));
      continue;
    }
    if (row.status === "held" && row.payload === undefined) {
      // Held from before payloads were kept: it cannot be sealed again, and the app is told.
      tx.put("outbox", key, terminal(row, "cancelled", "rotation"));
      cancelled++;
      after.push(() => deps.events?.cancelled?.(refOf(key, row), "rotation"));
      continue;
    }
    if (!target || target.nextCounter > MAX_COUNTER) continue;
    if (row.status === "held") {
      if (!servesHeld(tx, target, row)) continue; // a catch-up epoch comes first, or a later one
      const moved = resealIn(tx, deps, key, row, target, now);
      if (!moved) continue;
      target = moved.epoch;
      summary.resealed++;
      const ref: RecordRef = { localId: fromHex(key), recordId: fromHex(moved.newId), idempotencyKey: row.idempotencyKey };
      after.push(() => deps.events?.resealed?.(ref, fromHex(moved.oldId)));
    } else {
      if (!kindOf(deps.policy, row.kind)) {
        // The kind left the policy while the record waited: it cannot be sealed.
        tx.put("outbox", key, terminal(row, "cancelled", "undeclared"));
        cancelled++;
        after.push(() => deps.events?.cancelled?.(refOf(key, row), "undeclared"));
        continue;
      }
      if (target.catchUpFor !== undefined) continue; // a catch-up epoch carries held records only
      const sealed = firstSealIn(tx, deps, key, row, target, now);
      target = sealed.epoch;
      const ref: RecordRef = { localId: fromHex(key), recordId: fromHex(sealed.recordId), idempotencyKey: row.idempotencyKey };
      after.push(() => deps.events?.sealed?.(ref, row.kind, sealed.own));
    }
  }
  return cancelled;
}

/**
 * Seal what waits for an epoch now, without sending (0.9.0): `enqueue` calls it after preparing an
 * epoch, so a record queued unsealed is sealed at once when the device could rotate.
 */
export async function sealWaiting(deps: OutboxDeps): Promise<void> {
  const after: (() => void)[] = [];
  await deps.store.transaction((tx) => {
    const meta = tx.get("meta", META);
    if (!meta || meta.state !== "ACTIVE") return;
    sealWaitingIn(tx, deps, deps.now(), { resealed: 0 }, after);
  });
  for (const fire of after) fire();
}

async function handoffNext(deps: OutboxDeps, summary: DrainSummary): Promise<HandoffStep> {
  // Application events fire after the commit, never from inside it: a subscriber cannot roll a
  // transition back, and never sees state the store has not kept yet.
  const after: (() => void)[] = [];
  const step = await deps.store.transaction((tx): HandoffStep => {
    const meta = tx.get("meta", META);
    if (!meta || meta.state !== "ACTIVE") return { kind: "none" };
    const now = deps.now();
    const revision = currentRevision(tx);
    // One pass: every row that is no longer sendable (its revision moved on, or its window has
    // passed) is cancelled here, in bounded batches, and the first sendable row goes out in the
    // same transaction. A backlog of dead rows costs one scan, not one transaction per row.
    const live: [string, OutboxRow][] = [];
    let cancelled = sealWaitingIn(tx, deps, now, summary, after);
    for (const [key, row] of [...tx.list("outbox")].sort(([, a], [, b]) => a.epoch - b.epoch || a.counter - b.counter)) {
      if (row.status !== "queued" && row.status !== "inflight") continue;
      if (row.status === "queued" && row.attempts === 0 && unbig(row.desiredRevision) !== revision) {
        // Sealed under a revision that moved on and never sent: held for an epoch that may carry it
        // (revision 13), never cancelled. One handed off before is retried as it is: the host may
        // hold it, and a second seal would deliver it twice; its checkpoint answers, and only a
        // refusal (EPOCH_FENCED) holds it.
        tx.put("outbox", key, { ...row, status: "held", heldEpoch: row.epoch });
        continue;
      }
      const reason = cancelled >= CANCEL_BATCH ? undefined : unbig(row.sentAt) + deps.policy.deliveryWindowMs <= now ? "expired" : undefined;
      if (!reason) {
        live.push([key, row]);
        continue;
      }
      tx.put("outbox", key, terminal(row, "cancelled", reason));
      cancelled++;
      after.push(() => deps.events?.cancelled?.(refOf(key, row), reason));
    }
    summary.cancelled += cancelled;
    // A full batch means unchecked rows remain: finish them in the next handoff before sending.
    if (cancelled >= CANCEL_BATCH) return { kind: "skipped" };
    const next = live.find(([, r]) => r.status === "inflight") ?? live[0];
    if (!next) return { kind: "none" };
    const [key, row] = next;
    const marked: OutboxRow = { ...row, status: "inflight", attempts: row.attempts + 1 };
    tx.put("outbox", key, marked);
    let outcome: Promise<AppendOutcome>;
    try {
      outcome = tx.handoff(() => deps.relay.appendRecord(fromHex(row.recordId), fromHex(row.wire), { revision: PROTOCOL_REVISION }));
    } catch {
      // A synchronous transport failure: roll the in-flight mark back and stop this drain.
      tx.put("outbox", key, { ...row, attempts: row.attempts + 1 });
      summary.retry++;
      return { kind: "none" };
    }
    return { kind: "sent", key, row: marked, outcome };
  });
  for (const fire of after) fire();
  return step;
}

type Final = "accepted" | "cancelled" | "unknown" | "retry" | "held";

export async function recordOutcome(deps: OutboxDeps, key: string, outcome: AppendOutcome | undefined, summary?: DrainSummary): Promise<Final> {
  const after: (() => void)[] = [];
  const final = await deps.store.transaction((tx): Final => {
    const row = tx.get("outbox", key);
    if (!row || row.status !== "inflight") return "retry";
    const id = refOf(key, row);
    const requeue = (): void => tx.put("outbox", key, { ...row, status: "queued", reason: undefined });
    const cancel = (reason: string): void => tx.put("outbox", key, terminal(row, "cancelled", reason));
    if (!outcome) {
      requeue(); // lost response: retry the identical bytes; the relay answers from its checkpoint
      return "retry";
    }
    switch (outcome.status) {
      case "ACCEPTED":
      case "ALREADY_ACCEPTED": {
        // Kept without bytes for the delivery window, so `delivery(localId)` can answer later, from
        // any runtime; the retention purge removes it with the other finished rows.
        const { payload: _payload, eventTime: _eventTime, heldEpoch: _heldEpoch, ...rest } = row;
        void _payload;
        void _eventTime;
        void _heldEpoch;
        tx.put("outbox", key, { ...rest, wire: "", status: "accepted", reason: undefined });
        after.push(() => deps.events?.accepted?.(id));
        return "accepted";
      }
      case "RETRYABLE":
        requeue();
        return "retry";
      case "STALE_APPEND":
        tx.put("outbox", key, terminal(row, "unknown", "STALE_APPEND"));
        after.push(() => deps.events?.cancelled?.(id, "acceptanceUnknown"));
        if (kindOf(deps.policy, row.kind)?.newest) after.push(() => deps.events?.refresh?.("acceptanceUnknown"));
        return "unknown";
      case "EQUIVOCATION":
        cancel("EQUIVOCATION");
        after.push(() => deps.events?.securityError?.("EQUIVOCATION", "the relay holds a different record under this id"));
        return "cancelled";
      case "AUDIENCE_STALE": {
        // The epoch is current, its recipients are not: every row sealed under it shares the refused
        // audience, the answered one and those queued behind it. Each is held for the next epoch,
        // once; a row already resealed (or from before payloads were kept) is cancelled. The epoch
        // is retired (T3) after the rows are held, so the rotation cancels none of them, and the
        // next sync runs full to learn the membership the host acted on.
        let fate: Final = "held";
        let held = 0;
        let refreshNeeded = false;
        const rows = tx.list("outbox").filter(([k, r]) => k === key || (r.epoch === row.epoch && r.status === "queued"));
        for (const [k, r] of rows) {
          const current = k === key ? row : r;
          const rid = refOf(k, current);
          if (current.resealed || current.payload === undefined) {
            tx.put("outbox", k, terminal(current, "cancelled", "AUDIENCE_STALE"));
            after.push(() => deps.events?.cancelled?.(rid, "AUDIENCE_STALE"));
            if (kindOf(deps.policy, current.kind)?.newest) refreshNeeded = true;
            if (k === key) fate = "cancelled";
            else if (summary) summary.cancelled++;
          } else {
            tx.put("outbox", k, { ...current, status: "held", heldEpoch: current.epoch, staleHeld: true });
            held++;
          }
        }
        t3ApplyChange(tx, { kind: "audienceStale" });
        const meta = tx.get("meta", META);
        if (meta) tx.put("meta", META, { ...meta, fullSyncDue: true });
        if (summary) summary.held += held;
        if (refreshNeeded) after.push(() => deps.events?.refresh?.("AUDIENCE_STALE"));
        after.push(() => deps.events?.audienceStale?.(held));
        return fate;
      }
      case "EPOCH_FENCED": {
        if (row.payload !== undefined) {
          // The epoch is no longer the stream's current one: the host did not take the record, so it
          // is held and sealed again under an epoch that may carry it (revision 13).
          tx.put("outbox", key, { ...row, status: "held", heldEpoch: row.epoch });
          if (summary) summary.held++; // held work the drain goes on for
          return "held";
        }
        // From before payloads were kept: it cannot be sealed again.
        cancel("EPOCH_FENCED");
        after.push(() => deps.events?.cancelled?.(id, "EPOCH_FENCED"));
        if (kindOf(deps.policy, row.kind)?.newest) after.push(() => deps.events?.refresh?.("EPOCH_FENCED"));
        return "cancelled";
      }
      case "SUPERSEDED_DEVICE":
      case "UNAUTHORIZED":
        cancel(outcome.status);
        after.push(() => deps.events?.cancelled?.(id, outcome.status));
        if (kindOf(deps.policy, row.kind)?.newest) after.push(() => deps.events?.refresh?.(outcome.status));
        return "cancelled";
    }
  });
  for (const fire of after) fire();
  return final;
}

/** Retention for rows that will not be sent again: they go once the delivery window has passed. */
export async function purgeOutbox(store: Store, policy: RetentionPolicy, now: bigint): Promise<number> {
  return store.transaction((tx) => {
    let purged = 0;
    for (const [key, row] of tx.list("outbox")) {
      if ((row.status === "cancelled" || row.status === "unknown" || row.status === "accepted") && unbig(row.sentAt) + policy.deliveryWindowMs <= now) {
        tx.delete("outbox", key);
        purged++;
      }
    }
    // Idempotency keys outlive the delivery window by nothing: a replay later is a new record.
    for (const [key, row] of tx.list("enqueueKeys")) if (unbig(row.sentAt) + policy.deliveryWindowMs <= now) tx.delete("enqueueKeys", key);
    return purged;
  });
}

export interface OutboxCounts {
  readonly queued: number;
  readonly inflight: number;
  /** Refused as AUDIENCE_STALE, waiting for the next epoch. */
  readonly held: number;
  /** Enqueued while no epoch was usable, waiting to be sealed. */
  readonly unsealed: number;
  readonly cancelled: number;
  readonly unknown: number;
  /** Age of the oldest row still to send, when there is one. */
  readonly oldestPendingAgeMs: bigint | undefined;
}

/** Rows by state, for diagnostics. */
export function outboxCounts(tx: Pick<Tx, "list">, now: bigint): OutboxCounts {
  const counts = { queued: 0, inflight: 0, held: 0, unsealed: 0, cancelled: 0, unknown: 0 };
  let oldest: bigint | undefined;
  for (const [, r] of tx.list("outbox")) {
    if (r.status === "accepted") continue;
    counts[r.status]++;
    if (r.status === "queued" || r.status === "inflight" || r.status === "held" || r.status === "unsealed") {
      const sentAt = unbig(r.sentAt);
      if (oldest === undefined || sentAt < oldest) oldest = sentAt;
    }
  }
  return { ...counts, oldestPendingAgeMs: oldest === undefined ? undefined : now - oldest };
}

/** Rows still waiting, for state reporting. */
export async function outboxCount(store: Store): Promise<number> {
  return store.read((tx) => outboxCountIn(tx));
}

/** The records still to send, inside a read the caller holds. */
export function outboxCountIn(tx: Pick<Tx, "list">): number {
  return tx.list("outbox").filter(([, r]) => r.status === "queued" || r.status === "inflight" || r.status === "held" || r.status === "unsealed").length;
}
