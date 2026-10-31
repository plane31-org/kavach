/**
 * The outbox and the sender (protocol section 10, publishing; transactions T6 and T6h).
 */
import { fromHex, toHex } from "./bytes.js";
import { rotationReason, MAX_COUNTER } from "./epoch.js";
import { KavachError } from "./errors.js";
import type { RetentionPolicy } from "./policy.js";
import { sealRecord } from "./record.js";
import { big, unbig } from "./rows.js";
import type { OutboxRow, Store, Tx } from "./store.js";
import { META, REVISION, STREAM, currentRevision, t3ApplyChange } from "./transactions.js";
import type { AppendOutcome, Relay } from "./transport.js";
import type { RecordKind } from "./codec.js";

export interface OutboxEvents {
  queued?(recordId: Uint8Array, kind: RecordKind): void;
  accepted?(recordId: Uint8Array): void;
  cancelled?(recordId: Uint8Array, reason: string): void;
  /** A location's acceptance is unknown or it was cancelled: the host should supply a fresh sample. */
  needsLocation?(reason: string): void;
  securityError?(code: string, detail: string): void;
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

/**
 * T6: require a usable active epoch under the current desired revision, enforce the queue limits,
 * seal once, write the outbox row and the own history row, and advance the counter. The record
 * id is returned only after commit. A status (kind 2) is latest-wins: a status still queued when
 * a newer one is enqueued is cancelled, never sent, and a status writes no history row.
 */
export async function enqueue(deps: OutboxDeps, kind: RecordKind, payload: Uint8Array): Promise<{ recordId: Uint8Array; counter: number; epoch: number }> {
  const stage = "enqueue";
  const superseded: Uint8Array[] = [];
  const result = await deps.store.transaction((tx) => {
    requireReady(tx);
    const revision = tx.get("revision", REVISION);
    if (revision?.paused === "metadata") throw new KavachError("METADATA_REQUIRED", stage);
    if (revision?.paused === "limit") throw new KavachError("RECIPIENT_LIMIT", stage);
    const stream = tx.get("stream", STREAM);
    if (!stream || stream.activeEpoch === undefined || revision?.paused === "rotation") throw new KavachError("ROTATION_REQUIRED", stage, "no active epoch");
    const epoch = tx.get("epochs", String(stream.activeEpoch));
    if (!epoch || epoch.status !== "active") throw new KavachError("ROTATION_REQUIRED", stage, "epoch not active");
    const now = deps.now();
    const reason = rotationReason({ createdAt: unbig(epoch.createdAt), nextCounter: epoch.nextCounter, lastSentAt: epoch.lastSentAt === undefined ? undefined : unbig(epoch.lastSentAt) }, now, deps.policy.hygieneRotationMs);
    if (reason) {
      // Commit the invalidation (T3) and report the rotation after the transaction, so the
      // burned counters and cancelled rows are durable even though nothing was enqueued.
      t3ApplyChange(tx, { kind: reason });
      return { rotate: reason } as const;
    }
    let count = 0;
    let bytes = 0;
    for (const [key, row] of tx.list("outbox")) {
      if (kind === 2 && row.kind === 2 && row.status === "queued") {
        tx.put("outbox", key, terminal(row, "cancelled", "superseded"));
        superseded.push(fromHex(row.recordId));
        continue;
      }
      if (row.status === "queued" || row.status === "inflight") {
        count++;
        bytes += row.wire.length / 2;
      }
    }
    if (count >= deps.policy.maxOutboxRecords || bytes + payload.length + 159 > deps.policy.maxOutboxBytes) throw new KavachError("QUEUE_FULL", stage);
    const a = deps.author();
    const sealed = sealRecord({
      streamId: a.streamId,
      epoch: epoch.epoch,
      nextCounter: epoch.nextCounter,
      kind,
      payload,
      sentAt: now,
      epochKey: fromHex(epoch.epochKey),
      signingSecretKey: a.signingSecretKey
    });
    const id = toHex(sealed.recordId);
    tx.put("outbox", id, {
      recordId: id,
      wire: toHex(sealed.wire),
      epoch: epoch.epoch,
      counter: sealed.counter,
      kind,
      sentAt: big(now),
      desiredRevision: big(currentRevision(tx)),
      status: "queued",
      attempts: 0,
      reason: undefined
    });
    if (kind !== 2) {
      tx.put("history", id, {
        recordId: id,
        authorIdentityId: toHex(a.identityId),
        streamId: toHex(a.streamId),
        generation: big(a.generation),
        epoch: epoch.epoch,
        counter: sealed.counter,
        kind,
        sentAt: big(now),
        receivedAt: big(now),
        plaintext: toHex(payload),
        superseded: false,
        own: true
      });
    }
    const nextCounter = epoch.nextCounter + 1;
    tx.put("epochs", String(epoch.epoch), { ...epoch, nextCounter, lastSentAt: big(now) });
    if (nextCounter > MAX_COUNTER) {
      // The final counter was just used: the next enqueue rotates.
    }
    return { recordId: sealed.recordId, counter: sealed.counter, epoch: epoch.epoch };
  });
  if ("rotate" in result) {
    throw new KavachError(result.rotate === "counterExhausted" ? "COUNTER_EXHAUSTED" : "ROTATION_REQUIRED", stage, result.rotate);
  }
  for (const id of superseded) deps.events?.cancelled?.(id, "superseded");
  deps.events?.queued?.(result.recordId, kind);
  return result;
}

export interface DrainSummary {
  sent: number;
  accepted: number;
  cancelled: number;
  unknown: number;
  retry: number;
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
  const summary: DrainSummary = { sent: 0, accepted: 0, cancelled: 0, unknown: 0, retry: 0 };
  for (let i = 0; i < maxRecords; i++) {
    const step = await handoffNext(deps, summary);
    if (step.kind === "none") break;
    if (step.kind === "skipped") continue; // a cancelled row counts against the limit, never ends the drain
    summary.sent++;
    let outcome: AppendOutcome | undefined;
    try {
      outcome = await step.outcome;
    } catch {
      outcome = undefined; // lost response
    }
    const final = await recordOutcome(deps, step.key, outcome);
    if (final === "accepted") summary.accepted++;
    else if (final === "cancelled") summary.cancelled++;
    else if (final === "unknown") summary.unknown++;
    else {
      summary.retry++;
      break; // a retryable failure ends this drain; the next sync re-enters T6h
    }
  }
  return summary;
}

/** Dead rows cancelled per handoff transaction; a larger backlog is finished over the next handoffs. */
const CANCEL_BATCH = 500;

/** A row that will not be sent again keeps its summary and sheds the ciphertext. */
function terminal(row: OutboxRow, status: "cancelled" | "unknown", reason: string): OutboxRow {
  return { ...row, wire: "", status, reason };
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
    let cancelled = 0;
    let needsLocation = false;
    for (const [key, row] of [...tx.list("outbox")].sort(([, a], [, b]) => a.epoch - b.epoch || a.counter - b.counter)) {
      if (row.status !== "queued" && row.status !== "inflight") continue;
      const reason = cancelled >= CANCEL_BATCH ? undefined : unbig(row.desiredRevision) !== revision ? "rotation" : unbig(row.sentAt) + deps.policy.deliveryWindowMs <= now ? "expired" : undefined;
      if (!reason) {
        live.push([key, row]);
        continue;
      }
      tx.put("outbox", key, terminal(row, "cancelled", reason));
      cancelled++;
      after.push(() => deps.events?.cancelled?.(fromHex(row.recordId), reason));
      if (reason === "rotation" && row.kind === 0) needsLocation = true;
    }
    summary.cancelled += cancelled;
    if (needsLocation) after.push(() => deps.events?.needsLocation?.("rotation"));
    // A full batch means unchecked rows remain: finish them in the next handoff before sending.
    if (cancelled >= CANCEL_BATCH) return { kind: "skipped" };
    const next = live.find(([, r]) => r.status === "inflight") ?? live[0];
    if (!next) return { kind: "none" };
    const [key, row] = next;
    const marked: OutboxRow = { ...row, status: "inflight", attempts: row.attempts + 1 };
    tx.put("outbox", key, marked);
    let outcome: Promise<AppendOutcome>;
    try {
      outcome = tx.handoff(() => deps.relay.appendRecord(fromHex(row.recordId), fromHex(row.wire)));
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

type Final = "accepted" | "cancelled" | "unknown" | "retry";

export async function recordOutcome(deps: OutboxDeps, key: string, outcome: AppendOutcome | undefined): Promise<Final> {
  const after: (() => void)[] = [];
  const final = await deps.store.transaction((tx): Final => {
    const row = tx.get("outbox", key);
    if (!row || row.status !== "inflight") return "retry";
    const id = fromHex(row.recordId);
    const requeue = (): void => tx.put("outbox", key, { ...row, status: "queued", reason: undefined });
    const cancel = (reason: string): void => tx.put("outbox", key, terminal(row, "cancelled", reason));
    if (!outcome) {
      requeue(); // lost response: retry the identical bytes; the relay answers from its checkpoint
      return "retry";
    }
    switch (outcome.status) {
      case "ACCEPTED":
      case "ALREADY_ACCEPTED":
        tx.delete("outbox", key);
        after.push(() => deps.events?.accepted?.(id));
        return "accepted";
      case "RETRYABLE":
        requeue();
        return "retry";
      case "STALE_APPEND":
        tx.put("outbox", key, terminal(row, "unknown", "STALE_APPEND"));
        after.push(() => deps.events?.cancelled?.(id, "acceptanceUnknown"));
        if (row.kind === 0) after.push(() => deps.events?.needsLocation?.("acceptanceUnknown"));
        return "unknown";
      case "EQUIVOCATION":
        cancel("EQUIVOCATION");
        after.push(() => deps.events?.securityError?.("EQUIVOCATION", "the relay holds a different record under this id"));
        return "cancelled";
      case "EPOCH_FENCED":
      case "SUPERSEDED_DEVICE":
      case "UNAUTHORIZED":
        cancel(outcome.status);
        after.push(() => deps.events?.cancelled?.(id, outcome.status));
        if (row.kind === 0) after.push(() => deps.events?.needsLocation?.(outcome.status));
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
      if ((row.status === "cancelled" || row.status === "unknown") && unbig(row.sentAt) + policy.deliveryWindowMs <= now) {
        tx.delete("outbox", key);
        purged++;
      }
    }
    return purged;
  });
}

export interface OutboxCounts {
  readonly queued: number;
  readonly inflight: number;
  readonly cancelled: number;
  readonly unknown: number;
  /** Age of the oldest row still to send, when there is one. */
  readonly oldestPendingAgeMs: bigint | undefined;
}

/** Rows by state, for diagnostics. */
export function outboxCounts(tx: Pick<Tx, "list">, now: bigint): OutboxCounts {
  const counts = { queued: 0, inflight: 0, cancelled: 0, unknown: 0 };
  let oldest: bigint | undefined;
  for (const [, r] of tx.list("outbox")) {
    if (r.status === "accepted") continue;
    counts[r.status]++;
    if (r.status === "queued" || r.status === "inflight") {
      const sentAt = unbig(r.sentAt);
      if (oldest === undefined || sentAt < oldest) oldest = sentAt;
    }
  }
  return { ...counts, oldestPendingAgeMs: oldest === undefined ? undefined : now - oldest };
}

/** Rows still waiting, for state reporting. */
export async function outboxCount(store: Store): Promise<number> {
  return store.read((tx) => tx.list("outbox").filter(([, r]) => r.status === "queued" || r.status === "inflight").length);
}
