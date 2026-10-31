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
 * id is returned only after commit.
 */
export async function enqueue(deps: OutboxDeps, kind: RecordKind, payload: Uint8Array): Promise<{ recordId: Uint8Array; counter: number; epoch: number }> {
  const stage = "enqueue";
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
    for (const [, row] of tx.list("outbox")) {
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

type HandoffStep = { kind: "none" } | { kind: "sent"; key: string; row: OutboxRow; outcome: Promise<AppendOutcome> };

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

async function handoffNext(deps: OutboxDeps, summary: DrainSummary): Promise<HandoffStep> {
  return deps.store.transaction((tx) => {
    const meta = tx.get("meta", META);
    if (!meta || meta.state !== "ACTIVE") return { kind: "none" };
    const rows = tx
      .list("outbox")
      .filter(([, r]) => r.status === "queued" || r.status === "inflight")
      .sort(([, a], [, b]) => a.epoch - b.epoch || a.counter - b.counter);
    const inflight = rows.find(([, r]) => r.status === "inflight");
    const next = inflight ?? rows[0];
    if (!next) return { kind: "none" };
    const [key, row] = next;
    const now = deps.now();
    const revision = currentRevision(tx);
    if (unbig(row.desiredRevision) !== revision) {
      tx.put("outbox", key, { ...row, status: "cancelled", reason: "rotation" });
      summary.cancelled++;
      deps.events?.cancelled?.(fromHex(row.recordId), "rotation");
      if (row.kind === 0) deps.events?.needsLocation?.("rotation");
      return { kind: "none" };
    }
    if (unbig(row.sentAt) + deps.policy.deliveryWindowMs <= now) {
      tx.put("outbox", key, { ...row, status: "cancelled", reason: "expired" });
      summary.cancelled++;
      deps.events?.cancelled?.(fromHex(row.recordId), "expired");
      return { kind: "none" };
    }
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
}

type Final = "accepted" | "cancelled" | "unknown" | "retry";

export async function recordOutcome(deps: OutboxDeps, key: string, outcome: AppendOutcome | undefined): Promise<Final> {
  return deps.store.transaction((tx) => {
    const row = tx.get("outbox", key);
    if (!row || row.status !== "inflight") return "retry";
    const id = fromHex(row.recordId);
    const finish = (status: OutboxRow["status"], reason?: string): void => {
      if (status === "accepted") tx.delete("outbox", key);
      else tx.put("outbox", key, { ...row, status, reason });
    };
    if (!outcome) {
      finish("queued"); // lost response: retry the identical bytes; the relay answers from its checkpoint
      return "retry";
    }
    switch (outcome.status) {
      case "ACCEPTED":
      case "ALREADY_ACCEPTED":
        finish("accepted");
        deps.events?.accepted?.(id);
        return "accepted";
      case "RETRYABLE":
        finish("queued");
        return "retry";
      case "STALE_APPEND":
        finish("unknown", "STALE_APPEND");
        deps.events?.cancelled?.(id, "acceptanceUnknown");
        if (row.kind === 0) deps.events?.needsLocation?.("acceptanceUnknown");
        return "unknown";
      case "EQUIVOCATION":
        finish("cancelled", "EQUIVOCATION");
        deps.events?.securityError?.("EQUIVOCATION", "the relay holds a different record under this id");
        return "cancelled";
      case "EPOCH_FENCED":
      case "SUPERSEDED_DEVICE":
      case "UNAUTHORIZED":
        finish("cancelled", outcome.status);
        deps.events?.cancelled?.(id, outcome.status);
        if (row.kind === 0) deps.events?.needsLocation?.(outcome.status);
        return "cancelled";
    }
  });
}

/** Rows still waiting, for state reporting. */
export async function outboxCount(store: Store): Promise<number> {
  return store.read((tx) => tx.list("outbox").filter(([, r]) => r.status === "queued" || r.status === "inflight").length);
}
