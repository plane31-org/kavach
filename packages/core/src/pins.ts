/**
 * The live pin's order (protocol section 10), shared by the receiver (T7) and the sender's own
 * row (T6): a newer device generation first; within one generation the later measurement, the
 * decoded `capturedAt` clamped to the record's `sentAt` so a phone clock set ahead cannot pin a
 * stale fix; equal measurements by (epoch, counter).
 */
import { fromHex } from "./bytes.js";
import { decodeLocation } from "./codec.js";
import { compareSlots } from "./record.js";
import { big, unbig } from "./rows.js";
import type { LivePinRow, Tx } from "./store.js";

export interface PinOrder {
  readonly generation: bigint;
  readonly capturedAt: bigint;
  readonly epoch: number;
  readonly counter: number;
}

export function comparePins(a: PinOrder, b: PinOrder): number {
  if (a.generation !== b.generation) return a.generation < b.generation ? -1 : 1;
  if (a.capturedAt !== b.capturedAt) return a.capturedAt < b.capturedAt ? -1 : 1;
  return compareSlots(a, b);
}

/** The measurement time of a kind 0 payload: its `capturedAt`, never later than `sentAt`; `sentAt` for a payload that is not the location codec. */
export function measuredAt(plaintext: Uint8Array, sentAt: bigint): bigint {
  try {
    const captured = decodeLocation(plaintext).capturedAt;
    return captured < sentAt ? captured : sentAt;
  } catch {
    return sentAt;
  }
}

/** A pin's order, deriving the measurement time from its record for a row written before revision 7. */
export function pinOrder(tx: Pick<Tx, "get">, pin: LivePinRow): PinOrder {
  let capturedAt = pin.capturedAt === undefined ? undefined : unbig(pin.capturedAt);
  if (capturedAt === undefined) {
    const row = tx.get("history", pin.recordId);
    capturedAt = row ? measuredAt(fromHex(row.plaintext), unbig(row.sentAt)) : unbig(pin.sentAt);
  }
  return { generation: unbig(pin.generation), capturedAt, epoch: pin.epoch, counter: pin.counter };
}

/** Advance an author's pin to a stored kind 0 record if it orders after the current pin; true when it moved. */
export function advancePin(tx: Tx, authorIdentityId: string, candidate: PinOrder & { recordId: string; sentAt: bigint }): boolean {
  const pin = tx.get("livePins", authorIdentityId);
  if (pin && comparePins(candidate, pinOrder(tx, pin)) <= 0) return false;
  const next: LivePinRow = { recordId: candidate.recordId, generation: big(candidate.generation), epoch: candidate.epoch, counter: candidate.counter, sentAt: big(candidate.sentAt), capturedAt: big(candidate.capturedAt) };
  tx.put("livePins", authorIdentityId, next);
  return true;
}
