/**
 * The newest slot (protocol section 10): for every kind declared `newest`, one row per author
 * holding the newest record from the author's current device, shared by the receiver (T7) and
 * the sender's own row (T6). Order: a newer device generation first; within one generation the
 * later event time, clamped to the record's `sentAt` so a clock set ahead cannot hold the slot;
 * equal event times by (epoch, counter). The slot outlives its payload: expiry drops the payload
 * and keeps the order, so an older record replayed later cannot become current.
 */
import { decodeLocation } from "./codec.js";
import { compareSlots } from "./record.js";
import { big, unbig } from "./rows.js";
import type { NewestRow, Tx } from "./store.js";

export interface SlotOrder {
  readonly generation: bigint;
  readonly eventTime: bigint;
  readonly epoch: number;
  readonly counter: number;
}

export function compareSlotOrder(a: SlotOrder, b: SlotOrder): number {
  if (a.generation !== b.generation) return a.generation < b.generation ? -1 : 1;
  if (a.eventTime !== b.eventTime) return a.eventTime < b.eventTime ? -1 : 1;
  return compareSlots(a, b);
}

/**
 * The event time of a record until revision 8 carries it in the envelope: the location codec's
 * `capturedAt` when the payload is one, never later than `sentAt`; `sentAt` otherwise.
 */
export function eventTimeOf(plaintext: Uint8Array, sentAt: bigint): bigint {
  try {
    const captured = decodeLocation(plaintext).capturedAt;
    return captured < sentAt ? captured : sentAt;
  } catch {
    return sentAt;
  }
}

export function slotKey(authorIdentityId: string, kind: number): string {
  return `${authorIdentityId}:${kind}`;
}

export function slotOrderOf(row: NewestRow): SlotOrder {
  return { generation: unbig(row.generation), eventTime: unbig(row.eventTime), epoch: row.epoch, counter: row.counter };
}

export interface SlotCandidate extends SlotOrder {
  readonly recordId: string;
  readonly bodyHash: string;
  readonly sentAt: bigint;
  readonly receivedAt: bigint;
  readonly payload: Uint8Array;
}

/** Take the slot if the candidate orders after its current holder (or there is none); true when it did. */
export function takeSlot(tx: Tx, authorIdentityId: string, kind: number, c: SlotCandidate, toHex: (b: Uint8Array) => string): boolean {
  const key = slotKey(authorIdentityId, kind);
  const current = tx.get("newest", key);
  if (current && compareSlotOrder(c, slotOrderOf(current)) <= 0) return false;
  const next: NewestRow = { recordId: c.recordId, bodyHash: c.bodyHash, generation: big(c.generation), epoch: c.epoch, counter: c.counter, sentAt: big(c.sentAt), receivedAt: big(c.receivedAt), eventTime: big(c.eventTime), payload: toHex(c.payload) };
  tx.put("newest", key, next);
  return true;
}
