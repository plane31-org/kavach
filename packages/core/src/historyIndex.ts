/**
 * The history index: two time-ordered keys per history row, so a history query, a cursor and
 * the retention purge read a bounded slice of the store instead of the whole history table.
 *
 * Keys sort by time and are unique: the tuple is the zero-padded `sentAt`, epoch and counter
 * followed by the record id. `t:<kind>:<tuple>` is the timeline of one kind; `a:<author>:<kind>:
 * <tuple>` is one author's. A query without a kind merges the two kinds that reach history
 * (locations and check-ins); a status is never history. The tuple doubles as the page cursor:
 * it names a position that no later write moves.
 */
import type { RecordKind } from "./codec.js";
import { unbig } from "./rows.js";
import type { HistoryRow, Store, Tx } from "./store.js";

export const HISTORY_KINDS: readonly RecordKind[] = [0, 1];
const META = "meta";

/** A u64 as twenty decimal digits, so that string order is numeric order. */
export function padTime(ms: bigint): string {
  return (ms < 0n ? 0n : ms).toString().padStart(20, "0");
}

export function historyTuple(r: Pick<HistoryRow, "sentAt" | "epoch" | "counter" | "recordId">): string {
  return `${padTime(unbig(r.sentAt))}:${r.epoch.toString().padStart(10, "0")}:${r.counter.toString().padStart(10, "0")}:${r.recordId}`;
}

export function timelinePrefix(kind: RecordKind): string {
  return `t:${kind}:`;
}

export function authorPrefix(authorIdentityId: string, kind: RecordKind): string {
  return `a:${authorIdentityId}:${kind}:`;
}

function keysOf(r: HistoryRow): string[] {
  const tuple = historyTuple(r);
  return [timelinePrefix(r.kind) + tuple, authorPrefix(r.authorIdentityId, r.kind) + tuple];
}

/** Index a history row; written in the same transaction as the row (T6, T7). */
export function indexHistory(tx: Tx, r: HistoryRow): void {
  for (const k of keysOf(r)) tx.put("historyIndex", k, { recordId: r.recordId });
}

export function unindexHistory(tx: Tx, r: HistoryRow): void {
  for (const k of keysOf(r)) tx.delete("historyIndex", k);
}

/**
 * Build the index once for a store written before it existed: every history row is indexed and
 * the header records it. A fresh store is marked at T1 and never runs this. Idempotent.
 */
export async function ensureHistoryIndex(store: Store): Promise<boolean> {
  const built = await store.read((tx) => tx.get("meta", META)?.historyIndex === 1);
  if (built) return false;
  return store.transaction((tx) => {
    const meta = tx.get("meta", META);
    if (!meta || meta.historyIndex === 1) return false;
    for (const [, r] of tx.list("history")) indexHistory(tx, r);
    tx.put("meta", META, { ...meta, historyIndex: 1 });
    return true;
  });
}
