/**
 * The receiver: records, history, the acknowledged prefix and the live pin
 * (protocol section 10, receiving; transaction T7).
 */
import { equalBytes, fromHex, toHex } from "./bytes.js";
import { DocumentType, expectType, parseDocument, type EncryptedRecord, type RecordKind } from "./codec.js";
import { bodyHash } from "./crypto.js";
import { openEpoch, type AuthorView, type SelfView } from "./epoch.js";
import { KavachError, isKavachError } from "./errors.js";
import type { RetentionPolicy } from "./policy.js";
import { HISTORY_KINDS, authorPrefix, indexHistory, padTime, timelinePrefix, unindexHistory } from "./historyIndex.js";
import { compareSlots, openRecordWire } from "./record.js";
import { big, unbig } from "./rows.js";
import type { HistoryRow, KeyRange, LivePinRow, Store, SubscriptionRow, Tx, StatusRow } from "./store.js";
import type { Relay } from "./transport.js";

export const MAX_FUTURE_SKEW_MS = 300_000n;
export const READ_BATCH = 100;

export type ReceiveResult =
  | { readonly result: "updated"; readonly recordId: Uint8Array; readonly authorIdentityId: Uint8Array; readonly kind: RecordKind }
  | { readonly result: "history"; readonly recordId: Uint8Array; readonly authorIdentityId: Uint8Array; readonly kind: RecordKind }
  | { readonly result: "duplicate"; readonly recordId: Uint8Array }
  | { readonly result: "keyPending"; readonly streamId: Uint8Array; readonly epoch: number }
  | { readonly result: "expired"; readonly reason: "window" | "CLOCK_SKEW" }
  | { readonly result: "invalid"; readonly reason: string };

export interface InboxEvents {
  received?(r: ReceiveResult): void;
  /** The author's current epoch has no key for this device yet: show the person as waiting. */
  waiting?(authorIdentityId: Uint8Array): void;
  securityError?(code: string, detail: string): void;
}

export interface InboxDeps {
  readonly store: Store;
  readonly relay: Relay;
  readonly policy: RetentionPolicy;
  readonly now: () => bigint;
  readonly self: () => SelfView;
  readonly events?: InboxEvents;
}

// Views over the store --------------------------------------------------------------------------

function authorViewFor(tx: Pick<Tx, "get" | "list">, streamId: Uint8Array): { view: AuthorView; identityId: Uint8Array } | undefined {
  const certs = tx.list("certificates").filter(([, c]) => c.streamId === toHex(streamId));
  const first = certs[0]?.[1];
  if (!first) return undefined;
  const all = tx.list("certificates").filter(([, c]) => c.identityId === first.identityId);
  const certificates = new Map(
    all.map(([, c]) => [c.certificateHash, { certificateHash: fromHex(c.certificateHash), signingKey: fromHex(c.signingKey), streamId: fromHex(c.streamId), current: c.current }])
  );
  return { view: { identityId: fromHex(first.identityId), certificates }, identityId: fromHex(first.identityId) };
}

function isAuthorized(tx: Pick<Tx, "get" | "list">, authorIdentityId: Uint8Array, self: Uint8Array): boolean {
  if (equalBytes(authorIdentityId, self)) return true;
  const hex = toHex(authorIdentityId);
  return tx.list("circles").some(([, c]) => c.status === "member" && c.members.includes(hex));
}

function epochKeyFor(tx: Pick<Tx, "get">, streamId: Uint8Array, epoch: number): Uint8Array | undefined {
  const row = tx.get("readerEpochs", `${toHex(streamId)}:${epoch}`);
  return row ? fromHex(row.epochKey) : undefined;
}

/** Fetch and verify an epoch's key through the relay and store it. Returns false when it cannot be had yet. */
async function fetchEpochKey(deps: InboxDeps, streamId: Uint8Array, epoch: number): Promise<boolean> {
  let bundle;
  try {
    bundle = await deps.relay.getEpoch(streamId, epoch);
  } catch {
    return false;
  }
  if (!bundle?.wrap) return false;
  const wrap = bundle.wrap;
  const self = deps.self();
  return deps.store.transaction((tx) => {
    const author = authorViewFor(tx, streamId);
    if (!author) return false;
    const opened = openEpoch(bundle.manifest, author.view, self, wrap); // throws the section 8 codes
    tx.put("readerEpochs", `${toHex(streamId)}:${epoch}`, {
      streamId: toHex(streamId),
      epoch,
      epochKey: toHex(opened.epochKey),
      manifestHash: toHex(opened.manifest.bodyHash),
      authorCertificateHash: toHex(opened.manifest.authorCertificateHash),
      superseded: opened.superseded
    });
    return true;
  });
}

// T7 -------------------------------------------------------------------------------------------------

/**
 * Verify, decrypt and store one record (T7). Replays are harmless upserts; a different valid
 * body for a retained id is `EQUIVOCATION`. The live pin moves only for kind 0 from the author's
 * current device and a greater (generation, epoch, counter).
 */
function storeRecord(tx: Tx, deps: InboxDeps, wire: Uint8Array, now: bigint): ReceiveResult {
  const self = deps.self();
  const parsed = expectType<EncryptedRecord>(parseDocument(wire), DocumentType.EncryptedRecord, "receive");
  if (parsed.sentAt > now + MAX_FUTURE_SKEW_MS) return { result: "expired", reason: "CLOCK_SKEW" };
  const author = authorViewFor(tx, parsed.streamId);
  if (!author) return { result: "invalid", reason: "NOT_AUTHORIZED" };
  if (!isAuthorized(tx, author.identityId, self.identityId)) return { result: "invalid", reason: "NOT_AUTHORIZED" };
  let opened;
  try {
    opened = openRecordWire(wire, author.view, (s, e) => epochKeyFor(tx, s, e));
  } catch (e) {
    if (isKavachError(e, "KEY_PENDING")) return { result: "keyPending", streamId: parsed.streamId, epoch: parsed.epoch };
    if (e instanceof KavachError) return { result: "invalid", reason: e.code };
    throw e;
  }
  const id = toHex(opened.recordId);
  const hash = toHex(bodyHash(opened.record.body));
  const cert = [...author.view.certificates.values()].find((c) => equalBytes(c.streamId, parsed.streamId));
  const generation = unbig(tx.list("certificates").find(([, c]) => c.streamId === toHex(parsed.streamId))?.[1].generation ?? "0");
  const base = { recordId: opened.recordId, authorIdentityId: author.identityId, kind: parsed.kind };
  if (parsed.kind === 2) {
    // A status is the author's current state, not an event: one row per author, newest slot wins,
    // never a pin, never a check-in, never history. An older or superseded one changes nothing.
    const key = toHex(author.identityId);
    const current = tx.get("statuses", key);
    if (current?.recordId === id) {
      if (current.bodyHash === hash) return { result: "duplicate", recordId: opened.recordId };
      return { result: "invalid", reason: "EQUIVOCATION" };
    }
    if (opened.superseded || !cert?.current) return { result: "history", ...base };
    const slot = { generation, epoch: parsed.epoch, counter: parsed.counter };
    if (current && compareSlots(slot, { generation: unbig(current.generation), epoch: current.epoch, counter: current.counter }) <= 0) return { result: "history", ...base };
    tx.put("statuses", key, { recordId: id, bodyHash: hash, generation: big(generation), epoch: parsed.epoch, counter: parsed.counter, sentAt: big(parsed.sentAt), receivedAt: big(now), payload: toHex(opened.plaintext) });
    return { result: "updated", ...base };
  }
  const existing = tx.get("history", id);
  if (existing) {
    if (existing.bodyHash === hash) return { result: "duplicate", recordId: opened.recordId };
    return { result: "invalid", reason: "EQUIVOCATION" };
  }
  const row: HistoryRow = {
    recordId: id,
    authorIdentityId: toHex(author.identityId),
    streamId: toHex(parsed.streamId),
    generation: big(generation),
    epoch: parsed.epoch,
    counter: parsed.counter,
    kind: parsed.kind,
    sentAt: big(parsed.sentAt),
    receivedAt: big(now),
    plaintext: toHex(opened.plaintext),
    superseded: opened.superseded || !cert?.current,
    own: false,
    bodyHash: hash
  };
  tx.put("history", id, row);
  indexHistory(tx, row);
  let moved = false;
  if (parsed.kind === 0 && !row.superseded) {
    const pinKey = toHex(author.identityId);
    const pin = tx.get("livePins", pinKey);
    const slot = { generation, epoch: parsed.epoch, counter: parsed.counter };
    if (!pin || compareSlots(slot, { generation: unbig(pin.generation), epoch: pin.epoch, counter: pin.counter }) > 0) {
      const next: LivePinRow = { recordId: id, generation: big(generation), epoch: parsed.epoch, counter: parsed.counter, sentAt: big(parsed.sentAt) };
      tx.put("livePins", pinKey, next);
      moved = true;
    }
  }
  return moved || parsed.kind === 1 ? { result: "updated", ...base } : { result: "history", ...base };
}

/** A record pushed by the host outside `sync`: stored, but it never advances a relay cursor. */
export async function receive(deps: InboxDeps, wire: Uint8Array): Promise<ReceiveResult> {
  const now = deps.now();
  let r = await deps.store.transaction((tx) => storeRecord(tx, deps, wire, now));
  if (r.result === "keyPending" && (await fetchEpochKey(deps, r.streamId, r.epoch).catch(() => false))) {
    r = await deps.store.transaction((tx) => storeRecord(tx, deps, wire, now));
  }
  if (r.result === "invalid" && r.reason === "EQUIVOCATION") deps.events?.securityError?.("EQUIVOCATION", "a different valid body for a retained record id");
  deps.events?.received?.(r);
  return r;
}

// Sync: read, process, acknowledge -------------------------------------------------------------------

export interface StreamSyncSummary {
  read: number;
  stored: number;
  duplicate: number;
  keyPending: number;
  invalid: number;
  expired: number;
  acked: bigint | undefined;
}

function subscription(tx: Pick<Tx, "get">, streamId: Uint8Array, authorIdentityId: Uint8Array): SubscriptionRow {
  return (
    tx.get("subscriptions", toHex(streamId)) ?? {
      streamId: toHex(streamId),
      authorIdentityId: toHex(authorIdentityId),
      scanPos: "0",
      ackPrefix: "0",
      committedCursor: "0",
      ackInFlight: false
    }
  );
}

/** The eligible prefix: the scan position, held back to just before the oldest unresolved sequence. */
function eligiblePrefix(tx: Pick<Tx, "list">, streamId: Uint8Array, scanPos: bigint, expiredThrough: bigint): bigint {
  let prefix = scanPos;
  for (const [, u] of tx.list("unresolved", toHex(streamId) + ":")) {
    const seq = unbig(u.deliverySeq);
    if (seq <= expiredThrough) continue; // the relay expired it: queue progress, never a receipt
    if (seq - 1n < prefix) prefix = seq - 1n;
  }
  return prefix;
}

/**
 * One pass over one author stream: read a batch above the local scan position, process every
 * record, hold the prefix at any `keyPending` record, and send at most one acknowledgement.
 */
export async function syncStream(deps: InboxDeps, streamId: Uint8Array, authorIdentityId: Uint8Array): Promise<StreamSyncSummary> {
  const summary: StreamSyncSummary = { read: 0, stored: 0, duplicate: 0, keyPending: 0, invalid: 0, expired: 0, acked: undefined };
  const sub = await deps.store.read((tx) => subscription(tx, streamId, authorIdentityId));
  // While a record is unresolved the scan restarts from the eligible prefix, so the held record is
  // read again; records already stored come back as harmless duplicates.
  const unresolved = await deps.store.read((tx) => tx.list("unresolved", toHex(streamId) + ":"));
  const from = unresolved.length > 0 ? unbig(sub.ackPrefix) : unbig(sub.scanPos);
  // A failed read is the caller's to report: the sync names the stream in its report and goes on
  // to the next one, rather than counting a stream it never read as synced.
  const page = await deps.relay.readRecords(streamId, from, READ_BATCH);
  const now = deps.now();
  // Drop unresolved entries the relay has expired.
  for (const [key, u] of unresolved) {
    if (unbig(u.deliverySeq) <= page.expiredThrough) {
      await deps.store.transaction((tx) => tx.delete("unresolved", key));
      summary.expired++;
    }
  }

  for (const item of page.records) {
    summary.read++;
    if (item.deliverySeq <= page.expiredThrough) {
      summary.expired++;
      continue;
    }
    let r = await deps.store.transaction((tx) => storeRecord(tx, deps, item.wire, now));
    if (r.result === "keyPending") {
      let fetched = false;
      try {
        fetched = await fetchEpochKey(deps, r.streamId, r.epoch);
      } catch (e) {
        if (isKavachError(e, "NOT_AUTHORIZED")) r = { result: "invalid", reason: "NOT_AUTHORIZED" };
        else if (e instanceof KavachError) {
          // The served manifest or wrap did not verify. The record may still be honest, so it is
          // held as keyPending (the prefix stops here, scenario 21) and the code is named; the
          // relay's expiry resolves a manifest that never verifies.
          deps.events?.securityError?.(e.code, `epoch ${r.epoch} of stream ${toHex(r.streamId).slice(0, 8)} refused`);
        } else throw e;
      }
      if (fetched) r = await deps.store.transaction((tx) => storeRecord(tx, deps, item.wire, now));
    }
    const seqKey = `${toHex(streamId)}:${item.deliverySeq.toString().padStart(20, "0")}`;
    await deps.store.transaction((tx) => {
      if (r.result === "keyPending") {
        tx.put("unresolved", seqKey, { streamId: toHex(streamId), deliverySeq: big(item.deliverySeq), reason: "KEY_PENDING", epoch: r.epoch, recordedAt: big(now) });
      } else tx.delete("unresolved", seqKey);
    });
    if (r.result === "keyPending") {
      summary.keyPending++;
      deps.events?.waiting?.(authorIdentityId);
    } else if (r.result === "invalid") {
      // The relay serves only records addressed to this device, so anything unverifiable here is
      // the host's or the author's doing: it is named to the app and never stored.
      summary.invalid++;
      deps.events?.securityError?.(r.reason, `record at sequence ${item.deliverySeq} refused`);
    } else if (r.result === "expired") summary.expired++;
    else if (r.result === "duplicate") summary.duplicate++;
    else summary.stored++;
    deps.events?.received?.(r);
  }

  // Advance the scan position and the eligible prefix; acknowledge once if it moved.
  const toAck = await deps.store.transaction((tx) => {
    const s = subscription(tx, streamId, authorIdentityId);
    const scanPos = page.nextSeq > unbig(s.scanPos) ? page.nextSeq : unbig(s.scanPos);
    const prefix = eligiblePrefix(tx, streamId, scanPos, page.expiredThrough);
    const committed = page.committedCursor > unbig(s.committedCursor) ? page.committedCursor : unbig(s.committedCursor);
    const next: SubscriptionRow = { ...s, scanPos: big(scanPos), ackPrefix: big(prefix), committedCursor: big(committed) };
    const send = prefix > committed && !s.ackInFlight;
    tx.put("subscriptions", toHex(streamId), { ...next, ackInFlight: send });
    return send ? prefix : undefined;
  });
  if (toAck !== undefined) {
    let committed: bigint | undefined;
    try {
      const ack = await deps.relay.ackThrough(streamId, toAck);
      if (ack.status === "COMMITTED") committed = ack.committedCursor ?? toAck;
    } catch {
      committed = undefined;
    }
    await deps.store.transaction((tx) => {
      const s = subscription(tx, streamId, authorIdentityId);
      tx.put("subscriptions", toHex(streamId), { ...s, ackInFlight: false, committedCursor: committed !== undefined && committed > unbig(s.committedCursor) ? big(committed) : s.committedCursor });
    });
    summary.acked = committed;
  }
  return summary;
}

// Reads ------------------------------------------------------------------------------------------------

export interface HistoryEntry {
  readonly recordId: Uint8Array;
  readonly authorIdentityId: Uint8Array;
  readonly kind: RecordKind;
  readonly sentAt: bigint;
  readonly receivedAt: bigint;
  readonly plaintext: Uint8Array;
  readonly superseded: boolean;
  readonly own: boolean;
}

/**
 * A history query. Every filter is served from the index: an author, a kind, a `sentAt` window
 * (`since` inclusive, `before` exclusive), the order and a page size. `cursor` continues a page
 * from `HistoryPage.cursor`; it names a fixed position in time order, so pages stay stable while
 * records arrive or expire.
 */
export interface HistoryQuery {
  readonly authorIdentityId?: Uint8Array;
  readonly kind?: RecordKind;
  readonly since?: bigint;
  readonly before?: bigint;
  /** At most this many entries; 1000 when absent. */
  readonly limit?: number;
  /** Oldest first by default; `"desc"` reads newest first. */
  readonly order?: "asc" | "desc";
  readonly cursor?: string;
}

export interface HistoryPage {
  readonly entries: HistoryEntry[];
  /** Present when the page was full: pass it back as `cursor` for the next page. */
  readonly cursor: string | undefined;
}

export const HISTORY_PAGE = 1000;

function toEntry(r: HistoryRow): HistoryEntry {
  return {
    recordId: fromHex(r.recordId),
    authorIdentityId: fromHex(r.authorIdentityId),
    kind: r.kind,
    sentAt: unbig(r.sentAt),
    receivedAt: unbig(r.receivedAt),
    plaintext: fromHex(r.plaintext),
    superseded: r.superseded,
    own: r.own
  };
}

/** One page of history in time order, read through the index: one bounded scan per kind, merged. */
export async function historyPage(store: Store, q: HistoryQuery = {}): Promise<HistoryPage> {
  const limit = Math.max(0, Math.floor(q.limit ?? HISTORY_PAGE));
  const reverse = q.order === "desc";
  const kinds = q.kind === undefined ? HISTORY_KINDS : HISTORY_KINDS.includes(q.kind) ? [q.kind] : [];
  if (limit === 0 || kinds.length === 0) return { entries: [], cursor: undefined };
  return store.read((tx) => {
    const scans = kinds.map((kind) => {
      const prefix = q.authorIdentityId ? authorPrefix(toHex(q.authorIdentityId), kind) : timelinePrefix(kind);
      // Bounds in tuple space, prefixed into key space: the lower end from `since` and an
      // ascending cursor, the upper end from `before` and a descending cursor, the tighter winning.
      const upper = [q.before === undefined ? undefined : padTime(q.before), reverse ? q.cursor : undefined].filter((b): b is string => b !== undefined).sort()[0];
      const range: KeyRange = {
        prefix,
        ...(q.since === undefined ? {} : { gte: prefix + padTime(q.since) }),
        ...(!reverse && q.cursor !== undefined ? { gt: prefix + q.cursor } : {}),
        ...(upper === undefined ? {} : { lt: prefix + upper }),
        reverse,
        limit
      };
      return tx.range("historyIndex", range).map(([key, r]) => ({ tuple: key.slice(prefix.length), recordId: r.recordId }));
    });
    const merged = mergeByTuple(scans, reverse, limit);
    const entries: HistoryEntry[] = [];
    for (const m of merged) {
      const row = tx.get("history", m.recordId);
      if (row) entries.push(toEntry(row));
    }
    return { entries, cursor: merged.length === limit ? merged[merged.length - 1]?.tuple : undefined };
  });
}

/** The first page only, for callers that want a plain list. */
export async function history(store: Store, q: HistoryQuery = {}): Promise<HistoryEntry[]> {
  return (await historyPage(store, q)).entries;
}

/** The newest history entry matching the filters, read as a one-entry descending page. */
export async function newest(store: Store, q: Pick<HistoryQuery, "authorIdentityId" | "kind"> = {}): Promise<HistoryEntry | undefined> {
  return (await historyPage(store, { ...q, order: "desc", limit: 1 })).entries[0];
}

interface IndexHit {
  readonly tuple: string;
  readonly recordId: string;
}

/** Merge per-kind scans that are each in order into one ordered list of at most `limit`. */
function mergeByTuple(scans: IndexHit[][], reverse: boolean, limit: number): IndexHit[] {
  const heads = scans.map(() => 0);
  const out: IndexHit[] = [];
  while (out.length < limit) {
    let pick: { i: number; hit: IndexHit } | undefined;
    for (let i = 0; i < scans.length; i++) {
      const hit = scans[i]?.[heads[i] ?? 0];
      if (!hit) continue;
      if (!pick || (reverse ? hit.tuple > pick.hit.tuple : hit.tuple < pick.hit.tuple)) pick = { i, hit };
    }
    if (!pick) break;
    out.push(pick.hit);
    heads[pick.i] = (heads[pick.i] ?? 0) + 1;
  }
  return out;
}

export interface Latest {
  readonly recordId: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly sentAt: bigint;
  readonly ageMs: bigint;
}

/** The live pin: the newest verified location from the author's current device, with its age. */
export async function latest(store: Store, authorIdentityId: Uint8Array, now: bigint): Promise<Latest | undefined> {
  return store.read((tx) => {
    const pin = tx.get("livePins", toHex(authorIdentityId));
    if (!pin) return undefined;
    const row = tx.get("history", pin.recordId);
    if (!row) return undefined;
    return { recordId: fromHex(row.recordId), plaintext: fromHex(row.plaintext), sentAt: unbig(row.sentAt), ageMs: now - unbig(row.sentAt) };
  });
}

export interface LatestStatus {
  readonly recordId: Uint8Array;
  readonly payload: Uint8Array;
  readonly sentAt: bigint;
  readonly ageMs: bigint;
}

/** The author's newest status (kind 2), with its age. */
export async function latestStatus(store: Store, authorIdentityId: Uint8Array, now: bigint): Promise<LatestStatus | undefined> {
  return store.read((tx) => {
    const row = tx.get("statuses", toHex(authorIdentityId));
    if (!row || row.payload === null) return undefined; // none, or expired: the slot stays, the payload is gone
    return { recordId: fromHex(row.recordId), payload: fromHex(row.payload), sentAt: unbig(row.sentAt), ageMs: now - unbig(row.sentAt) };
  });
}

/**
 * Retention: drop history outside the windows; a pin whose record is gone disappears with it. A
 * status expires with the location window: its payload is dropped while the row keeps its slot,
 * so an older status replayed later cannot become current.
 */
export async function purgeHistory(store: Store, policy: RetentionPolicy, now: bigint): Promise<number> {
  const window = (kind: RecordKind): bigint => (kind === 1 ? policy.checkInHistoryMs : policy.locationHistoryMs);
  const staleStatus = (r: StatusRow): boolean => r.payload !== null && unbig(r.sentAt) + window(2) <= now;
  // The expired prefix of each kind's timeline: `sentAt + window <= now`, as a key bound.
  const expiredRange = (kind: RecordKind, limit?: number): KeyRange | undefined => {
    const cutoff = now - window(kind) + 1n;
    return cutoff <= 0n ? undefined : { prefix: timelinePrefix(kind), lt: timelinePrefix(kind) + padTime(cutoff), ...(limit === undefined ? {} : { limit }) };
  };
  const expired = (tx: Pick<Tx, "range">, limit?: number) => HISTORY_KINDS.flatMap((kind) => {
    const r = expiredRange(kind, limit);
    return r ? tx.range("historyIndex", r) : [];
  });
  // Read first: most syncs purge nothing and must not take the writer lock for it.
  const any = await store.read((tx) => expired(tx, 1).length > 0 || tx.list("statuses").some(([, r]) => staleStatus(r)));
  if (!any) return 0;
  return store.transaction((tx) => {
    let removed = 0;
    for (const [key, hit] of expired(tx)) {
      const row = tx.get("history", hit.recordId);
      if (!row) {
        tx.delete("historyIndex", key);
        continue;
      }
      unindexHistory(tx, row);
      tx.delete("history", hit.recordId);
      removed++;
      const pin = tx.get("livePins", row.authorIdentityId);
      if (pin?.recordId === hit.recordId) tx.delete("livePins", row.authorIdentityId);
    }
    for (const [key, r] of tx.list("statuses")) {
      if (staleStatus(r)) {
        tx.put("statuses", key, { ...r, payload: null });
        removed++;
      }
    }
    return removed;
  });
}

/** Clear a removed author's live pin and keys; history already received stays. */
export async function forgetAuthor(store: Store, authorIdentityId: Uint8Array): Promise<void> {
  await store.transaction((tx) => forgetAuthorIn(tx, authorIdentityId));
}

/** The same, inside a caller's transaction. */
export function forgetAuthorIn(tx: Tx, authorIdentityId: Uint8Array): void {
  tx.delete("livePins", toHex(authorIdentityId));
  tx.delete("statuses", toHex(authorIdentityId));
  for (const [, c] of tx.list("certificates")) {
    if (c.identityId !== toHex(authorIdentityId)) continue;
    for (const [k] of tx.list("readerEpochs", c.streamId + ":")) tx.delete("readerEpochs", k);
  }
}
