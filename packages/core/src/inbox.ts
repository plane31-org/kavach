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
import { compareSlots, openRecordWire } from "./record.js";
import { big, unbig } from "./rows.js";
import type { HistoryRow, LivePinRow, Store, SubscriptionRow, Tx } from "./store.js";
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
  const existing = tx.get("history", id);
  if (existing) {
    if (existing.bodyHash === hash) return { result: "duplicate", recordId: opened.recordId };
    deps.events?.securityError?.("EQUIVOCATION", "a different valid body for a retained record id");
    return { result: "invalid", reason: "EQUIVOCATION" };
  }
  const cert = [...author.view.certificates.values()].find((c) => equalBytes(c.streamId, parsed.streamId));
  const generation = unbig(tx.list("certificates").find(([, c]) => c.streamId === toHex(parsed.streamId))?.[1].generation ?? "0");
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
  const base = { recordId: opened.recordId, authorIdentityId: author.identityId, kind: parsed.kind };
  return moved || parsed.kind === 1 ? { result: "updated", ...base } : { result: "history", ...base };
}

/** A record pushed by the host outside `sync`: stored, but it never advances a relay cursor. */
export async function receive(deps: InboxDeps, wire: Uint8Array): Promise<ReceiveResult> {
  const now = deps.now();
  let r = await deps.store.transaction((tx) => storeRecord(tx, deps, wire, now));
  if (r.result === "keyPending" && (await fetchEpochKey(deps, r.streamId, r.epoch).catch(() => false))) {
    r = await deps.store.transaction((tx) => storeRecord(tx, deps, wire, now));
  }
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
  let page;
  try {
    page = await deps.relay.readRecords(streamId, from, READ_BATCH);
  } catch {
    return summary;
  }
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

export interface HistoryQuery {
  readonly authorIdentityId?: Uint8Array;
  readonly kind?: RecordKind;
  readonly since?: bigint;
  readonly limit?: number;
}

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

export async function history(store: Store, q: HistoryQuery = {}): Promise<HistoryEntry[]> {
  return store.read((tx) =>
    tx
      .list("history")
      .map(([, r]) => r)
      .filter((r) => (q.authorIdentityId ? r.authorIdentityId === toHex(q.authorIdentityId) : true))
      .filter((r) => (q.kind === undefined ? true : r.kind === q.kind))
      .filter((r) => (q.since === undefined ? true : unbig(r.sentAt) >= q.since))
      .sort((a, b) => (unbig(a.sentAt) < unbig(b.sentAt) ? -1 : unbig(a.sentAt) > unbig(b.sentAt) ? 1 : a.epoch - b.epoch || a.counter - b.counter))
      .slice(0, q.limit ?? 1000)
      .map(toEntry)
  );
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

/** Retention: drop history outside the windows; a pin whose record is gone disappears with it. */
export async function purgeHistory(store: Store, policy: RetentionPolicy, now: bigint): Promise<number> {
  const expired = (kind: 0 | 1, sentAt: string): boolean => unbig(sentAt) + (kind === 0 ? policy.locationHistoryMs : policy.checkInHistoryMs) <= now;
  // Read first: most syncs purge nothing and must not take the writer lock for it.
  const any = await store.read((tx) => tx.list("history").some(([, r]) => expired(r.kind, r.sentAt)));
  if (!any) return 0;
  return store.transaction((tx) => {
    let removed = 0;
    for (const [key, r] of tx.list("history")) {
      if (expired(r.kind, r.sentAt)) {
        tx.delete("history", key);
        removed++;
        for (const [pk, pin] of tx.list("livePins")) if (pin.recordId === key) tx.delete("livePins", pk);
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
  for (const [, c] of tx.list("certificates")) {
    if (c.identityId !== toHex(authorIdentityId)) continue;
    for (const [k] of tx.list("readerEpochs", c.streamId + ":")) tx.delete("readerEpochs", k);
  }
}
