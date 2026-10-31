/**
 * An in-memory host: the directory and the cumulative-cursor relay of protocol sections 6, 10
 * and 13, bound per caller device. It is the behavioural reference for the Worker in
 * examples/host-worker and the test double for the client. Not a production server, and
 * exported under `@kavach/core/testing` only.
 */
import { equalBytes, fromHex, toHex } from "../bytes.js";
import {
  DocumentType,
  buildResetReceipt,
  expectType,
  parseDocument,
  parseVaultHeader,
  verifyDocument,
  type AccountDevice,
  type CircleSnapshot,
  type EncryptedRecord,
  type EpochManifest
} from "../codec.js";
import { bodyHash, identityId, streamId as deriveStreamId, type SigningKeypair } from "../crypto.js";
import type {
  AppendOutcome,
  Directory,
  EpochBundle,
  JoinRequest,
  MutationOutcome,
  ReadRecordsResult,
  Relay,
  ResolvedAccount,
  Transport,
  TransportHint
} from "../transport.js";

interface Account {
  accountName: string;
  accountKey: Uint8Array;
  identityId: string;
  certificate: Uint8Array;
  certificateHash: string;
  generation: bigint;
  deviceIds: Set<string>;
  retiredCertificates: Set<string>;
  vault: { wire: Uint8Array; revision: bigint; hash: string } | undefined;
  retiredIdentity: boolean;
  previousIdentities: Set<string>;
  resetReceipt: Uint8Array | undefined;
}

interface StoredRecord {
  recordId: string;
  wire: Uint8Array;
  acceptedAt: bigint;
  epoch: number;
  counter: number;
  kind: 0 | 1;
  required: Set<string>; // reader certificate hashes
}

interface StreamState {
  authorIdentityId: string;
  accountName: string;
  currentEpoch: number;
  currentManifestHash: string | undefined;
  epochs: Map<number, { manifest: Uint8Array; wraps: Map<string, Uint8Array>; rows: { identityId: string; certificateHash: string }[] }>;
  records: Map<bigint, StoredRecord>;
  tail: bigint;
  expiredThrough: bigint;
  lastAcceptedAt: bigint;
  highWater: { epoch: number; counter: number } | undefined;
  lastAppend: { recordId: string; hash: string; seq: bigint; at: bigint; outcome: AppendOutcome } | undefined;
  subscriptions: Map<string, { identityId: string; cursor: bigint; startSeq: bigint }>;
}

export interface Notification {
  kind: "joinRequest" | "leaveRequest" | "checkIn" | "wake";
  to: string;
  from: string;
  circleId?: string;
}

export class FakeHost {
  now: () => bigint = () => 0n;
  deliveryWindowMs = 86_400_000n;
  appendRetryWindowMs = 604_800_000n;
  readonly accounts = new Map<string, Account>();
  readonly certificates = new Map<string, Uint8Array>();
  readonly circles = new Map<string, { snapshot: Uint8Array; revision: bigint; hash: string; ownerIdentityId: string; closed: boolean }>();
  readonly requests = new Map<string, JoinRequest[]>();
  readonly streams = new Map<string, StreamState>();
  readonly notifications: Notification[] = [];
  readonly receipts = new Map<string, Uint8Array>();
  resetKeyList: Uint8Array | undefined;
  resetSigner: { key: SigningKeypair; keyId: Uint8Array } | undefined;
  private readonly observers = new Set<(hint: TransportHint) => void>();
  /** Test switches. */
  failAppends = false;
  dropAppendResponses = false;
  withholdSnapshots = false;
  withholdEpochs = false;
  appendCalls = 0;
  /** Every append the relay answered, in order: what the author's stream has been asked to accept. */
  readonly appendLog: { streamId: string; recordId: string; hash: string; status: AppendOutcome["status"]; epoch: number; counter: number }[] = [];

  // Helpers ---------------------------------------------------------------------------------------

  accountByIdentity(iid: string): Account | undefined {
    return [...this.accounts.values()].find((a) => a.identityId === iid);
  }

  private hint(h: TransportHint): void {
    for (const o of this.observers) o(h);
  }

  private stream(streamHex: string, authorIdentityId: string, accountName: string): StreamState {
    let s = this.streams.get(streamHex);
    if (!s) {
      s = {
        authorIdentityId,
        accountName,
        currentEpoch: 0,
        currentManifestHash: undefined,
        epochs: new Map(),
        records: new Map(),
        tail: 0n,
        expiredThrough: 0n,
        lastAcceptedAt: 0n,
        highWater: undefined,
        lastAppend: undefined,
        subscriptions: new Map()
      };
      this.streams.set(streamHex, s);
    }
    return s;
  }

  /** The expiry alarm: delete the expired prefix and advance the watermark. */
  expire(): void {
    const now = this.now();
    for (const s of this.streams.values()) {
      for (const [seq, r] of [...s.records]) if (r.acceptedAt + this.deliveryWindowMs <= now) s.records.delete(seq);
      const retained = [...s.records.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      s.expiredThrough = retained.length ? (retained[0] ?? 0n) - 1n : s.tail;
      this.purgeEpochs(s);
    }
  }

  private purgeEpochs(s: StreamState): void {
    const referenced = new Set([...s.records.values()].map((r) => r.epoch));
    for (const e of [...s.epochs.keys()]) if (e !== s.currentEpoch && !referenced.has(e)) s.epochs.delete(e);
  }

  private collect(s: StreamState, upTo: bigint): void {
    for (const [seq, r] of [...s.records]) {
      if (seq > upTo) continue;
      let done = true;
      for (const cert of r.required) {
        const sub = s.subscriptions.get(cert);
        if (!sub || sub.cursor < seq) {
          done = false;
          break;
        }
      }
      if (done) s.records.delete(seq);
    }
    this.purgeEpochs(s);
  }

  retainedCount(streamId: Uint8Array): number {
    return this.streams.get(toHex(streamId))?.records.size ?? 0;
  }

  // Transport per caller ---------------------------------------------------------------------------

  asDevice(accountName: string, certificateHash: Uint8Array): Transport {
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- the transport closures outlive this call
    const host = this;
    const callerCert = toHex(certificateHash);
    const caller = (): Account => {
      const a = host.accounts.get(accountName);
      if (!a) throw new Error("unknown account");
      return a;
    };
    const current = (): boolean => caller().certificateHash === callerCert;

    const directory: Directory = {
      async resolveAccounts(names): Promise<ResolvedAccount[]> {
        return names.flatMap((n) => {
          const a = host.accounts.get(n);
          if (!a) return [];
          const r: ResolvedAccount = { accountName: n, accountKey: a.accountKey, certificate: a.certificate };
          return [a.resetReceipt ? { ...r, resetReceipt: a.resetReceipt } : r];
        });
      },
      async resolveIdentities(identityIds): Promise<ResolvedAccount[]> {
        return identityIds.flatMap((iid) => {
          const a = host.accountByIdentity(toHex(iid)) ?? [...host.accounts.values()].find((x) => x.previousIdentities.has(toHex(iid)));
          if (!a) return [];
          const r: ResolvedAccount = { accountName: a.accountName, accountKey: a.accountKey, certificate: a.certificate };
          return [a.resetReceipt ? { ...r, resetReceipt: a.resetReceipt } : r];
        });
      },
      async getCertificate(hash) {
        return host.certificates.get(toHex(hash));
      },
      async registerAccount({ certificate, vault }): Promise<MutationOutcome> {
        const doc = expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice);
        if (host.accounts.has(doc.accountName)) return { status: "CONFLICT" };
        const vh = parseVaultHeader(vault);
        const iid = toHex(identityId(doc.accountName, doc.accountKey));
        host.accounts.set(doc.accountName, {
          accountName: doc.accountName,
          accountKey: doc.accountKey,
          identityId: iid,
          certificate,
          certificateHash: toHex(doc.bodyHash),
          generation: doc.generation,
          deviceIds: new Set([toHex(doc.deviceId)]),
          retiredCertificates: new Set(),
          vault: { wire: vault, revision: vh.vaultRevision, hash: toHex(vh.hash) },
          retiredIdentity: false,
          previousIdentities: new Set(),
          resetReceipt: undefined
        });
        host.certificates.set(toHex(doc.bodyHash), certificate);
        host.stream(toHex(deriveStreamId(fromHex(iid), doc.deviceId)), iid, doc.accountName);
        return { status: "COMMITTED" };
      },
      async activateDevice(input): Promise<MutationOutcome> {
        const a = host.accounts.get(input.accountName);
        if (!a) return { status: "UNAUTHORIZED" };
        const doc = expectType<AccountDevice>(verifyDocument(input.newCertificate), DocumentType.AccountDevice);
        if (toHex(doc.bodyHash) === a.certificateHash) return { status: "ALREADY_COMMITTED" };
        if (a.certificateHash !== toHex(input.expectedCertificateHash)) return { status: "CONFLICT", current: a.certificate };
        if (!a.vault || a.vault.revision !== input.expectedVaultRevision || a.vault.hash !== toHex(input.expectedVaultHash)) return { status: "CONFLICT", current: a.vault?.wire, currentRevision: a.vault?.revision };
        if (!equalBytes(doc.accountKey, a.accountKey) || doc.generation !== a.generation + 1n || a.deviceIds.has(toHex(doc.deviceId))) return { status: "UNAUTHORIZED" };
        const vh = parseVaultHeader(input.newVault);
        a.retiredCertificates.add(a.certificateHash);
        a.certificate = input.newCertificate;
        a.certificateHash = toHex(doc.bodyHash);
        a.generation = doc.generation;
        a.deviceIds.add(toHex(doc.deviceId));
        a.vault = { wire: input.newVault, revision: vh.vaultRevision, hash: toHex(vh.hash) };
        host.certificates.set(a.certificateHash, input.newCertificate);
        host.stream(toHex(deriveStreamId(fromHex(a.identityId), doc.deviceId)), a.identityId, a.accountName);
        host.hint("metadataChanged");
        return { status: "COMMITTED" };
      },
      async getVault(name) {
        return host.accounts.get(name)?.vault?.wire;
      },
      async publishVault({ expectedRevision, expectedHash, newVault }): Promise<MutationOutcome> {
        const a = caller();
        if (!current()) return { status: "UNAUTHORIZED" };
        const vh = parseVaultHeader(newVault);
        if (a.vault && (a.vault.revision !== expectedRevision || (expectedHash && a.vault.hash !== toHex(expectedHash)))) {
          if (a.vault.hash === toHex(vh.hash)) return { status: "ALREADY_COMMITTED" };
          return { status: "CONFLICT", current: a.vault.wire, currentRevision: a.vault.revision };
        }
        if (vh.vaultRevision !== expectedRevision + 1n) return { status: "CONFLICT", current: a.vault?.wire, currentRevision: a.vault?.revision };
        a.vault = { wire: newVault, revision: vh.vaultRevision, hash: toHex(vh.hash) };
        return { status: "COMMITTED" };
      },
      async getCircle(circleId) {
        if (host.withholdSnapshots) return undefined;
        const c = host.circles.get(toHex(circleId));
        return c && !c.closed ? c.snapshot : undefined;
      },
      async publishOwnedCircle({ circleId, expectedRevision, expectedHash, newSnapshot }): Promise<MutationOutcome> {
        const a = caller();
        if (!current()) return { status: "UNAUTHORIZED" };
        const doc = expectType<CircleSnapshot>(verifyDocument(newSnapshot, a.accountKey), DocumentType.CircleSnapshot);
        if (toHex(doc.ownerIdentityId) !== a.identityId || !equalBytes(doc.circleId, circleId)) return { status: "UNAUTHORIZED" };
        const key = toHex(circleId);
        const existing = host.circles.get(key);
        if (existing) {
          if (existing.hash === toHex(doc.bodyHash)) return { status: "ALREADY_COMMITTED" };
          if (existing.revision !== expectedRevision || (expectedHash && existing.hash !== toHex(expectedHash)) || doc.revision !== existing.revision + 1n) {
            return { status: "CONFLICT", current: existing.snapshot, currentRevision: existing.revision };
          }
        } else if (expectedRevision !== 0n || doc.revision !== 1n) return { status: "CONFLICT" };
        host.circles.set(key, { snapshot: newSnapshot, revision: doc.revision, hash: toHex(doc.bodyHash), ownerIdentityId: a.identityId, closed: false });
        // Requests for accounts now admitted are cleared.
        const members = new Set(doc.members.map(toHex));
        host.requests.set(key, (host.requests.get(key) ?? []).filter((r) => !members.has(host.accounts.get(r.accountName)?.identityId ?? "")));
        host.hint("metadataChanged");
        return { status: "COMMITTED" };
      },
      async requestJoin(circleId): Promise<MutationOutcome> {
        const a = caller();
        const c = host.circles.get(toHex(circleId));
        if (!c) return { status: "PERMANENT_FAILURE" };
        const list = (host.requests.get(toHex(circleId)) ?? []).filter((r) => !(r.accountName === a.accountName && r.action === "join"));
        // A repeated request refreshes the pending one; the owner is notified once per live request.
        const hadLive = (host.requests.get(toHex(circleId)) ?? []).some((r) => r.accountName === a.accountName && r.action === "join" && r.requestedAt > host.now() - 7n * 86_400_000n);
        list.push({ circleId, accountName: a.accountName, action: "join", requestedAt: host.now() });
        host.requests.set(toHex(circleId), list);
        if (!hadLive) {
          const owner = host.accountByIdentity(c.ownerIdentityId);
          if (owner) host.notifications.push({ kind: "joinRequest", to: owner.accountName, from: a.accountName, circleId: toHex(circleId) });
        }
        return { status: "COMMITTED" };
      },
      async requestLeave(circleId): Promise<MutationOutcome> {
        const a = caller();
        const c = host.circles.get(toHex(circleId));
        if (!c) return { status: "PERMANENT_FAILURE" };
        const list = host.requests.get(toHex(circleId)) ?? [];
        list.push({ circleId, accountName: a.accountName, action: "leave", requestedAt: host.now() });
        host.requests.set(toHex(circleId), list);
        const owner = host.accountByIdentity(c.ownerIdentityId);
        if (owner) host.notifications.push({ kind: "leaveRequest", to: owner.accountName, from: a.accountName, circleId: toHex(circleId) });
        return { status: "COMMITTED" };
      },
      async readRequests(circleId) {
        const a = caller();
        const c = host.circles.get(toHex(circleId));
        if (!c || c.ownerIdentityId !== a.identityId) return [];
        const cutoff = host.now() - 7n * 86_400_000n;
        return (host.requests.get(toHex(circleId)) ?? []).filter((r) => r.requestedAt > cutoff);
      },
      async getResetKeyList() {
        return host.resetKeyList;
      },
      async getResetReceipt(resetId) {
        return host.receipts.get(toHex(resetId));
      },
      async resetAccount(input) {
        const a = host.accounts.get(input.accountName);
        if (!a || a.identityId !== toHex(input.expectedOldIdentityId) || !host.resetSigner) return { status: "UNAUTHORIZED" as const };
        const existing = host.receipts.get(toHex(input.resetId));
        if (existing) return { status: "ALREADY_COMMITTED" as const, receipt: existing };
        const doc = expectType<AccountDevice>(verifyDocument(input.newCertificate), DocumentType.AccountDevice);
        const newIid = identityId(doc.accountName, doc.accountKey);
        const receipt = buildResetReceipt(
          { accountName: input.accountName, oldIdentityId: input.expectedOldIdentityId, newIdentityId: newIid, resetId: input.resetId, issuedAt: host.now(), authorityKeyId: host.resetSigner.keyId },
          host.resetSigner.key.secretKey
        );
        host.receipts.set(toHex(input.resetId), receipt);
        for (const c of host.circles.values()) if (c.ownerIdentityId === a.identityId) c.closed = true;
        const vh = parseVaultHeader(input.newVault);
        a.previousIdentities.add(a.identityId);
        a.resetReceipt = receipt;
        a.retiredCertificates.add(a.certificateHash);
        a.accountKey = doc.accountKey;
        a.identityId = toHex(newIid);
        a.certificate = input.newCertificate;
        a.certificateHash = toHex(doc.bodyHash);
        a.generation = doc.generation;
        a.deviceIds.add(toHex(doc.deviceId));
        a.vault = { wire: input.newVault, revision: vh.vaultRevision, hash: toHex(vh.hash) };
        host.certificates.set(a.certificateHash, input.newCertificate);
        host.stream(toHex(deriveStreamId(newIid, doc.deviceId)), a.identityId, a.accountName);
        host.hint("metadataChanged");
        return { status: "COMMITTED" as const, receipt };
      }
    };

    const relay: Relay = {
      async getCurrentEpoch(streamId) {
        const s = host.streams.get(toHex(streamId));
        if (!s || s.currentEpoch === 0 || !s.currentManifestHash) return undefined;
        return { epoch: s.currentEpoch, manifestHash: fromHex(s.currentManifestHash) };
      },
      async getEpoch(streamId, epoch): Promise<EpochBundle | undefined> {
        if (host.withholdEpochs) return undefined;
        const s = host.streams.get(toHex(streamId));
        const e = s?.epochs.get(epoch);
        if (!e) return undefined;
        return { manifest: e.manifest, wrap: e.wraps.get(caller().identityId) };
      },
      async publishEpoch({ streamId, expectedEpoch, manifest, wraps }) {
        const a = caller();
        const s = host.streams.get(toHex(streamId));
        if (!s || s.authorIdentityId !== a.identityId) return { status: "UNAUTHORIZED" as const };
        if (!current()) return { status: "UNAUTHORIZED" as const };
        const doc = expectType<EpochManifest>(parseDocument(manifest), DocumentType.EpochManifest);
        const cur = s.epochs.get(s.currentEpoch);
        if (doc.epoch === s.currentEpoch && cur && equalBytes(cur.manifest, manifest)) return { status: "ALREADY_COMMITTED" as const };
        if (expectedEpoch !== s.currentEpoch || doc.epoch !== s.currentEpoch + 1) {
          return { status: "CONFLICT" as const, currentEpoch: s.currentEpoch, currentManifest: cur?.manifest };
        }
        const rows = doc.audience.map((r) => ({ identityId: toHex(r.identityId), certificateHash: toHex(r.certificateHash) }));
        s.epochs.set(doc.epoch, { manifest, wraps: new Map(wraps), rows });
        s.currentEpoch = doc.epoch;
        s.currentManifestHash = toHex(doc.bodyHash);
        for (const r of rows) {
          if (r.identityId === a.identityId) continue;
          if (!s.subscriptions.has(r.certificateHash)) s.subscriptions.set(r.certificateHash, { identityId: r.identityId, cursor: s.tail, startSeq: s.tail });
        }
        host.purgeEpochs(s);
        return { status: "COMMITTED" as const };
      },
      appendRecord(recordId, wire): Promise<AppendOutcome> {
        host.appendCalls++;
        if (host.failAppends) throw new Error("transport down");
        const run = (): AppendOutcome => {
          const a = caller();
          const rec = expectType<EncryptedRecord>(parseDocument(wire), DocumentType.EncryptedRecord);
          const s = host.streams.get(toHex(rec.streamId));
          if (!s || s.authorIdentityId !== a.identityId) return { status: "UNAUTHORIZED" };
          if (!current()) return { status: "SUPERSEDED_DEVICE" };
          const id = toHex(recordId);
          const hash = toHex(bodyHash(wire)); // exact bytes, signature included
          // Checkpoint first, then the epoch fence.
          if (s.lastAppend && s.lastAppend.recordId === id) {
            if (s.lastAppend.hash !== hash) return { status: "EQUIVOCATION" };
            if (s.lastAppend.at + host.appendRetryWindowMs > host.now()) return { status: "ALREADY_ACCEPTED", deliverySeq: s.lastAppend.seq };
          }
          const retained = [...s.records.values()].find((r) => r.recordId === id);
          if (retained) return hash === toHex(bodyHash(retained.wire)) ? { status: "ALREADY_ACCEPTED" } : { status: "EQUIVOCATION" };
          if (s.highWater && (rec.epoch < s.highWater.epoch || (rec.epoch === s.highWater.epoch && rec.counter <= s.highWater.counter))) return { status: "STALE_APPEND" };
          if (rec.epoch !== s.currentEpoch) return rec.epoch < s.currentEpoch ? { status: "EPOCH_FENCED" } : { status: "UNAUTHORIZED" };
          const epoch = s.epochs.get(rec.epoch);
          if (!epoch) return { status: "UNAUTHORIZED" };
          const seq = ++s.tail;
          const acceptedAt = host.now() > s.lastAcceptedAt ? host.now() : s.lastAcceptedAt;
          s.lastAcceptedAt = acceptedAt;
          const required = new Set(epoch.rows.filter((r) => r.identityId !== a.identityId).map((r) => r.certificateHash));
          s.records.set(seq, { recordId: id, wire, acceptedAt, epoch: rec.epoch, counter: rec.counter, kind: rec.kind, required });
          s.highWater = { epoch: rec.epoch, counter: rec.counter };
          const outcome: AppendOutcome = { status: "ACCEPTED", deliverySeq: seq };
          s.lastAppend = { recordId: id, hash, seq, at: acceptedAt, outcome };
          for (const r of epoch.rows) {
            if (r.identityId === a.identityId) continue;
            const to = host.accountByIdentity(r.identityId)?.accountName ?? r.identityId;
            host.notifications.push({ kind: rec.kind === 1 ? "checkIn" : "wake", to, from: a.accountName });
          }
          if (required.size === 0) s.records.delete(seq);
          return outcome;
        };
        const result = run();
        try {
          const rec = expectType<EncryptedRecord>(parseDocument(wire), DocumentType.EncryptedRecord);
          host.appendLog.push({ streamId: toHex(rec.streamId), recordId: toHex(recordId), hash: toHex(bodyHash(wire)), status: result.status, epoch: rec.epoch, counter: rec.counter });
        } catch {
          /* unparsable wires are refused above */
        }
        if (host.dropAppendResponses) return new Promise<AppendOutcome>((_, reject) => reject(new Error("response lost")));
        return Promise.resolve(result);
      },
      async readRecords(streamId, afterSeq, limit): Promise<ReadRecordsResult> {
        const s = host.streams.get(toHex(streamId));
        if (!s) return { records: [], nextSeq: afterSeq, tail: 0n, expiredThrough: 0n, committedCursor: 0n };
        if (afterSeq > s.tail) throw new Error("CURSOR_OUT_OF_RANGE");
        const sub = s.subscriptions.get(callerCert);
        if (!sub) return { records: [], nextSeq: s.tail, tail: s.tail, expiredThrough: s.expiredThrough, committedCursor: 0n };
        let scan = afterSeq;
        if (sub.cursor > scan) scan = sub.cursor;
        if (s.expiredThrough > scan) scan = s.expiredThrough;
        const records: { deliverySeq: bigint; wire: Uint8Array }[] = [];
        let next = scan;
        for (let seq = scan + 1n; seq <= s.tail; seq++) {
          const r = s.records.get(seq);
          if (r && r.required.has(callerCert)) {
            if (records.length >= limit) break;
            records.push({ deliverySeq: seq, wire: r.wire });
          }
          next = seq;
        }
        return { records, nextSeq: next, tail: s.tail, expiredThrough: s.expiredThrough, committedCursor: sub.cursor };
      },
      async ackThrough(streamId, cursor) {
        const s = host.streams.get(toHex(streamId));
        const sub = s?.subscriptions.get(callerCert);
        if (!s || !sub) return { status: "UNAUTHORIZED" as const };
        if (cursor > s.tail) return { status: "CURSOR_OUT_OF_RANGE" as const };
        if (cursor > sub.cursor) {
          sub.cursor = cursor;
          host.collect(s, cursor);
        }
        return { status: "COMMITTED" as const, committedCursor: sub.cursor };
      },
      async listSubscriptions() {
        const out: { streamId: Uint8Array; authorIdentityId: Uint8Array }[] = [];
        for (const [sid, s] of host.streams) if (s.subscriptions.has(callerCert)) out.push({ streamId: fromHex(sid), authorIdentityId: fromHex(s.authorIdentityId) });
        return out;
      }
    };

    return {
      directory,
      relay,
      observe: (handler) => {
        host.observers.add(handler);
        return () => host.observers.delete(handler);
      }
    };
  }
}
