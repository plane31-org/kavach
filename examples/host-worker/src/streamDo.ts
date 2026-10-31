/**
 * One Durable Object per author stream: the cumulative-cursor relay of protocol section 10.
 *
 * Retained records by delivery sequence with their acceptance time; one subscription per reader
 * device with its cursor; the expiry watermark; the per-stream high-water pair and last-append
 * outcome; the epoch material while it is current or referenced. Deletion runs in the same
 * transaction as the cursor advance; the expiry prefix advances on the alarm. The object's
 * single-threaded SQLite transaction is the serialisation the protocol requires.
 */
import { DurableObject } from "cloudflare:workers";
import { DocumentType, bodyHash, expectType, fromHex, parseDocument, toHex, type EncryptedRecord, type EpochManifest } from "@kavach/core";
import type { Env } from "./env.js";

interface OpenBody {
  streamId: string;
  authorIdentityId: string;
  accountName: string;
}
interface PublishBody {
  callerIdentityId: string;
  expectedEpoch: number;
  manifest: string;
  wraps: Record<string, string>;
}
interface AppendBody {
  callerIdentityId: string;
  recordId: string;
  wire: string;
  now: string;
}
interface ReadBody {
  callerCertificate: string;
  afterSeq: string;
  limit: number;
}
interface AckBody {
  callerCertificate: string;
  cursor: string;
}

export class StreamDO extends DurableObject<Env> {
  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
  }

  private init(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS epochs (epoch INTEGER PRIMARY KEY, manifest TEXT NOT NULL, wraps TEXT NOT NULL, rows TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS records (seq INTEGER PRIMARY KEY, record_id TEXT NOT NULL, wire TEXT NOT NULL, accepted_at TEXT NOT NULL, epoch INTEGER NOT NULL, counter INTEGER NOT NULL, kind INTEGER NOT NULL, required TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS records_id ON records (record_id);
      CREATE TABLE IF NOT EXISTS subs (cert TEXT PRIMARY KEY, identity TEXT NOT NULL, cursor INTEGER NOT NULL, start_seq INTEGER NOT NULL);
    `);
  }

  private get(key: string): string | undefined {
    const row = this.sql.exec("SELECT value FROM meta WHERE key = ?", key).toArray()[0];
    return row ? String(row["value"]) : undefined;
  }
  private set(key: string, value: string | number | bigint): void {
    this.sql.exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", key, String(value));
  }
  private num(key: string, fallback = 0): number {
    const v = this.get(key);
    return v === undefined ? fallback : Number(v);
  }

  override async fetch(request: Request): Promise<Response> {
    this.init();
    const url = new URL(request.url);
    const reply = (b: unknown, status = 200): Response => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    try {
      switch (url.pathname) {
        case "/open": {
          const b = (await request.json()) as OpenBody;
          if (this.get("streamId") === undefined) {
            this.set("streamId", b.streamId);
            this.set("authorIdentityId", b.authorIdentityId);
            this.set("accountName", b.accountName);
            this.set("currentEpoch", 0);
            this.set("tail", 0);
            this.set("expiredThrough", 0);
            this.set("lastAcceptedAt", 0);
          }
          return reply({ ok: true });
        }
        case "/currentEpoch": {
          const e = this.num("currentEpoch");
          return reply(e === 0 ? null : { epoch: e, manifestHash: this.get("currentManifestHash") });
        }
        case "/epoch": {
          const { epoch, callerIdentityId } = (await request.json()) as { epoch: number; callerIdentityId: string };
          const row = this.sql.exec("SELECT manifest, wraps FROM epochs WHERE epoch = ?", epoch).toArray()[0] as { manifest: string; wraps: string } | undefined;
          if (!row) return reply(null);
          const wraps = JSON.parse(row.wraps) as Record<string, string>;
          return reply({ manifest: row.manifest, wrap: wraps[callerIdentityId] ?? null });
        }
        case "/publishEpoch":
          return reply(this.publish((await request.json()) as PublishBody));
        case "/append":
          return reply(this.append((await request.json()) as AppendBody));
        case "/read":
          return reply(this.read((await request.json()) as ReadBody));
        case "/ack":
          return reply(this.ack((await request.json()) as AckBody));
        case "/expire": {
          const { now } = (await request.json()) as { now: string };
          this.expire(BigInt(now));
          return reply({ ok: true });
        }
        case "/debug":
          return reply(this.debug());
        default:
          return reply({ error: "not found" }, 404);
      }
    } catch (e) {
      return reply({ error: "STORAGE_FAILURE", message: e instanceof Error ? e.message : String(e) }, 500);
    }
  }

  private publish(b: PublishBody): { status: string; currentEpoch?: number; currentManifest?: string; newSubscriptions?: { certificateHash: string; identityId: string }[] } {
    if (this.get("authorIdentityId") !== b.callerIdentityId) return { status: "UNAUTHORIZED" };
    const manifest = fromHex(b.manifest);
    const doc = expectType<EpochManifest>(parseDocument(manifest), DocumentType.EpochManifest);
    const current = this.num("currentEpoch");
    const currentRow = this.sql.exec("SELECT manifest FROM epochs WHERE epoch = ?", current).toArray()[0] as { manifest: string } | undefined;
    if (doc.epoch === current && currentRow?.manifest === b.manifest) return { status: "ALREADY_COMMITTED" };
    if (b.expectedEpoch !== current || doc.epoch !== current + 1) return { status: "CONFLICT", currentEpoch: current, ...(currentRow ? { currentManifest: currentRow.manifest } : {}) };
    const rows = doc.audience.map((r) => ({ identityId: toHex(r.identityId), certificateHash: toHex(r.certificateHash) }));
    const tail = this.num("tail");
    const created: { certificateHash: string; identityId: string }[] = [];
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO epochs (epoch, manifest, wraps, rows) VALUES (?, ?, ?, ?)", doc.epoch, b.manifest, JSON.stringify(b.wraps), JSON.stringify(rows));
      this.set("currentEpoch", doc.epoch);
      this.set("currentManifestHash", toHex(doc.bodyHash));
      for (const r of rows) {
        if (r.identityId === b.callerIdentityId) continue;
        const exists = this.sql.exec("SELECT 1 FROM subs WHERE cert = ?", r.certificateHash).toArray().length > 0;
        if (!exists) {
          this.sql.exec("INSERT INTO subs (cert, identity, cursor, start_seq) VALUES (?, ?, ?, ?)", r.certificateHash, r.identityId, tail, tail);
          created.push(r);
        }
      }
      this.purgeEpochs();
    });
    return { status: "COMMITTED", newSubscriptions: created };
  }

  private purgeEpochs(): void {
    const current = this.num("currentEpoch");
    this.sql.exec("DELETE FROM epochs WHERE epoch != ? AND epoch NOT IN (SELECT DISTINCT epoch FROM records)", current);
  }

  private append(b: AppendBody): { status: string; deliverySeq?: string; notify?: { identityId: string; kind: string }[] } {
    if (this.get("authorIdentityId") !== b.callerIdentityId) return { status: "UNAUTHORIZED" };
    const wire = fromHex(b.wire);
    const rec = expectType<EncryptedRecord>(parseDocument(wire), DocumentType.EncryptedRecord);
    if (toHex(rec.streamId) !== this.get("streamId")) return { status: "UNAUTHORIZED" };
    // Idempotent by record id and exact bytes: the checkpoint keeps a digest of the whole wire.
    const hash = toHex(bodyHash(wire));
    const now = BigInt(b.now);
    const last = this.get("lastAppend");
    if (last) {
      const l = JSON.parse(last) as { recordId: string; hash: string; seq: number; at: string };
      if (l.recordId === b.recordId) {
        if (l.hash !== hash) return { status: "EQUIVOCATION" };
        if (BigInt(l.at) + BigInt(this.env.APPEND_RETRY_WINDOW_MS) > now) return { status: "ALREADY_ACCEPTED", deliverySeq: String(l.seq) };
      }
    }
    const retained = this.sql.exec("SELECT wire FROM records WHERE record_id = ?", b.recordId).toArray()[0] as { wire: string } | undefined;
    if (retained) return retained.wire === b.wire ? { status: "ALREADY_ACCEPTED" } : { status: "EQUIVOCATION" };
    const hwEpoch = this.get("hwEpoch");
    if (hwEpoch !== undefined) {
      const he = Number(hwEpoch);
      const hc = this.num("hwCounter");
      if (rec.epoch < he || (rec.epoch === he && rec.counter <= hc)) return { status: "STALE_APPEND" };
    }
    const current = this.num("currentEpoch");
    if (rec.epoch !== current) return rec.epoch < current ? { status: "EPOCH_FENCED" } : { status: "UNAUTHORIZED" };
    const epoch = this.sql.exec("SELECT rows FROM epochs WHERE epoch = ?", rec.epoch).toArray()[0] as { rows: string } | undefined;
    if (!epoch) return { status: "UNAUTHORIZED" };
    const rows = JSON.parse(epoch.rows) as { identityId: string; certificateHash: string }[];
    const required = rows.filter((r) => r.identityId !== b.callerIdentityId).map((r) => r.certificateHash);
    const seq = this.num("tail") + 1;
    const lastAccepted = BigInt(this.get("lastAcceptedAt") ?? "0");
    const acceptedAt = now > lastAccepted ? now : lastAccepted;
    this.ctx.storage.transactionSync(() => {
      this.set("tail", seq);
      this.set("lastAcceptedAt", acceptedAt);
      this.set("hwEpoch", rec.epoch);
      this.set("hwCounter", rec.counter);
      this.set("lastAppend", JSON.stringify({ recordId: b.recordId, hash, seq, at: acceptedAt.toString() }));
      if (required.length > 0) {
        this.sql.exec("INSERT INTO records (seq, record_id, wire, accepted_at, epoch, counter, kind, required) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", seq, b.recordId, b.wire, acceptedAt.toString(), rec.epoch, rec.counter, rec.kind, JSON.stringify(required));
      }
    });
    void this.ctx.storage.setAlarm(Number(acceptedAt + BigInt(this.env.DELIVERY_WINDOW_MS)));
    const notify = rows.filter((r) => r.identityId !== b.callerIdentityId).map((r) => ({ identityId: r.identityId, kind: rec.kind === 1 ? "checkIn" : "wake" }));
    return { status: "ACCEPTED", deliverySeq: String(seq), notify };
  }

  private read(b: ReadBody): { error?: string; records: { deliverySeq: string; wire: string }[]; nextSeq: string; tail: string; expiredThrough: string; committedCursor: string } {
    const tail = this.num("tail");
    const expiredThrough = this.num("expiredThrough");
    const afterSeq = Number(b.afterSeq);
    const empty = { records: [], nextSeq: String(afterSeq), tail: String(tail), expiredThrough: String(expiredThrough), committedCursor: "0" };
    if (afterSeq > tail) return { error: "CURSOR_OUT_OF_RANGE", ...empty };
    const sub = this.sql.exec("SELECT cursor FROM subs WHERE cert = ?", b.callerCertificate).toArray()[0] as { cursor: number } | undefined;
    if (!sub) return { ...empty, nextSeq: String(tail) };
    const scan = Math.max(afterSeq, sub.cursor, expiredThrough);
    const limit = Math.max(1, Math.min(b.limit, 500));
    const records: { deliverySeq: string; wire: string }[] = [];
    let next = scan;
    const rows = this.sql.exec("SELECT seq, wire, required FROM records WHERE seq > ? ORDER BY seq", scan).toArray() as { seq: number; wire: string; required: string }[];
    let stopped = false;
    for (const r of rows) {
      const required = JSON.parse(r.required) as string[];
      if (required.includes(b.callerCertificate)) {
        if (records.length >= limit) {
          stopped = true;
          break;
        }
        records.push({ deliverySeq: String(r.seq), wire: r.wire });
      }
      next = r.seq;
    }
    if (!stopped) next = tail;
    return { records, nextSeq: String(next), tail: String(tail), expiredThrough: String(expiredThrough), committedCursor: String(sub.cursor) };
  }

  private ack(b: AckBody): { status: string; committedCursor?: string } {
    const tail = this.num("tail");
    const cursor = Number(b.cursor);
    const sub = this.sql.exec("SELECT cursor FROM subs WHERE cert = ?", b.callerCertificate).toArray()[0] as { cursor: number } | undefined;
    if (!sub) return { status: "UNAUTHORIZED" };
    if (cursor > tail) return { status: "CURSOR_OUT_OF_RANGE" };
    if (cursor <= sub.cursor) return { status: "COMMITTED", committedCursor: String(sub.cursor) };
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("UPDATE subs SET cursor = ? WHERE cert = ?", cursor, b.callerCertificate);
      this.collect(cursor);
    });
    return { status: "COMMITTED", committedCursor: String(cursor) };
  }

  /** Delete every record at or below `upTo` whose required readers have all passed it. */
  private collect(upTo: number): void {
    const subs = new Map<string, number>();
    for (const s of this.sql.exec("SELECT cert, cursor FROM subs").toArray() as { cert: string; cursor: number }[]) subs.set(s.cert, s.cursor);
    const rows = this.sql.exec("SELECT seq, required FROM records WHERE seq <= ?", upTo).toArray() as { seq: number; required: string }[];
    for (const r of rows) {
      const required = JSON.parse(r.required) as string[];
      if (required.every((c) => (subs.get(c) ?? -1) >= r.seq)) this.sql.exec("DELETE FROM records WHERE seq = ?", r.seq);
    }
    this.purgeEpochs();
  }

  /** The expiry alarm: delete the expired prefix and advance the watermark. */
  private expire(now: bigint): void {
    const window = BigInt(this.env.DELIVERY_WINDOW_MS);
    this.ctx.storage.transactionSync(() => {
      const rows = this.sql.exec("SELECT seq, accepted_at FROM records ORDER BY seq").toArray() as { seq: number; accepted_at: string }[];
      let oldestRetained: number | undefined;
      for (const r of rows) {
        if (BigInt(r.accepted_at) + window <= now) this.sql.exec("DELETE FROM records WHERE seq = ?", r.seq);
        else oldestRetained ??= r.seq;
      }
      const tail = this.num("tail");
      this.set("expiredThrough", oldestRetained === undefined ? tail : oldestRetained - 1);
      this.purgeEpochs();
      const next = this.sql.exec("SELECT MIN(CAST(accepted_at AS INTEGER)) AS t FROM records").toArray()[0] as { t: number | null } | undefined;
      if (next?.t) void this.ctx.storage.setAlarm(Number(BigInt(next.t) + window));
    });
  }

  override async alarm(): Promise<void> {
    this.init();
    // Under the test clock, expiry is driven through /expire with X-Test-Now; real time would
    // expire everything the tests accepted in their past.
    if (this.env.ALLOW_TEST_CLOCK === "true") return;
    this.expire(BigInt(Date.now()));
  }

  private debug() {
    return {
      streamId: this.get("streamId"),
      currentEpoch: this.num("currentEpoch"),
      tail: this.num("tail"),
      expiredThrough: this.num("expiredThrough"),
      retained: (this.sql.exec("SELECT seq, record_id, epoch, counter, kind, required FROM records ORDER BY seq").toArray() as { seq: number; record_id: string; epoch: number; counter: number; kind: number; required: string }[]).map((r) => ({ ...r, required: JSON.parse(r.required) as string[] })),
      epochs: (this.sql.exec("SELECT epoch FROM epochs ORDER BY epoch").toArray() as { epoch: number }[]).map((r) => r.epoch),
      subscriptions: this.sql.exec("SELECT cert, identity, cursor, start_seq FROM subs").toArray(),
      highWater: this.get("hwEpoch") === undefined ? null : { epoch: this.num("hwEpoch"), counter: this.num("hwCounter") },
      lastAppend: this.get("lastAppend") ? JSON.parse(this.get("lastAppend") ?? "null") : null
    };
  }
}
