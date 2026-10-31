/**
 * The directory over D1 (protocol sections 4 to 6, 12 and 13): accounts with their current
 * certificate, immutable certificates by hash, vaults and snapshots by compare-and-swap, join
 * and leave requests, reset receipts and the key list. Everything stored is public or opaque.
 */
import {
  DocumentType,
  buildResetReceipt,
  expectType,
  identityId,
  parseVaultHeader,
  signingKeypairFromSeed,
  streamId,
  verifyDocument,
  type AccountDevice,
  type CircleSnapshot
} from "@kavach/core/adapters";
import type { Env } from "./env.js";
import { HttpError, hex, unhex, type Caller } from "./wire.js";

export interface AccountRow {
  account_name: string;
  account_key: string;
  identity_id: string;
  certificate: string;
  certificate_hash: string;
  generation: string;
  vault: string | null;
  vault_revision: string | null;
  vault_hash: string | null;
  reset_receipt: string | null;
}

type Outcome = { status: string; current?: string; currentRevision?: string; receipt?: string };
interface Resolved {
  accountName: string;
  accountKey: string;
  certificate: string;
  resetReceipt?: string;
}
interface RequestView {
  circleId: string;
  accountName: string;
  action: string;
  requestedAt: string;
}
interface SubscriptionView {
  streamId: string;
  authorIdentityId: string;
}

export class Directory {
  constructor(
    private readonly env: Env,
    private readonly now: bigint
  ) {}

  private get db(): D1Database {
    return this.env.DIRECTORY;
  }

  async account(name: string): Promise<AccountRow | null> {
    return this.db.prepare("SELECT * FROM accounts WHERE account_name = ?").bind(name).first<AccountRow>();
  }

  async accountByIdentity(iid: string): Promise<AccountRow | null> {
    const name = await this.db.prepare("SELECT account_name FROM identities WHERE identity_id = ?").bind(iid).first<{ account_name: string }>();
    return name ? this.account(name.account_name) : null;
  }

  /** The caller must be the account's current device for every write. */
  async currentDevice(c: Caller): Promise<AccountRow> {
    const a = await this.account(c.accountName);
    if (!a) throw new HttpError(401, "UNAUTHORIZED", "unknown account");
    if (a.certificate_hash !== c.certificateHash) throw new HttpError(403, "SUPERSEDED_DEVICE");
    return a;
  }

  resolved(a: AccountRow): Resolved {
    return { accountName: a.account_name, accountKey: a.account_key, certificate: a.certificate, ...(a.reset_receipt ? { resetReceipt: a.reset_receipt } : {}) };
  }

  async resolveAccounts(names: string[]): Promise<Resolved[]> {
    const out: Resolved[] = [];
    for (const n of names) {
      const a = await this.account(n);
      if (a) out.push(this.resolved(a));
    }
    return out;
  }

  async resolveIdentities(ids: string[]): Promise<Resolved[]> {
    const out: Resolved[] = [];
    for (const iid of ids) {
      const a = await this.accountByIdentity(iid);
      if (a) out.push(this.resolved(a));
    }
    return out;
  }

  async certificate(hash: string): Promise<string | null> {
    const r = await this.db.prepare("SELECT wire FROM certificates WHERE certificate_hash = ?").bind(hash).first<{ wire: string }>();
    return r?.wire ?? null;
  }

  async register(certificateHex: string, vaultHex: string): Promise<Outcome> {
    const certificate = unhex(certificateHex, "certificate");
    const doc = expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice);
    const taken = await this.account(doc.accountName);
    // The same certificate again is an enrollment resuming after a lost response, not a conflict.
    if (taken) return taken.certificate === certificateHex ? { status: "ALREADY_COMMITTED" } : { status: "CONFLICT" };
    const vh = parseVaultHeader(unhex(vaultHex, "vault"));
    const iid = hex(identityId(doc.accountName, doc.accountKey));
    const certHash = hex(doc.bodyHash);
    await this.db.batch([
      this.db
        .prepare("INSERT INTO accounts (account_name, account_key, identity_id, certificate, certificate_hash, generation, vault, vault_revision, vault_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(doc.accountName, hex(doc.accountKey), iid, certificateHex, certHash, doc.generation.toString(), vaultHex, vh.vaultRevision.toString(), hex(vh.hash)),
      this.db.prepare("INSERT INTO identities (identity_id, account_name) VALUES (?, ?)").bind(iid, doc.accountName),
      this.db.prepare("INSERT INTO certificates (certificate_hash, account_name, wire, current) VALUES (?, ?, ?, 1)").bind(certHash, doc.accountName, certificateHex),
      this.db.prepare("INSERT INTO device_ids (account_name, device_id) VALUES (?, ?)").bind(doc.accountName, hex(doc.deviceId))
    ]);
    await this.openStream(iid, doc.deviceId, doc.accountName);
    return { status: "COMMITTED" };
  }

  private async openStream(iid: string, deviceId: Uint8Array, accountName: string): Promise<void> {
    const sid = hex(streamId(unhex(iid, "identity"), deviceId));
    const stub = this.env.STREAMS.get(this.env.STREAMS.idFromName(sid));
    await stub.fetch("https://stream/open", { method: "POST", body: JSON.stringify({ streamId: sid, authorIdentityId: iid, accountName }) });
  }

  async activate(input: { accountName: string; expectedCertificateHash: string; expectedVaultRevision: string; expectedVaultHash: string; newCertificate: string; newVault: string }): Promise<Outcome> {
    const a = await this.account(input.accountName);
    if (!a) return { status: "UNAUTHORIZED" };
    const doc = expectType<AccountDevice>(verifyDocument(unhex(input.newCertificate, "newCertificate")), DocumentType.AccountDevice);
    const newHash = hex(doc.bodyHash);
    if (newHash === a.certificate_hash) return { status: "ALREADY_COMMITTED" };
    if (a.certificate_hash !== input.expectedCertificateHash) return { status: "CONFLICT", current: a.certificate };
    if (a.vault_revision !== input.expectedVaultRevision || a.vault_hash !== input.expectedVaultHash) return { status: "CONFLICT", ...(a.vault ? { current: a.vault } : {}), ...(a.vault_revision ? { currentRevision: a.vault_revision } : {}) };
    if (hex(doc.accountKey) !== a.account_key || doc.generation !== BigInt(a.generation) + 1n) return { status: "UNAUTHORIZED" };
    const used = await this.db.prepare("SELECT 1 FROM device_ids WHERE account_name = ? AND device_id = ?").bind(a.account_name, hex(doc.deviceId)).first();
    if (used) return { status: "UNAUTHORIZED" };
    const vh = parseVaultHeader(unhex(input.newVault, "newVault"));
    // Compare-and-swap in one statement: the update is conditional on the expected hash.
    const result = await this.db.batch([
      this.db
        .prepare("UPDATE accounts SET certificate = ?, certificate_hash = ?, generation = ?, vault = ?, vault_revision = ?, vault_hash = ? WHERE account_name = ? AND certificate_hash = ? AND vault_revision = ?")
        .bind(input.newCertificate, newHash, doc.generation.toString(), input.newVault, vh.vaultRevision.toString(), hex(vh.hash), a.account_name, input.expectedCertificateHash, input.expectedVaultRevision),
      this.db.prepare("UPDATE certificates SET current = 0 WHERE account_name = ?").bind(a.account_name),
      this.db.prepare("INSERT INTO certificates (certificate_hash, account_name, wire, current) VALUES (?, ?, ?, 1)").bind(newHash, a.account_name, input.newCertificate),
      this.db.prepare("INSERT INTO device_ids (account_name, device_id) VALUES (?, ?)").bind(a.account_name, hex(doc.deviceId))
    ]);
    if ((result[0]?.meta.changes ?? 0) !== 1) return { status: "CONFLICT" };
    await this.openStream(a.identity_id, doc.deviceId, a.account_name);
    return { status: "COMMITTED" };
  }

  async vault(name: string): Promise<string | null> {
    return (await this.account(name))?.vault ?? null;
  }

  async publishVault(c: Caller, input: { expectedRevision: string; expectedHash?: string; newVault: string }): Promise<Outcome> {
    const a = await this.currentDevice(c);
    const vh = parseVaultHeader(unhex(input.newVault, "newVault"));
    if (a.vault_hash === hex(vh.hash)) return { status: "ALREADY_COMMITTED" };
    if (a.vault_revision !== input.expectedRevision || (input.expectedHash && a.vault_hash !== input.expectedHash) || vh.vaultRevision !== BigInt(input.expectedRevision) + 1n) {
      return { status: "CONFLICT", ...(a.vault ? { current: a.vault } : {}), ...(a.vault_revision ? { currentRevision: a.vault_revision } : {}) };
    }
    const r = await this.db.prepare("UPDATE accounts SET vault = ?, vault_revision = ?, vault_hash = ? WHERE account_name = ? AND vault_revision = ?").bind(input.newVault, vh.vaultRevision.toString(), hex(vh.hash), a.account_name, input.expectedRevision).run();
    return { status: r.meta.changes === 1 ? "COMMITTED" : "CONFLICT" };
  }

  async circle(id: string): Promise<string | null> {
    const r = await this.db.prepare("SELECT snapshot, closed FROM circles WHERE circle_id = ?").bind(id).first<{ snapshot: string; closed: number }>();
    return r && !r.closed ? r.snapshot : null;
  }

  async publishCircle(c: Caller, input: { circleId: string; expectedRevision: string; expectedHash?: string; newSnapshot: string }): Promise<Outcome> {
    const a = await this.currentDevice(c);
    const snapshot = unhex(input.newSnapshot, "newSnapshot");
    const doc = expectType<CircleSnapshot>(verifyDocument(snapshot, unhex(a.account_key, "key")), DocumentType.CircleSnapshot);
    if (hex(doc.ownerIdentityId) !== a.identity_id || hex(doc.circleId) !== input.circleId) return { status: "UNAUTHORIZED" };
    const existing = await this.db.prepare("SELECT revision, hash, snapshot FROM circles WHERE circle_id = ?").bind(input.circleId).first<{ revision: string; hash: string; snapshot: string }>();
    const newHash = hex(doc.bodyHash);
    if (existing) {
      if (existing.hash === newHash) return { status: "ALREADY_COMMITTED" };
      if (existing.revision !== input.expectedRevision || (input.expectedHash && existing.hash !== input.expectedHash) || doc.revision !== BigInt(existing.revision) + 1n) {
        return { status: "CONFLICT", current: existing.snapshot, currentRevision: existing.revision };
      }
      const r = await this.db.prepare("UPDATE circles SET snapshot = ?, revision = ?, hash = ? WHERE circle_id = ? AND revision = ?").bind(input.newSnapshot, doc.revision.toString(), newHash, input.circleId, input.expectedRevision).run();
      if (r.meta.changes !== 1) return { status: "CONFLICT" };
    } else {
      if (input.expectedRevision !== "0" || doc.revision !== 1n) return { status: "CONFLICT" };
      await this.db.prepare("INSERT INTO circles (circle_id, owner_identity, snapshot, revision, hash, closed) VALUES (?, ?, ?, ?, ?, 0)").bind(input.circleId, a.identity_id, input.newSnapshot, "1", newHash).run();
    }
    // Requests of accounts now admitted are cleared.
    const members = doc.members.map(hex);
    const rows = await this.db.prepare("SELECT r.account_name FROM requests r JOIN accounts a ON a.account_name = r.account_name WHERE r.circle_id = ? AND r.action = 'join'").bind(input.circleId).all<{ account_name: string }>();
    for (const row of rows.results) {
      const acct = await this.account(row.account_name);
      if (acct && members.includes(acct.identity_id)) await this.db.prepare("DELETE FROM requests WHERE circle_id = ? AND account_name = ? AND action = 'join'").bind(input.circleId, row.account_name).run();
    }
    return { status: "COMMITTED" };
  }

  async request(c: Caller, circleId: string, action: "join" | "leave"): Promise<Outcome> {
    const a = await this.account(c.accountName);
    if (!a) return { status: "UNAUTHORIZED" };
    const circle = await this.db.prepare("SELECT owner_identity, closed FROM circles WHERE circle_id = ?").bind(circleId).first<{ owner_identity: string; closed: number }>();
    if (!circle || circle.closed) return { status: "PERMANENT_FAILURE" };
    const ttl = BigInt(this.env.REQUEST_TTL_MS);
    const live = await this.db.prepare("SELECT requested_at FROM requests WHERE circle_id = ? AND account_name = ? AND action = ?").bind(circleId, a.account_name, action).first<{ requested_at: string }>();
    const hadLive = live !== null && BigInt(live.requested_at) > this.now - ttl;
    await this.db.prepare("INSERT INTO requests (circle_id, account_name, action, requested_at) VALUES (?, ?, ?, ?) ON CONFLICT (circle_id, account_name, action) DO UPDATE SET requested_at = excluded.requested_at").bind(circleId, a.account_name, action, this.now.toString()).run();
    if (!hadLive) {
      const owner = await this.accountByIdentity(circle.owner_identity);
      if (owner) await this.notify(action === "join" ? "joinRequest" : "leaveRequest", owner.account_name, a.account_name, circleId);
    }
    return { status: "COMMITTED" };
  }

  async requests(c: Caller, circleId: string): Promise<RequestView[]> {
    const a = await this.account(c.accountName);
    const circle = await this.db.prepare("SELECT owner_identity FROM circles WHERE circle_id = ?").bind(circleId).first<{ owner_identity: string }>();
    if (!a || !circle || circle.owner_identity !== a.identity_id) return [];
    const cutoff = (this.now - BigInt(this.env.REQUEST_TTL_MS)).toString();
    const rows = await this.db.prepare("SELECT account_name, action, requested_at FROM requests WHERE circle_id = ? AND CAST(requested_at AS INTEGER) > CAST(? AS INTEGER)").bind(circleId, cutoff).all<{ account_name: string; action: string; requested_at: string }>();
    return rows.results.map((r) => ({ circleId, accountName: r.account_name, action: r.action, requestedAt: r.requested_at }));
  }

  async notify(kind: string, to: string, from: string, circleId?: string): Promise<void> {
    await this.db.prepare("INSERT INTO notifications (kind, to_account, from_account, circle_id, at) VALUES (?, ?, ?, ?, ?)").bind(kind, to, from, circleId ?? null, this.now.toString()).run();
  }

  resetKeyList(): string | null {
    return this.env.RESET_KEY_LIST ?? null;
  }

  async receipt(resetId: string): Promise<string | null> {
    const r = await this.db.prepare("SELECT wire FROM receipts WHERE reset_id = ?").bind(resetId).first<{ wire: string }>();
    return r?.wire ?? null;
  }

  async reset(input: { accountName: string; expectedOldIdentityId: string; newCertificate: string; newVault: string; resetId: string }): Promise<Outcome> {
    // The reset id answers first: a device retrying after a lost response finds the account
    // already under its new identity and must get its receipt, not UNAUTHORIZED.
    const existing = await this.receipt(input.resetId);
    if (existing) return { status: "ALREADY_COMMITTED", receipt: existing };
    const a = await this.account(input.accountName);
    if (!a || a.identity_id !== input.expectedOldIdentityId) return { status: "UNAUTHORIZED" };
    if (!this.env.RESET_OPERATIONAL_SEED || !this.env.RESET_KEY_ID) return { status: "PERMANENT_FAILURE" };
    const doc = expectType<AccountDevice>(verifyDocument(unhex(input.newCertificate, "newCertificate")), DocumentType.AccountDevice);
    if (doc.accountName !== a.account_name) return { status: "UNAUTHORIZED" };
    const newIid = identityId(doc.accountName, doc.accountKey);
    const signer = signingKeypairFromSeed(unhex(this.env.RESET_OPERATIONAL_SEED, "seed"));
    const receipt = buildResetReceipt(
      { accountName: a.account_name, oldIdentityId: unhex(a.identity_id, "iid"), newIdentityId: newIid, resetId: unhex(input.resetId, "resetId"), issuedAt: this.now, authorityKeyId: unhex(this.env.RESET_KEY_ID, "keyId") },
      signer.secretKey
    );
    const vh = parseVaultHeader(unhex(input.newVault, "newVault"));
    const receiptHex = hex(receipt);
    const newHash = hex(doc.bodyHash);
    await this.db.batch([
      this.db.prepare("INSERT INTO receipts (reset_id, account_name, wire) VALUES (?, ?, ?)").bind(input.resetId, a.account_name, receiptHex),
      this.db.prepare("UPDATE circles SET closed = 1 WHERE owner_identity = ?").bind(a.identity_id),
      this.db
        .prepare("UPDATE accounts SET account_key = ?, identity_id = ?, certificate = ?, certificate_hash = ?, generation = ?, vault = ?, vault_revision = ?, vault_hash = ?, reset_receipt = ? WHERE account_name = ?")
        .bind(hex(doc.accountKey), hex(newIid), input.newCertificate, newHash, doc.generation.toString(), input.newVault, vh.vaultRevision.toString(), hex(vh.hash), receiptHex, a.account_name),
      this.db.prepare("INSERT INTO identities (identity_id, account_name) VALUES (?, ?)").bind(hex(newIid), a.account_name),
      this.db.prepare("UPDATE certificates SET current = 0 WHERE account_name = ?").bind(a.account_name),
      this.db.prepare("INSERT INTO certificates (certificate_hash, account_name, wire, current) VALUES (?, ?, ?, 1)").bind(newHash, a.account_name, input.newCertificate),
      this.db.prepare("INSERT OR IGNORE INTO device_ids (account_name, device_id) VALUES (?, ?)").bind(a.account_name, hex(doc.deviceId))
    ]);
    await this.openStream(hex(newIid), doc.deviceId, a.account_name);
    return { status: "COMMITTED", receipt: receiptHex };
  }

  async subscriptions(c: Caller): Promise<SubscriptionView[]> {
    const rows = await this.db.prepare("SELECT stream_id, author_identity FROM subscriptions WHERE reader_certificate = ?").bind(c.certificateHash).all<{ stream_id: string; author_identity: string }>();
    return rows.results.map((r) => ({ streamId: r.stream_id, authorIdentityId: r.author_identity }));
  }
}
