/** The HTTP surface of the reference host: protocol section 13's directory and relay, as JSON. */
import { DocumentType, expectType, parseDocument, type EncryptedRecord } from "@plane31/blind-relay/adapters";
import { Directory } from "./directory.js";
import type { Env } from "./env.js";
import { HttpError, big, body, error, hex, hostNow, json, requireCaller, unhex } from "./wire.js";

export async function handle(request: Request, env: Env): Promise<Response> {
  try {
    return await route(request, env);
  } catch (e) {
    if (e instanceof HttpError) return error(e.status, e.code, e.message);
    const code = typeof e === "object" && e !== null && "code" in e ? String((e as { code: unknown }).code) : "STORAGE_FAILURE";
    return error(code === "MALFORMED" || code === "BAD_SIGNATURE" || code === "UNSUPPORTED_TYPE" || code === "SIZE_LIMIT" ? 400 : 500, code, e instanceof Error ? e.message : undefined);
  }
}

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const now = hostNow(request, env);
  const dir = new Directory(env, now);
  const p = url.pathname.replace(/\/+$/, "").split("/").slice(1); // ["v1", ...]
  const m = request.method;
  if (url.pathname === "/health") return json({ ok: true, host: "kavach reference host", clock: env.ALLOW_TEST_CLOCK === "true" ? "test" : "real" });
  if (p[0] !== "v1") return error(404, "NOT_FOUND");
  const seg = p.slice(1);

  // Directory ----------------------------------------------------------------------------------
  if (seg[0] === "accounts" && seg.length === 1 && m === "POST") {
    const b = await body<{ certificate: string; vault: string }>(request);
    return json(await dir.register(b.certificate, b.vault));
  }
  if (seg[0] === "accounts" && seg.length === 1 && m === "GET") {
    const names = (url.searchParams.get("names") ?? "").split(",").filter(Boolean);
    return json(await dir.resolveAccounts(names));
  }
  if (seg[0] === "identities" && m === "GET") {
    const ids = (url.searchParams.get("ids") ?? "").split(",").filter(Boolean);
    return json(await dir.resolveIdentities(ids));
  }
  if (seg[0] === "certificates" && seg[1] && m === "GET") {
    const wire = await dir.certificate(seg[1]);
    return wire ? json({ wire }) : error(404, "NOT_FOUND");
  }
  if (seg[0] === "accounts" && seg[1] && seg[2] === "activate" && m === "POST") {
    const b = await body<{ expectedCertificateHash: string; expectedVaultRevision: string; expectedVaultHash: string; newCertificate: string; newVault: string }>(request);
    return json(await dir.activate({ accountName: seg[1], ...b }));
  }
  if (seg[0] === "accounts" && seg[1] && seg[2] === "vault" && m === "GET") {
    const v = await dir.vault(seg[1]);
    return v ? json({ wire: v }) : error(404, "NOT_FOUND");
  }
  if (seg[0] === "vault" && m === "PUT") {
    const b = await body<{ expectedRevision: string; expectedHash?: string; newVault: string }>(request);
    return json(await dir.publishVault(requireCaller(request), b));
  }
  if (seg[0] === "circles" && seg[1] && seg.length === 2 && m === "GET") {
    const s = await dir.circle(seg[1]);
    return s ? json({ wire: s }) : error(404, "NOT_FOUND");
  }
  if (seg[0] === "circles" && seg[1] && seg.length === 2 && m === "PUT") {
    const b = await body<{ expectedRevision: string; expectedHash?: string; newSnapshot: string }>(request);
    return json(await dir.publishCircle(requireCaller(request), { circleId: seg[1], ...b }));
  }
  if (seg[0] === "circles" && seg[1] && seg[2] === "requests" && m === "POST") {
    const b = await body<{ action: "join" | "leave" }>(request);
    if (b.action !== "join" && b.action !== "leave") throw new HttpError(400, "MALFORMED", "action");
    return json(await dir.request(requireCaller(request), seg[1], b.action));
  }
  if (seg[0] === "circles" && seg[1] && seg[2] === "requests" && m === "GET") return json(await dir.requests(requireCaller(request), seg[1]));
  if (seg[0] === "reset-keys" && m === "GET") {
    const w = dir.resetKeyList();
    return w ? json({ wire: w }) : error(404, "NOT_FOUND");
  }
  if (seg[0] === "reset-receipts" && seg[1] && m === "GET") {
    const w = await dir.receipt(seg[1]);
    return w ? json({ wire: w }) : error(404, "NOT_FOUND");
  }
  if (seg[0] === "accounts" && seg[1] && seg[2] === "reset" && m === "POST") {
    const b = await body<{ expectedOldIdentityId: string; newCertificate: string; newVault: string; resetId: string }>(request);
    return json(await dir.reset({ accountName: seg[1], ...b }));
  }
  if (seg[0] === "subscriptions" && m === "GET") return json(await dir.subscriptions(requireCaller(request)));

  // Relay ------------------------------------------------------------------------------------------
  if (seg[0] === "streams" && seg[1]) {
    const streamId = seg[1];
    if (!/^[0-9a-f]{64}$/.test(streamId)) throw new HttpError(400, "MALFORMED", "stream id");
    const stub = env.STREAMS.get(env.STREAMS.idFromName(streamId));
    const call = async <T>(path: string, payload: unknown): Promise<T> => {
      const res = await stub.fetch("https://stream" + path, { method: "POST", body: JSON.stringify(payload) });
      return (await res.json()) as T;
    };
    if (seg[2] === "epoch" && m === "GET") return json(await call("/currentEpoch", {}));
    if (seg[2] === "epochs" && seg[3] && m === "GET") {
      const c = requireCaller(request);
      const a = await dir.account(c.accountName);
      if (!a) throw new HttpError(401, "UNAUTHORIZED");
      return json(await call("/epoch", { epoch: Number(seg[3]), callerIdentityId: a.identity_id }));
    }
    if (seg[2] === "epochs" && seg.length === 3 && m === "PUT") {
      const a = await dir.currentDevice(requireCaller(request));
      const b = await body<{ expectedEpoch: number; manifest: string; wraps: Record<string, string> }>(request);
      const r = await call<{ status: string; newSubscriptions?: { certificateHash: string; identityId: string }[] }>("/publishEpoch", { callerIdentityId: a.identity_id, ...b });
      for (const s of r.newSubscriptions ?? []) {
        await env.DIRECTORY.prepare("INSERT OR IGNORE INTO subscriptions (stream_id, reader_certificate, author_identity) VALUES (?, ?, ?)").bind(streamId, s.certificateHash, a.identity_id).run();
      }
      return json(r);
    }
    if (seg[2] === "records" && m === "POST") {
      const a = await dir.currentDevice(requireCaller(request));
      const b = await body<{ recordId: string; wire: string }>(request);
      const rec = expectType<EncryptedRecord>(parseDocument(unhex(b.wire, "wire")), DocumentType.EncryptedRecord);
      if (hex(rec.streamId) !== streamId) throw new HttpError(400, "MALFORMED", "record is for another stream");
      const r = await call<{ status: string; notify?: { identityId: string; kind: string }[] }>("/append", { callerIdentityId: a.identity_id, recordId: b.recordId, wire: b.wire, now: now.toString() });
      for (const n of r.notify ?? []) {
        const to = await dir.accountByIdentity(n.identityId);
        if (to) await dir.notify(n.kind, to.account_name, a.account_name);
      }
      return json({ status: r.status });
    }
    if (seg[2] === "records" && m === "GET") {
      const c = requireCaller(request);
      const r = await call<{ error?: string }>("/read", { callerCertificate: c.certificateHash, afterSeq: big(url.searchParams.get("after") ?? "0", "after").toString(), limit: Number(url.searchParams.get("limit") ?? "100") });
      if (r.error) throw new HttpError(400, r.error);
      return json(r);
    }
    if (seg[2] === "ack" && m === "POST") {
      const c = requireCaller(request);
      const b = await body<{ cursor: string }>(request);
      return json(await call("/ack", { callerCertificate: c.certificateHash, cursor: big(b.cursor, "cursor").toString() }));
    }
    if (seg[2] === "expire" && m === "POST" && env.ALLOW_TEST_CLOCK === "true") return json(await call("/expire", { now: now.toString() }));
    if (seg[2] === "debug" && m === "GET" && env.ALLOW_TEST_CLOCK === "true") return json(await call("/debug", {}));
  }
  if (seg[0] === "debug" && seg[1] === "notifications" && m === "GET" && env.ALLOW_TEST_CLOCK === "true") {
    const rows = await env.DIRECTORY.prepare("SELECT kind, to_account, from_account, circle_id FROM notifications ORDER BY id").all();
    return json(rows.results);
  }
  return error(404, "NOT_FOUND");
}
