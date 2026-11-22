/**
 * The HTTP binding of the transport contract (protocol section 13), as the reference host serves
 * it: JSON bodies with bytes as hex, one route per operation, relative to `baseUrl`, which carries
 * the host's version prefix (`https://host/v1`, or wherever the routes are mounted). Published as
 * `@plane31/blind-relay/http` (0.9.0) so an app does not keep its own copy of these wire rules.
 *
 * Failures are typed as the transport error contract says: no answer, a timeout (408), a server
 * error (5xx), a body lost while streaming, or a 2xx whose body is not JSON (a captive portal or a
 * proxy answered) is `NETWORK`, retryable; a 429 is `RATE_LIMITED` with the host's `Retry-After`;
 * a 404 on `sync-state` is `UNSUPPORTED_OPERATION`. Any other refusal is a plain error. Every
 * message names the call and the host's `x-request-id` when it sent one.
 *
 * The client attaches itself (`Transport.attach`): each call carries the device's certificate hash
 * in `x-kavach-device` and the running sync's id in `x-kavach-op`, and an append carries the
 * client's revision in `kavach-revision`. Authentication is the app's: `headers` returns what the
 * host needs (a bearer token, say), synchronously, since an append must start inside the sender's
 * transaction.
 */
import { fromHex, toHex } from "./bytes.js";
import { KavachError } from "./errors.js";
import type { AppendOutcome, Directory, EpochBundle, JoinRequest, MutationOutcome, ReadRecordsResult, Relay, ResolvedAccount, Transport, TransportContext } from "./transport.js";

/** The part of a fetch response the transport reads. */
export interface FetchResponseLike {
  readonly status: number;
  readonly ok: boolean;
  readonly headers: { get(name: string): string | null };
  text(): Promise<string>;
}

/** The part of `fetch` the transport calls; the platform's `fetch` fits it. */
export type FetchLike = (input: string, init: { method: string; headers: Record<string, string>; body?: string }) => Promise<FetchResponseLike>;

export interface HttpTransportOptions {
  /** The host's routes, with their version prefix: `https://host/v1`. */
  readonly baseUrl: string;
  /** Default: the platform's `fetch`. */
  readonly fetch?: FetchLike;
  /** Headers of the app's own for every call (authentication, a test clock), given what the client attached. Synchronous. */
  readonly headers?: (context: TransportContext | undefined) => Record<string, string>;
  /** Default `x-kavach-device`: the current certificate hash, hex. */
  readonly deviceHeader?: string;
  /** Default `x-kavach-op`: the running sync's correlation id. */
  readonly opHeader?: string;
}

type Json = Record<string, unknown>;

export function httpTransport(o: HttpTransportOptions): Transport {
  const fetcher = o.fetch ?? (globalThis as { fetch?: FetchLike }).fetch?.bind(globalThis);
  if (!fetcher) throw new KavachError("MALFORMED", "httpTransport", "no fetch: pass one");
  const deviceHeader = o.deviceHeader ?? "x-kavach-device";
  const opHeader = o.opHeader ?? "x-kavach-op";
  let context: TransportContext | undefined;
  const call = async <T>(method: string, path: string, payload?: unknown, extra: Record<string, string> = {}): Promise<T> => {
    const headers: Record<string, string> = { "content-type": "application/json", ...(o.headers?.(context) ?? {}), ...extra };
    const device = context?.device();
    if (device) headers[deviceHeader] = toHex(device.certificateHash);
    const op = context?.opId();
    if (op) headers[opHeader] = op;
    let res: FetchResponseLike;
    try {
      res = await fetcher(o.baseUrl + path, { method, headers, ...(payload === undefined ? {} : { body: JSON.stringify(payload, (_, v: unknown) => (typeof v === "bigint" ? v.toString() : v)) }) });
    } catch (e) {
      throw new KavachError("NETWORK", "transport", `${method} ${path}: ${e instanceof Error ? e.message : String(e)}`);
    }
    const requestId = res.headers.get("x-request-id");
    const where = `${method} ${path}${requestId ? ` (request ${requestId})` : ""}`;
    if (res.status === 404) return null as T;
    if (res.status === 429) {
      // The host asked for a pause: retryable, with the wait it named (seconds or an HTTP date).
      const header = res.headers.get("retry-after");
      const seconds = header === null ? NaN : Number(header);
      const retryAfterMs = header === null ? undefined : Number.isFinite(seconds) ? Math.max(0, seconds) * 1000 : Math.max(0, Date.parse(header) - Date.now()) || undefined;
      throw new KavachError("RATE_LIMITED", "transport", `${where}: 429`, retryAfterMs === undefined ? {} : { retryAfterMs });
    }
    if (res.status >= 500 || res.status === 408) throw new KavachError("NETWORK", "transport", `${where}: ${res.status}`);
    // The fetch promise resolves at the headers: a connection lost while the body streams fails here.
    let text: string;
    try {
      text = await res.text();
    } catch (e) {
      throw new KavachError("NETWORK", "transport", `${where}: body: ${e instanceof Error ? e.message : String(e)}`);
    }
    let data: Json;
    try {
      data = JSON.parse(text) as Json;
    } catch {
      // A success that is not JSON did not come from the host: a captive portal or a proxy. Retryable.
      if (res.ok) throw new KavachError("NETWORK", "transport", `${where}: the answer is not JSON`);
      throw new Error(`${where}: ${res.status}`);
    }
    if (!res.ok) {
      // A host may answer `{ error: "..." }` or `{ error: { code, message } }`.
      const err = data["error"];
      const detail = typeof err === "object" && err !== null ? [(err as Json)["code"], (err as Json)["message"]].filter((x) => x !== undefined).map(String).join(": ") : String(err ?? res.status);
      throw new Error(`${where}: ${detail || res.status}`);
    }
    return data as T;
  };
  const outcome = (r: Json): MutationOutcome => ({
    status: r["status"] as MutationOutcome["status"],
    ...(typeof r["current"] === "string" ? { current: fromHex(r["current"]) } : {}),
    ...(typeof r["currentRevision"] === "string" ? { currentRevision: BigInt(r["currentRevision"]) } : {})
  });
  const links = (rows: unknown): { wire: Uint8Array; certificate: Uint8Array }[] => (Array.isArray(rows) ? (rows as { wire: string; certificate: string }[]).map((l) => ({ wire: fromHex(l.wire), certificate: fromHex(l.certificate) })) : []);
  const resolved = (rows: Json[]): ResolvedAccount[] =>
    rows.map((r) => ({
      accountName: String(r["accountName"]),
      accountKey: fromHex(String(r["accountKey"])),
      certificate: fromHex(String(r["certificate"])),
      ...(typeof r["resetReceipt"] === "string" ? { resetReceipt: fromHex(r["resetReceipt"]) } : {}),
      ...(Array.isArray(r["successions"]) ? { successions: links(r["successions"]) } : {}),
      ...(typeof r["successionsNext"] === "string" ? { successionsNext: BigInt(r["successionsNext"]) } : {}),
      ...(typeof r["rootCertificate"] === "string" ? { rootCertificate: fromHex(r["rootCertificate"]) } : {})
    }));

  const directory: Directory = {
    resolveAccounts: async (names) => resolved((await call<Json[]>("GET", `/accounts?names=${names.join(",")}`)) ?? []),
    resolveIdentities: async (ids) => resolved((await call<Json[]>("GET", `/identities?ids=${ids.map(toHex).join(",")}`)) ?? []),
    getCertificate: async (hash) => {
      const r = await call<{ wire: string } | null>("GET", `/certificates/${toHex(hash)}`);
      return r ? fromHex(r.wire) : undefined;
    },
    registerAccount: async ({ certificate, vault }) => outcome(await call<Json>("POST", "/accounts", { certificate: toHex(certificate), ...(vault ? { vault: toHex(vault) } : {}) })),
    activateDevice: async (i) =>
      outcome(
        await call<Json>("POST", `/accounts/${i.accountName}/activate`, {
          expectedCertificateHash: toHex(i.expectedCertificateHash),
          expectedVaultRevision: i.expectedVaultRevision,
          expectedVaultHash: toHex(i.expectedVaultHash),
          newCertificate: toHex(i.newCertificate),
          newVault: toHex(i.newVault)
        })
      ),
    getVault: async (name) => {
      const r = await call<{ wire: string } | null>("GET", `/accounts/${name}/vault`);
      return r ? fromHex(r.wire) : undefined;
    },
    publishVault: async (i) => outcome(await call<Json>("PUT", "/vault", { expectedRevision: i.expectedRevision, ...(i.expectedHash ? { expectedHash: toHex(i.expectedHash) } : {}), newVault: toHex(i.newVault) })),
    getCircle: async (id) => {
      const r = await call<{ wire: string } | null>("GET", `/circles/${toHex(id)}`);
      return r ? fromHex(r.wire) : undefined;
    },
    publishOwnedCircle: async (i) => outcome(await call<Json>("PUT", `/circles/${toHex(i.circleId)}`, { expectedRevision: i.expectedRevision, ...(i.expectedHash ? { expectedHash: toHex(i.expectedHash) } : {}), newSnapshot: toHex(i.newSnapshot) })),
    requestJoin: async (id) => outcome(await call<Json>("POST", `/circles/${toHex(id)}/requests`, { action: "join" })),
    requestLeave: async (id) => outcome(await call<Json>("POST", `/circles/${toHex(id)}/requests`, { action: "leave" })),
    readRequests: async (id): Promise<JoinRequest[]> =>
      ((await call<Json[]>("GET", `/circles/${toHex(id)}/requests`)) ?? []).map((r) => ({ circleId: id, accountName: String(r["accountName"]), action: r["action"] as "join" | "leave", requestedAt: BigInt(String(r["requestedAt"])) })),
    getResetKeyList: async () => {
      const r = await call<{ wire: string } | null>("GET", "/reset-keys");
      return r ? fromHex(r.wire) : undefined;
    },
    getResetReceipt: async (id) => {
      const r = await call<{ wire: string } | null>("GET", `/reset-receipts/${toHex(id)}`);
      return r ? fromHex(r.wire) : undefined;
    },
    resetAccount: async (i) => {
      const r = await call<Json>("POST", `/accounts/${i.accountName}/reset`, { expectedOldIdentityId: toHex(i.expectedOldIdentityId), newCertificate: toHex(i.newCertificate), ...(i.newVault ? { newVault: toHex(i.newVault) } : {}), resetId: toHex(i.resetId) });
      return { ...outcome(r), ...(typeof r["receipt"] === "string" ? { receipt: fromHex(r["receipt"]) } : {}) };
    },
    succeedAccount: async (i) => {
      const r = await call<Json>("POST", `/accounts/${i.accountName}/succeed`, {
        expectedCertificateHash: toHex(i.expectedCertificateHash),
        newCertificate: toHex(i.newCertificate),
        ...(i.newVault ? { newVault: toHex(i.newVault) } : {}),
        successionId: toHex(i.successionId),
        authorization: toHex(i.authorization)
      });
      return { ...outcome(r), ...(typeof r["succession"] === "string" ? { succession: fromHex(r["succession"]) } : {}) };
    },
    getSuccessions: async (accountId, after, limit) => {
      const r = await call<Json | null>("GET", `/successions/${toHex(accountId)}?after=${after}&limit=${limit}`);
      return { successions: links(r?.["successions"]), ...(typeof r?.["nextGeneration"] === "string" ? { nextGeneration: BigInt(r["nextGeneration"]) } : {}), ...(typeof r?.["rootCertificate"] === "string" ? { rootCertificate: fromHex(r["rootCertificate"]) } : {}) };
    },
    listCircles: async (cursor) => {
      const r = await call<Json | null>("GET", `/circles${cursor ? `?cursor=${cursor}` : ""}`);
      const rows = Array.isArray(r?.["circles"]) ? (r["circles"] as Json[]) : [];
      return {
        circles: rows.map((c) => ({
          circleId: fromHex(String(c["circleId"])),
          ownerAccountId: fromHex(String(c["ownerAccountId"])),
          role: c["role"] as "owner" | "member" | "pending",
          snapshot: typeof c["snapshot"] === "string" ? fromHex(c["snapshot"]) : undefined,
          enabled: typeof c["enabled"] === "boolean" ? c["enabled"] : undefined,
          preferenceRevision: BigInt(String(c["preferenceRevision"] ?? "0"))
        })),
        ...(typeof r?.["cursor"] === "string" ? { cursor: r["cursor"] } : {})
      };
    },
    setSharingPreference: async (circleId, enabled, expectedRevision) => {
      const r = await call<Json>("PUT", `/circles/${toHex(circleId)}/preference`, { enabled, expectedRevision });
      return { status: r["status"] as "COMMITTED" | "ALREADY_COMMITTED" | "CONFLICT" | "UNAUTHORIZED" | "RETRYABLE", revision: BigInt(String(r["revision"] ?? "0")), ...(typeof r["enabled"] === "boolean" ? { enabled: r["enabled"] } : {}) };
    }
  };

  const relay: Relay = {
    getCurrentEpoch: async (streamId) => {
      const r = await call<{ epoch: number; manifestHash: string } | null>("GET", `/streams/${toHex(streamId)}/epoch`);
      return r ? { epoch: r.epoch, manifestHash: fromHex(r.manifestHash) } : undefined;
    },
    getEpoch: async (streamId, epoch): Promise<EpochBundle | undefined> => {
      const r = await call<{ manifest: string; wrap: string | null } | null>("GET", `/streams/${toHex(streamId)}/epochs/${epoch}`);
      return r ? { manifest: fromHex(r.manifest), wrap: r.wrap ? fromHex(r.wrap) : undefined } : undefined;
    },
    publishEpoch: async (i) => {
      const r = await call<Json>("PUT", `/streams/${toHex(i.streamId)}/epochs`, { expectedEpoch: i.expectedEpoch, manifest: toHex(i.manifest), wraps: Object.fromEntries([...i.wraps].map(([k, v]) => [k, toHex(v)])) });
      return { ...outcome(r), ...(typeof r["currentEpoch"] === "number" ? { currentEpoch: r["currentEpoch"] } : {}), ...(typeof r["currentManifest"] === "string" ? { currentManifest: fromHex(r["currentManifest"]) } : {}) };
    },
    appendRecord: (recordId, wire, options): Promise<AppendOutcome> => {
      // Callable from inside T6h: the request starts synchronously, the promise is awaited later.
      // The client's revision travels as a header, so a host answers AUDIENCE_STALE only to
      // clients that read it (revision 12).
      const streamId = toHex(wire.subarray(2, 34));
      const extra: Record<string, string> = options ? { "kavach-revision": String(options.revision) } : {};
      return call<Json>("POST", `/streams/${streamId}/records`, { recordId: toHex(recordId), wire: toHex(wire) }, extra).then((r) => ({ status: r["status"] as AppendOutcome["status"] }));
    },
    readRecords: async (streamId, afterSeq, limit): Promise<ReadRecordsResult> => {
      const r = await call<Json>("GET", `/streams/${toHex(streamId)}/records?after=${afterSeq}&limit=${limit}`);
      return {
        records: (r["records"] as { deliverySeq: string; wire: string }[]).map((x) => ({ deliverySeq: BigInt(x.deliverySeq), wire: fromHex(x.wire) })),
        nextSeq: BigInt(String(r["nextSeq"])),
        tail: BigInt(String(r["tail"])),
        expiredThrough: BigInt(String(r["expiredThrough"])),
        committedCursor: BigInt(String(r["committedCursor"]))
      };
    },
    ackThrough: async (streamId, cursor) => {
      const r = await call<Json>("POST", `/streams/${toHex(streamId)}/ack`, { cursor });
      return { status: r["status"] as "COMMITTED" | "CURSOR_OUT_OF_RANGE" | "RETRYABLE" | "UNAUTHORIZED", ...(typeof r["committedCursor"] === "string" ? { committedCursor: BigInt(r["committedCursor"]) } : {}) };
    },
    listSubscriptions: async () => ((await call<Json[]>("GET", "/subscriptions")) ?? []).map((s) => ({ streamId: fromHex(String(s["streamId"])), authorIdentityId: fromHex(String(s["authorIdentityId"])) })),
    syncState: async () => {
      const r = await call<Json | null>("GET", "/sync-state");
      // A host without the change check answers 404: a deployment mismatch, never a fallback.
      if (r === null) throw new KavachError("UNSUPPORTED_OPERATION", "transport", "GET /sync-state: 404");
      return {
        subscriptions: (r["subscriptions"] as Json[]).map((s) => ({ streamId: fromHex(String(s["streamId"])), authorIdentityId: fromHex(String(s["authorIdentityId"])), head: BigInt(String(s["head"])), pending: s["pending"] === true }))
      };
    }
  };

  return {
    directory,
    relay,
    attach: (c) => {
      context = c;
    }
  };
}
