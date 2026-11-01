/**
 * The core's Transport over the reference host's HTTP surface. Bytes travel as hex; the caller
 * is a bearer of `accountName:certificateHash` (the reference host's stand-in for real login).
 */
import { KavachError, fromHex, toHex, type AppendOutcome, type Directory, type EpochBundle, type JoinRequest, type MutationOutcome, type ReadRecordsResult, type Relay, type ResolvedAccount, type Transport } from "@plane31/blind-relay/adapters";

export interface HttpTransportOptions {
  readonly baseUrl: string;
  readonly fetch: (input: string, init?: RequestInit) => Promise<Response>;
  /** The caller after enrollment; undefined before. */
  readonly caller: () => { accountName: string; certificateHash: Uint8Array } | undefined;
  /** Test clock forwarded as X-Test-Now when the host allows it. */
  readonly now?: () => bigint;
}

type Json = Record<string, unknown>;

export function httpTransport(o: HttpTransportOptions): Transport {
  const call = async <T>(method: string, path: string, payload?: unknown): Promise<T> => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    const c = o.caller();
    if (c) headers["authorization"] = `Bearer ${c.accountName}:${toHex(c.certificateHash)}`;
    if (o.now) headers["x-test-now"] = o.now().toString();
    // Failures at the transport boundary are typed: no answer, a timeout or a server error is
    // NETWORK (retryable); anything else that goes wrong is a plain error, which core reports as
    // unexpected and not retryable.
    let res: Response;
    try {
      res = await o.fetch(o.baseUrl + path, { method, headers, ...(payload === undefined ? {} : { body: JSON.stringify(payload, (_, v: unknown) => (typeof v === "bigint" ? v.toString() : v)) }) });
    } catch (e) {
      throw new KavachError("NETWORK", "transport", `${method} ${path}: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (res.status === 404) return null as T;
    if (res.status >= 500 || res.status === 408 || res.status === 429) throw new KavachError("NETWORK", "transport", `${method} ${path}: ${res.status}`);
    // The fetch promise resolves at the headers: a connection lost while the body streams fails
    // here, and is NETWORK too. A body that arrived but is not JSON is the host's bug, a plain error.
    let text: string;
    try {
      text = await res.text();
    } catch (e) {
      throw new KavachError("NETWORK", "transport", `${method} ${path}: body: ${e instanceof Error ? e.message : String(e)}`);
    }
    const data = JSON.parse(text) as Json;
    if (!res.ok) throw new Error(`${method} ${path}: ${String(data["error"] ?? res.status)}`);
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
    resolveAccounts: async (names) => resolved((await call<Json[]>("GET", `/v1/accounts?names=${names.join(",")}`)) ?? []),
    resolveIdentities: async (ids) => resolved((await call<Json[]>("GET", `/v1/identities?ids=${ids.map(toHex).join(",")}`)) ?? []),
    getCertificate: async (hash) => {
      const r = await call<{ wire: string } | null>("GET", `/v1/certificates/${toHex(hash)}`);
      return r ? fromHex(r.wire) : undefined;
    },
    registerAccount: async ({ certificate, vault }) => outcome(await call<Json>("POST", "/v1/accounts", { certificate: toHex(certificate), vault: toHex(vault) })),
    activateDevice: async (i) =>
      outcome(
        await call<Json>("POST", `/v1/accounts/${i.accountName}/activate`, {
          expectedCertificateHash: toHex(i.expectedCertificateHash),
          expectedVaultRevision: i.expectedVaultRevision,
          expectedVaultHash: toHex(i.expectedVaultHash),
          newCertificate: toHex(i.newCertificate),
          newVault: toHex(i.newVault)
        })
      ),
    getVault: async (name) => {
      const r = await call<{ wire: string } | null>("GET", `/v1/accounts/${name}/vault`);
      return r ? fromHex(r.wire) : undefined;
    },
    publishVault: async (i) => outcome(await call<Json>("PUT", "/v1/vault", { expectedRevision: i.expectedRevision, ...(i.expectedHash ? { expectedHash: toHex(i.expectedHash) } : {}), newVault: toHex(i.newVault) })),
    getCircle: async (id) => {
      const r = await call<{ wire: string } | null>("GET", `/v1/circles/${toHex(id)}`);
      return r ? fromHex(r.wire) : undefined;
    },
    publishOwnedCircle: async (i) => outcome(await call<Json>("PUT", `/v1/circles/${toHex(i.circleId)}`, { expectedRevision: i.expectedRevision, ...(i.expectedHash ? { expectedHash: toHex(i.expectedHash) } : {}), newSnapshot: toHex(i.newSnapshot) })),
    requestJoin: async (id) => outcome(await call<Json>("POST", `/v1/circles/${toHex(id)}/requests`, { action: "join" })),
    requestLeave: async (id) => outcome(await call<Json>("POST", `/v1/circles/${toHex(id)}/requests`, { action: "leave" })),
    readRequests: async (id): Promise<JoinRequest[]> =>
      ((await call<Json[]>("GET", `/v1/circles/${toHex(id)}/requests`)) ?? []).map((r) => ({ circleId: id, accountName: String(r["accountName"]), action: r["action"] as "join" | "leave", requestedAt: BigInt(String(r["requestedAt"])) })),
    getResetKeyList: async () => {
      const r = await call<{ wire: string } | null>("GET", "/v1/reset-keys");
      return r ? fromHex(r.wire) : undefined;
    },
    getResetReceipt: async (id) => {
      const r = await call<{ wire: string } | null>("GET", `/v1/reset-receipts/${toHex(id)}`);
      return r ? fromHex(r.wire) : undefined;
    },
    resetAccount: async (i) => {
      const r = await call<Json>("POST", `/v1/accounts/${i.accountName}/reset`, { expectedOldIdentityId: toHex(i.expectedOldIdentityId), newCertificate: toHex(i.newCertificate), newVault: toHex(i.newVault), resetId: toHex(i.resetId) });
      return { ...outcome(r), ...(typeof r["receipt"] === "string" ? { receipt: fromHex(r["receipt"]) } : {}) };
    },
    succeedAccount: async (i) => {
      const r = await call<Json>("POST", `/v1/accounts/${i.accountName}/succeed`, {
        expectedCertificateHash: toHex(i.expectedCertificateHash),
        newCertificate: toHex(i.newCertificate),
        ...(i.newVault ? { newVault: toHex(i.newVault) } : {}),
        successionId: toHex(i.successionId),
        authorization: toHex(i.authorization)
      });
      return { ...outcome(r), ...(typeof r["succession"] === "string" ? { succession: fromHex(r["succession"]) } : {}) };
    },
    getSuccessions: async (accountId, after, limit) => {
      const r = await call<Json | null>("GET", `/v1/successions/${toHex(accountId)}?after=${after}&limit=${limit}`);
      return { successions: links(r?.["successions"]), ...(typeof r?.["nextGeneration"] === "string" ? { nextGeneration: BigInt(r["nextGeneration"]) } : {}), ...(typeof r?.["rootCertificate"] === "string" ? { rootCertificate: fromHex(r["rootCertificate"]) } : {}) };
    },
    listCircles: async (cursor) => {
      const r = await call<Json | null>("GET", `/v1/circles${cursor ? `?cursor=${cursor}` : ""}`);
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
      const r = await call<Json>("PUT", `/v1/circles/${toHex(circleId)}/preference`, { enabled, expectedRevision });
      return { status: r["status"] as "COMMITTED" | "ALREADY_COMMITTED" | "CONFLICT" | "UNAUTHORIZED" | "RETRYABLE", revision: BigInt(String(r["revision"] ?? "0")), ...(typeof r["enabled"] === "boolean" ? { enabled: r["enabled"] } : {}) };
    }
  };

  const relay: Relay = {
    getCurrentEpoch: async (streamId) => {
      const r = await call<{ epoch: number; manifestHash: string } | null>("GET", `/v1/streams/${toHex(streamId)}/epoch`);
      return r ? { epoch: r.epoch, manifestHash: fromHex(r.manifestHash) } : undefined;
    },
    getEpoch: async (streamId, epoch): Promise<EpochBundle | undefined> => {
      const r = await call<{ manifest: string; wrap: string | null } | null>("GET", `/v1/streams/${toHex(streamId)}/epochs/${epoch}`);
      return r ? { manifest: fromHex(r.manifest), wrap: r.wrap ? fromHex(r.wrap) : undefined } : undefined;
    },
    publishEpoch: async (i) => {
      const r = await call<Json>("PUT", `/v1/streams/${toHex(i.streamId)}/epochs`, { expectedEpoch: i.expectedEpoch, manifest: toHex(i.manifest), wraps: Object.fromEntries([...i.wraps].map(([k, v]) => [k, toHex(v)])) });
      return { ...outcome(r), ...(typeof r["currentEpoch"] === "number" ? { currentEpoch: r["currentEpoch"] } : {}), ...(typeof r["currentManifest"] === "string" ? { currentManifest: fromHex(r["currentManifest"]) } : {}) };
    },
    appendRecord: (recordId, wire): Promise<AppendOutcome> => {
      // Callable from inside T6h: the request starts synchronously, the promise is awaited later.
      const streamId = toHex(wire.subarray(2, 34));
      return call<Json>("POST", `/v1/streams/${streamId}/records`, { recordId: toHex(recordId), wire: toHex(wire) }).then((r) => ({ status: r["status"] as AppendOutcome["status"] }));
    },
    readRecords: async (streamId, afterSeq, limit): Promise<ReadRecordsResult> => {
      const r = await call<Json>("GET", `/v1/streams/${toHex(streamId)}/records?after=${afterSeq}&limit=${limit}`);
      return {
        records: (r["records"] as { deliverySeq: string; wire: string }[]).map((x) => ({ deliverySeq: BigInt(x.deliverySeq), wire: fromHex(x.wire) })),
        nextSeq: BigInt(String(r["nextSeq"])),
        tail: BigInt(String(r["tail"])),
        expiredThrough: BigInt(String(r["expiredThrough"])),
        committedCursor: BigInt(String(r["committedCursor"]))
      };
    },
    ackThrough: async (streamId, cursor) => {
      const r = await call<Json>("POST", `/v1/streams/${toHex(streamId)}/ack`, { cursor });
      return { status: r["status"] as "COMMITTED" | "CURSOR_OUT_OF_RANGE" | "RETRYABLE" | "UNAUTHORIZED", ...(typeof r["committedCursor"] === "string" ? { committedCursor: BigInt(r["committedCursor"]) } : {}) };
    },
    listSubscriptions: async () => ((await call<Json[]>("GET", "/v1/subscriptions")) ?? []).map((s) => ({ streamId: fromHex(String(s["streamId"])), authorIdentityId: fromHex(String(s["authorIdentityId"])) }))
  };

  return { directory, relay };
}
