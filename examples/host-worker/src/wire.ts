/** JSON over HTTP helpers for the reference host. Bytes travel as hex strings. */
import { fromHex, toHex } from "@kavach/core/adapters";
import type { Env } from "./env.js";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message?: string
  ) {
    super(message ?? code);
  }
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, (_, v: unknown) => (typeof v === "bigint" ? v.toString() : v)), { status, headers: { "content-type": "application/json" } });
}

export function error(status: number, code: string, message?: string): Response {
  return json({ error: code, ...(message ? { message } : {}) }, status);
}

export async function body<T>(request: Request): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    throw new HttpError(400, "MALFORMED", "body is not JSON");
  }
}

export const hex = (b: Uint8Array): string => toHex(b);
export const unhex = (s: string | undefined, field: string): Uint8Array => {
  if (typeof s !== "string") throw new HttpError(400, "MALFORMED", `${field} missing`);
  try {
    return fromHex(s);
  } catch {
    throw new HttpError(400, "MALFORMED", `${field} is not hex`);
  }
};
export const big = (s: string | number | undefined, field: string): bigint => {
  if (s === undefined) throw new HttpError(400, "MALFORMED", `${field} missing`);
  try {
    return BigInt(s);
  } catch {
    throw new HttpError(400, "MALFORMED", `${field} is not an integer`);
  }
};

/**
 * The caller. The reference host trusts a bearer of the form `accountName:certificateHash`; a
 * production host replaces this with its own login and session and hands the same two facts to
 * the handlers. The certificate hash names the device; a superseded device is refused writes.
 */
export interface Caller {
  readonly accountName: string;
  readonly certificateHash: string;
}

export function caller(request: Request): Caller | undefined {
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return undefined;
  const [accountName, certificateHash] = auth.slice(7).split(":");
  if (!accountName || !certificateHash || !/^[A-Za-z0-9_-]{1,64}$/.test(accountName) || !/^[0-9a-f]{64}$/.test(certificateHash)) return undefined;
  return { accountName, certificateHash };
}

export function requireCaller(request: Request): Caller {
  const c = caller(request);
  if (!c) throw new HttpError(401, "UNAUTHORIZED");
  return c;
}

/** Host time in milliseconds; tests may drive it with a header when the environment allows. */
export function hostNow(request: Request | undefined, env: Env): bigint {
  const override = request?.headers.get("x-test-now");
  if (override && env.ALLOW_TEST_CLOCK === "true") return BigInt(override);
  return BigInt(Date.now());
}
