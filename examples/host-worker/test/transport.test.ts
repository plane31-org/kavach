/** The reference HTTP transport types its failures: no answer or a server error is NETWORK, a client error is not. */
import { describe, expect, it } from "vitest";
import { isKavachError } from "@kavach/core";
import { httpTransport } from "../client/httpTransport.js";

function transportWith(fetch: (input: string, init?: RequestInit) => Promise<Response>) {
  return httpTransport({ baseUrl: "http://host.test", fetch, caller: () => undefined });
}

async function failure(fn: () => Promise<unknown>): Promise<{ network: boolean; retryable: boolean | undefined }> {
  try {
    await fn();
    throw new Error("did not throw");
  } catch (e) {
    return { network: isKavachError(e, "NETWORK"), retryable: isKavachError(e) ? e.retryable : undefined };
  }
}

describe("httpTransport failures", () => {
  it("a connection failure is NETWORK and retryable", async () => {
    const t = transportWith(async () => {
      throw new TypeError("Failed to fetch");
    });
    expect(await failure(() => t.directory.resolveAccounts(["alice"]))).toEqual({ network: true, retryable: true });
  });

  it("a server error or a timeout status is NETWORK, a client error is a plain error", async () => {
    const answer = (status: number) => transportWith(async () => new Response(JSON.stringify({ error: "x" }), { status, headers: { "content-type": "application/json" } }));
    expect(await failure(() => answer(503).directory.resolveAccounts(["alice"]))).toEqual({ network: true, retryable: true });
    expect(await failure(() => answer(429).directory.resolveAccounts(["alice"]))).toEqual({ network: true, retryable: true });
    expect(await failure(() => answer(400).directory.resolveAccounts(["alice"]))).toEqual({ network: false, retryable: undefined });
  });
});
