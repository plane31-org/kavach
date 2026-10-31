import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("workerd smoke", () => {
  it("serves health and has the bindings", async () => {
    const res = await SELF.fetch("https://host/health");
    expect(await res.json()).toEqual({ ok: true, host: "kavach reference host" });
    const rows = await env.DIRECTORY.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'").all();
    expect(rows.results.length).toBe(1);
    const id = env.STREAMS.idFromName("x");
    const stub = env.STREAMS.get(id);
    expect(await (await stub.fetch("https://do/")).json()).toEqual({ ok: true });
  });
});
