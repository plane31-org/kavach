/** Second review, finding 3: a replacement whose stream open failed after the directory committed still ends with a usable stream. */
import { describe, expect, it } from "vitest";
import { toHex } from "@plane31/blind-relay";
import { circleOfTwo, clock, device, hostJson, Platform } from "./world.js";
import { enqueueLocation, latest, locationFromDegrees } from "./location.js";

const loc = (lat = 37.7749) => locationFromDegrees(lat, -122.4194, 5, clock.now());

async function failedCommit(name: string) {
  const d = await device(name, new Platform());
  const p = await d.client.prepareReplacement();
  const { token } = await hostJson<{ token: string }>(`/v1/accounts/${name}/replacement-authorizations`, {
    method: "POST",
    body: JSON.stringify({ successionId: toHex(p.successionId), expectedCertificateHash: toHex(p.expectedCertificateHash), certificate: toHex(p.certificate) })
  });
  // The host commits the replacement (with the vault the device prepared), then its stream open fails: the device sees an error.
  const row = await d.store.read((tx) => tx.get("replacement", "pending"));
  const r = await hostJson<{ error?: string }>(`/v1/accounts/${name}/succeed`, {
    method: "POST",
    headers: { "x-test-fail-stream-open": "true" },
    body: JSON.stringify({ expectedCertificateHash: toHex(p.expectedCertificateHash), newCertificate: toHex(p.certificate), newVault: row?.vault, successionId: toHex(p.successionId), authorization: token })
  });
  expect(r.error).toBe("RETRYABLE");
  const page = await hostJson<{ successions: unknown[] }>(`/v1/successions/${toHex(p.accountId)}?after=0&limit=10`);
  expect(page.successions.length).toBe(1);
  return { d, p, token: Uint8Array.from(Buffer.from(token, "hex")) };
}

describe("a commit whose stream open did not finish", () => {
  it("the same call again answers ALREADY_COMMITTED and opens the stream; the device publishes", async () => {
    const { a, bobId } = await circleOfTwo();
    const { d, p, token } = await failedCommit("bob");
    expect((await d.client.completeReplacement({ successionId: p.successionId, authorization: token })).generation).toBe(2n);
    await d.client.sync();
    await a.client.sync();
    await d.client.sync();
    await enqueueLocation(d.client, loc(2));
    const r = await d.client.sync();
    expect([r.errors, r.epoch, r.outbox.accepted]).toEqual([[], "unchanged", 1]);
    await a.client.sync();
    expect(await latest(a.client, bobId)).toBeDefined();
  });

  it("a device that finishes from the chain never calls the commit again, and still gets its stream at its first publication", async () => {
    const { a, bobId } = await circleOfTwo();
    const { d } = await failedCommit("bob");
    const first = await d.client.sync(); // resumes from the chain
    expect([first.errors, (await d.client.getState()).generation]).toEqual([[], 2n]);
    await a.client.sync();
    await d.client.sync();
    await enqueueLocation(d.client, loc(3));
    const r = await d.client.sync();
    expect([r.errors, r.outbox.accepted]).toEqual([[], 1]);
    await a.client.sync();
    expect(await latest(a.client, bobId)).toBeDefined();
  });
});
