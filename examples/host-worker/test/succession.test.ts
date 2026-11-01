/** Account recovery over HTTP against the real Worker: prepare, authorize through the test hook, commit, bootstrap, and the fence. */
import { describe, expect, it } from "vitest";
import { toHex } from "@plane31/blind-relay";
import { circleOfTwo, device, hostJson, Platform } from "./world.js";
import { enqueueLocation, latest, locationFromDegrees } from "./location.js";
import { clock } from "./world.js";

const loc = (lat = 37.7749) => locationFromDegrees(lat, -122.4194, 5, clock.now());

describe("account recovery over HTTP", () => {
  it("a member's replacement with no recovery material: the host signs the succession, the peer rotates, the old device is fenced", async () => {
    const { a, b, circleId, aliceId, bobId } = await circleOfTwo();
    const oldBearer = b.bearer();
    const b2 = await device("bob", new Platform());
    const proposal = await b2.client.prepareReplacement();
    expect((await b2.client.getState()).status).toBe("replacementPrepared");
    const { token } = await hostJson<{ token: string }>("/v1/accounts/bob/replacement-authorizations", {
      method: "POST",
      body: JSON.stringify({ successionId: toHex(proposal.successionId), expectedCertificateHash: toHex(proposal.expectedCertificateHash), certificate: toHex(proposal.certificate) })
    });
    const done = await b2.client.completeReplacement({ successionId: proposal.successionId, authorization: Uint8Array.from(Buffer.from(token, "hex")) });
    expect(done.generation).toBe(2n);
    // The same call again: ALREADY_COMMITTED at the host, idempotent here.
    expect((await b2.client.completeReplacement({ successionId: proposal.successionId, authorization: Uint8Array.from(Buffer.from(token, "hex")) })).generation).toBe(2n);
    const first = await b2.client.sync();
    expect([first.errors, first.bootstrap]).toEqual([[], { circles: 1, pending: 0, failed: 0 }]);
    expect((await b2.client.circles.list()).map((c) => [toHex(c.circleId), c.status, c.enabled])).toEqual([[toHex(circleId), "member", true]]);
    const ar = await a.client.sync();
    expect([ar.errors, ar.metadata.successions]).toEqual([[], 1]);
    await b2.client.sync();
    await enqueueLocation(b2.client, loc(2));
    await b2.client.sync();
    await a.client.sync();
    expect(await latest(a.client, bobId)).toBeDefined();
    await enqueueLocation(a.client, loc(3));
    await a.client.sync();
    await b2.client.sync();
    expect(await latest(b2.client, aliceId)).toBeDefined();
    // The old device: retired on its next sync, and refused by the relay with its old certificate.
    await b.client.sync();
    expect((await b.client.getState()).status).toBe("retired");
    const subs = await hostJson<{ streamId: string }[]>("/v1/subscriptions", { headers: { authorization: oldBearer } });
    const res = await hostJson<{ error?: string }>(`/v1/streams/${subs[0]?.streamId ?? ""}/records?after=0&limit=10`, { headers: { authorization: oldBearer } });
    expect(res.error).toBe("SUPERSEDED_DEVICE");
    // The chain is served under the account id.
    const [resolved] = await hostJson<{ successions?: unknown[] }[]>(`/v1/identities?ids=${toHex(bobId)}`);
    expect(resolved?.successions?.length).toBe(1);
  });
});
