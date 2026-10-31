/** The core's client scenarios, unchanged in substance, against the real Worker. */
import { describe, expect, it } from "vitest";
import { locationFromDegrees, toHex } from "@kavach/core";
import { circleOfTwo, clock, device } from "./world.js";

const loc = (lat = 37.7749) => locationFromDegrees(lat, -122.4194, 5, clock.now());

describe("client scenarios over HTTP", () => {
  it("1 and 2: create, request, approve, deliver; an offline requester shares on return", async () => {
    const { a, b, aliceId, bobId } = await circleOfTwo();
    expect((await b.client.getState()).circles[0]?.status).toBe("member");
    await a.client.enqueueLocation(loc(1));
    await a.client.sync();
    await b.client.sync();
    expect(await b.client.latest(aliceId)).toBeDefined();
    await b.client.enqueueLocation(loc(2));
    await b.client.sync();
    await a.client.sync();
    expect(await a.client.latest(bobId)).toBeDefined();
  });

  it("3 and 4: device replacement on either side keeps membership and rotates the other", async () => {
    const { a, b, circleId } = await circleOfTwo();
    const a2 = await device("alice", a.provider);
    const restored = await a2.client.restoreAccount();
    expect(restored.generation).toBe(2n);
    await a2.client.sync();
    expect((await a2.client.circles.list())[0]?.owned).toBe(true);
    await a.client.sync();
    expect((await a.client.getState()).status).toBe("retired");
    await b.client.sync();
    expect(b.events.some((e) => e.kind === "deviceChanged")).toBe(true);
    await a2.client.enqueueLocation(loc(3));
    await a2.client.sync();
    await b.client.sync();
    expect(await b.client.latest(restored.identityId)).toBeDefined();
    void circleId;
  });

  it("5: the lost device opens nothing new once authors have rotated", async () => {
    const { a, b, aliceId } = await circleOfTwo();
    const b2 = await device("bob", b.provider);
    await b2.client.restoreAccount();
    await b2.client.sync();
    await a.client.sync();
    await a.client.enqueueLocation(loc(3));
    await a.client.sync();
    const before = (await b.client.history({ authorIdentityId: aliceId })).length;
    await b.client.sync();
    expect((await b.client.getState()).status).toBe("retired");
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(before);
  });

  it("11: a reset receipt from the host closes owned circles at peers; a bare key change cannot happen through this host", async () => {
    const { a, b } = await circleOfTwo();
    await a.client.resetAccount({ confirmed: true });
    const report = await b.client.sync();
    expect(report.errors).toEqual([]);
    expect(b.events.some((e) => e.kind === "accountKeyChanged" && !e.quarantined)).toBe(true);
    expect((await b.client.circles.list())[0]?.status).toBe("closed");
  });

  it("12: removal with the owner online rotates and locks the removed member out", async () => {
    const { a, b, bobId } = await circleOfTwo();
    const circleId = (await a.client.circles.list())[0]?.circleId ?? new Uint8Array();
    await a.client.circles.remove(circleId, bobId);
    await a.client.sync();
    await a.client.enqueueLocation(loc(9));
    await a.client.sync();
    const r = await b.client.sync();
    expect((await b.client.circles.list())[0]?.status).toBe("left");
    expect(r.inbox.stored).toBe(0);
    expect(toHex(bobId).length).toBe(64);
  });
});
