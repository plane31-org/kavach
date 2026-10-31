/**
 * Regressions from the external review of the step 14 commit: concurrent promotion, activation
 * resume, unconfirmed owner snapshots and vault writes, and pauses that outlive their cause.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ready } from "../src/crypto.js";
import { pair, thrown, world } from "./clientWorld.js";

beforeAll(() => ready());

describe("review findings", () => {
  it("1: two concurrent sends after an invalidation never share a record id or reset the counter", async () => {
    const w = world();
    const { a, circleId } = await pair(w);
    // Invalidate the active epoch so both enqueues race through epoch publication.
    await a.client.circles.setEnabled(circleId, false);
    await a.client.circles.setEnabled(circleId, true);
    const [x, y] = await Promise.all([a.client.enqueueLocation(w.loc(2)), a.client.enqueueLocation(w.loc(3))]);
    expect(toHex(x.recordId)).not.toBe(toHex(y.recordId));
    const counters = await a.store.read((tx) => tx.list("outbox").map(([, r]) => r.counter).sort());
    expect(counters).toEqual([0, 1]);
    const r = await w.sync(a);
    expect(r.outbox.accepted).toBe(2);
    expect(w.host.appendLog.some((e) => e.status === "EQUIVOCATION" || e.status === "STALE_APPEND")).toBe(false);
  });

  it("2: a lost activation response is finished by the next sync, and a second restore allocates nothing", async () => {
    const w = world();
    const { b } = await pair(w);
    const b2 = await w.device("bob", b.provider.twin());
    b2.t.knobs.loseResponseOf.add("activateDevice");
    expect(await thrown(() => b2.client.restoreAccount())).toMatch(/response lost/);
    expect((await b2.client.getState()).status).toBe("activationPending");
    const r = await w.sync(b2);
    expect(r.errors).toEqual([]);
    expect((await b2.client.getState()).status).toBe("ready");
    expect(await thrown(() => b2.client.restoreAccount())).toBe("MALFORMED");
    const acct = w.host.accounts.get("bob");
    expect([acct?.generation, acct?.deviceIds.size]).toEqual([2n, 2]);
  });

  it("3: a removal whose publication failed is published by the next sync and the member is out", async () => {
    const w = world();
    const { a, b, bobId, circleId } = await pair(w);
    a.t.knobs.refuse.add("publishOwnedCircle");
    expect(await thrown(() => a.client.circles.remove(circleId, bobId))).toMatch(/unreachable/);
    expect(w.host.circles.get(toHex(circleId))?.revision).toBe(2n);
    const r = await w.sync(a);
    expect(r.errors).toEqual([]);
    expect(w.host.circles.get(toHex(circleId))?.revision).toBe(3n);
    expect((await a.client.circles.list())[0]?.members.length).toBe(1);
    await w.sync(b);
    expect((await b.client.circles.list())[0]?.status).toBe("left");
    // Nothing after the removal is readable by Bob.
    await a.client.enqueueLocation(w.loc(4));
    await w.sync(a);
    expect((await w.sync(b)).inbox.stored).toBe(0);
  });

  it("4: a sharing preference whose vault write failed reaches the vault on the next sync and survives a phone replacement", async () => {
    const w = world();
    const { b, circleId } = await pair(w);
    const before = w.host.accounts.get("bob")?.vault?.revision;
    b.t.knobs.refuse.add("publishVault");
    expect(await thrown(() => b.client.circles.setEnabled(circleId, false))).toMatch(/unreachable/);
    expect((await b.client.circles.list())[0]?.enabled).toBe(false);
    expect(w.host.accounts.get("bob")?.vault?.revision).toBe(before);
    // Repeating the same preference does not lose it either.
    await b.client.circles.setEnabled(circleId, false);
    expect(w.host.accounts.get("bob")?.vault?.revision).toBe((before ?? 0n) + 1n);
    // And if nothing is repeated, sync does it.
    b.t.knobs.refuse.add("publishVault");
    expect(await thrown(() => b.client.circles.setEnabled(circleId, true))).toMatch(/unreachable/);
    const r = await w.sync(b);
    expect(r.errors).toEqual([]);
    expect(w.host.accounts.get("bob")?.vault?.revision).toBe((before ?? 0n) + 2n);
    const b2 = await w.device("bob", b.provider.twin());
    await b2.client.restoreAccount();
    expect((await b2.client.circles.list())[0]?.enabled).toBe(true);
  });

  it("5: a certificate that arrives late lifts the metadata pause when the epoch promotes", async () => {
    const w = world();
    const { a, b, aliceId, circleId } = await pair(w);
    const c = await w.device("carol");
    await c.client.initializeAccount();
    await c.client.circles.requestJoin(circleId, aliceId);
    await w.sync(a);
    b.t.knobs.withhold.add("certificates");
    await a.client.circles.approve(circleId, "carol");
    await w.sync(a);
    await w.sync(b);
    const paused = await b.client.getState();
    expect([paused.status, paused.paused]).toEqual(["paused", "metadata"]);
    expect(await thrown(() => b.client.enqueueLocation(w.loc(5)))).toBe("METADATA_REQUIRED");
    b.t.knobs.withhold.delete("certificates");
    const r = await w.sync(b);
    expect(r.epoch).toBe("prepared");
    expect((await b.client.getState()).status).toBe("ready");
    expect(await thrown(() => b.client.enqueueLocation(w.loc(6)))).toBe("OK");
  });
});
