/** Statuses (kind 2): latest wins in the outbox, newest per author on the reader, no pin, no history, no notification. */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ready } from "../src/crypto.js";
import { pair, world } from "./clientWorld.js";

beforeAll(() => ready());

const status = (battery: number, flags = 0, permission = 3): Uint8Array => new Uint8Array([1, battery, flags, permission]);

describe("status records", () => {
  it("latest wins while queued: an older status is cancelled as superseded and never sent, a queued check-in stays", async () => {
    const w = world();
    const { a } = await pair(w);
    const first = await a.client.enqueueStatus(status(80));
    const checkIn = await a.client.enqueueCheckIn(w.loc(5));
    const second = await a.client.enqueueStatus(status(75));
    const rows = await a.store.read((tx) => new Map(tx.list("outbox").map(([k, r]) => [k, r])));
    expect([rows.get(toHex(first.recordId))?.status, rows.get(toHex(first.recordId))?.reason, rows.get(toHex(first.recordId))?.wire]).toEqual(["cancelled", "superseded", ""]);
    expect([rows.get(toHex(checkIn.recordId))?.status, rows.get(toHex(second.recordId))?.status]).toEqual(["queued", "queued"]);
    expect(a.events.some((e) => e.kind === "cancelled" && toHex(e.recordId) === toHex(first.recordId) && e.reason === "superseded")).toBe(true);
    // A status writes no history row, on the sender either.
    expect((await a.client.history({ authorIdentityId: (await a.client.inspect()).identityId })).map((h) => h.kind)).not.toContain(2);
    const r = await w.sync(a);
    expect([r.outbox.sent, r.outbox.accepted]).toEqual([2, 2]);
  });

  it("the reader keeps the newest status per author, moves no pin, counts no check-in, keeps no history and gets no notification", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    const pinBefore = await b.client.latest(aliceId);
    const historyBefore = (await b.client.history({ authorIdentityId: aliceId })).length;
    const notesBefore = w.host.notifications.length;
    await a.client.enqueueStatus(status(60, 0b0001));
    await w.sync(a);
    expect(w.host.notifications.length).toBe(notesBefore);
    const events = b.events.length;
    const r = await w.sync(b);
    expect(r.inbox.stored).toBe(1);
    const latest = await b.client.latestStatus(aliceId);
    expect(latest && toHex(latest.payload)).toBe(toHex(status(60, 0b0001)));
    expect(latest?.ageMs).toBeGreaterThanOrEqual(0n);
    expect(b.events.slice(events).filter((e) => e.kind === "statusUpdated").length).toBe(1);
    expect(b.events.slice(events).some((e) => e.kind === "checkIn" || e.kind === "latestUpdated")).toBe(false);
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(toHex(pinBefore?.recordId ?? new Uint8Array()));
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(historyBefore);
    // A newer status replaces the row in place; a replay of it changes nothing.
    await a.client.enqueueStatus(status(55));
    await w.sync(a);
    await w.sync(b);
    expect(toHex((await b.client.latestStatus(aliceId))?.payload ?? new Uint8Array())).toBe(toHex(status(55)));
    expect(await b.store.read((tx) => tx.count("statuses"))).toBe(1);
    expect((await w.sync(b)).inbox.stored).toBe(0);
  });

  it("an author who leaves takes their status with them", async () => {
    const w = world();
    const { a, b, aliceId, bobId, circleId } = await pair(w);
    await b.client.enqueueStatus(status(40));
    await w.sync(b);
    await w.sync(a);
    expect(await a.client.latestStatus(bobId)).toBeDefined();
    await a.client.circles.remove(circleId, bobId);
    await w.sync(a);
    expect(await a.client.latestStatus(bobId)).toBeUndefined();
    void aliceId;
  });
});
