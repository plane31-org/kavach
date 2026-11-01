/** Statuses (kind 2): latest wins in the outbox, newest per author on the reader, no pin, no history, no notification. */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ready } from "../src/crypto.js";
import { pair, world } from "./clientWorld.js";
import { enqueueCheckIn, enqueueStatus, latest, latestStatus } from "./location.js";

beforeAll(() => ready());

const status = (battery: number, flags = 0, permission = 3): Uint8Array => new Uint8Array([1, battery, flags, permission]);

describe("status records", () => {
  it("latest wins while queued: an older status is cancelled as superseded and never sent, a queued check-in stays", async () => {
    const w = world();
    const { a } = await pair(w);
    const first = await enqueueStatus(a.client, status(80));
    const checkIn = await enqueueCheckIn(a.client, w.loc(5));
    const second = await enqueueStatus(a.client, status(75));
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
    const pinBefore = await latest(b.client, aliceId);
    const historyBefore = (await b.client.history({ authorIdentityId: aliceId })).length;
    const notesBefore = w.host.notifications.length;
    await enqueueStatus(a.client, status(60, 0b0001));
    await w.sync(a);
    expect(w.host.notifications.length).toBe(notesBefore);
    const events = b.events.length;
    const r = await w.sync(b);
    expect(r.inbox.stored).toBe(1);
    const current = await latestStatus(b.client, aliceId);
    expect(current && toHex(current.payload)).toBe(toHex(status(60, 0b0001)));
    expect(current?.ageMs).toBeGreaterThanOrEqual(0n);
    expect(b.events.slice(events).filter((e) => e.kind === "recordStored" && e.recordKind === 2 && e.tookSlot).length).toBe(1);
    expect(b.events.slice(events).some((e) => e.kind === "recordStored" && e.recordKind !== 2)).toBe(false);
    expect(toHex((await latest(b.client, aliceId))?.recordId ?? new Uint8Array())).toBe(toHex(pinBefore?.recordId ?? new Uint8Array()));
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(historyBefore);
    // A newer status replaces the row in place; a replay of it changes nothing.
    await enqueueStatus(a.client, status(55));
    await w.sync(a);
    await w.sync(b);
    expect(toHex((await latestStatus(b.client, aliceId))?.payload ?? new Uint8Array())).toBe(toHex(status(55)));
    expect(await b.store.read((tx) => tx.list("newest").filter(([k]) => k.endsWith(":2")).length)).toBe(1);
    expect((await w.sync(b)).inbox.stored).toBe(0);
  });

  it("a status expires with the location window: the payload goes, the slot stays, and an older status cannot become current", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    await enqueueStatus(a.client, status(50));
    await w.sync(a);
    await w.sync(b);
    const kept = await b.store.read((tx) => tx.get("newest", toHex(aliceId) + ":2"));
    w.clock.advance(86_400_000n + 1n);
    const r = await w.sync(b);
    expect(r.purged).toBeGreaterThanOrEqual(1);
    expect(await latestStatus(b.client, aliceId)).toBeUndefined();
    const after = await b.store.read((tx) => tx.get("newest", toHex(aliceId) + ":2"));
    expect([after?.payload, after?.recordId, after?.epoch, after?.counter]).toEqual([null, kept?.recordId, kept?.epoch, kept?.counter]);
    // A fresh status is current again.
    await enqueueStatus(a.client, status(45));
    await w.sync(a);
    await w.sync(b);
    expect(toHex((await latestStatus(b.client, aliceId))?.payload ?? new Uint8Array())).toBe(toHex(status(45)));
  });

  it("an empty payload is a status like any other: current until it expires, never mistaken for an expired one", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    await enqueueStatus(a.client, new Uint8Array());
    await w.sync(a);
    const events = b.events.length;
    await w.sync(b);
    expect(b.events.slice(events).filter((e) => e.kind === "recordStored" && e.recordKind === 2 && e.tookSlot).length).toBe(1);
    const current = await latestStatus(b.client, aliceId);
    expect(current?.payload.length).toBe(0);
    expect((await b.store.read((tx) => tx.get("newest", toHex(aliceId) + ":2")))?.payload).toBe("");
    w.clock.advance(86_400_000n + 1n);
    await w.sync(b);
    expect(await latestStatus(b.client, aliceId)).toBeUndefined();
    expect((await b.store.read((tx) => tx.get("newest", toHex(aliceId) + ":2")))?.payload).toBeNull();
  });

  it("an author who leaves takes their status with them", async () => {
    const w = world();
    const { a, b, aliceId, bobId, circleId } = await pair(w);
    await enqueueStatus(b.client, status(40));
    await w.sync(b);
    await w.sync(a);
    expect(await latestStatus(a.client, bobId)).toBeDefined();
    await a.client.circles.remove(circleId, bobId);
    await w.sync(a);
    expect(await latestStatus(a.client, bobId)).toBeUndefined();
    void aliceId;
  });
});
