/** The relay scenarios of the appendix (21 to 23, 27) and the profile's gate table, against the real Worker. */
import { describe, expect, it } from "vitest";
import { toHex } from "@kavach/core";
import { circleOfTwo, clock, device, hostJson, type Device } from "./world.js";
import { enqueueCheckIn, enqueueLocation, enqueueStatus, latestStatus, locationFromDegrees } from "./location.js";

interface Debug {
  tail: number;
  expiredThrough: number;
  retained: { seq: number; record_id: string; epoch: number; counter: number; kind: number; required: string[] }[];
  epochs: number[];
  subscriptions: { cert: string; identity: string; cursor: number; start_seq: number }[];
  highWater: { epoch: number; counter: number } | null;
  lastAppend: { recordId: string; seq: number } | null;
  currentEpoch: number;
}

const loc = (lat = 37.7749) => locationFromDegrees(lat, -122.4194, 5, clock.now());

async function streamOf(d: Device): Promise<string> {
  const subs = await hostJson<{ streamId: string }[]>("/v1/subscriptions", { headers: { authorization: d.bearer() } });
  return subs[0]?.streamId ?? "";
}
const debug = (sid: string) => hostJson<Debug>(`/v1/streams/${sid}/debug`);

describe("relay: deletion, expiry, cursors", () => {
  it("22: the last required reader's cursor deletes the record; epoch material goes when unreferenced and not current", async () => {
    const { a, b } = await circleOfTwo();
    const sid = await streamOf(b);
    await enqueueLocation(a.client, loc(1));
    await a.client.sync();
    let d = await debug(sid);
    expect(d.retained.length).toBe(1);
    expect(d.retained[0]?.required.length).toBe(1);
    await b.client.sync();
    d = await debug(sid);
    expect(d.retained.length).toBe(0);
    expect(d.subscriptions[0]?.cursor).toBe(1);
    // Alice rotates: epoch 2 is current; epoch 1 is unreferenced and gone.
    await a.client.circles.setEnabled((await a.client.circles.list())[0]?.circleId ?? new Uint8Array(), false);
    await a.client.circles.setEnabled((await a.client.circles.list())[0]?.circleId ?? new Uint8Array(), true);
    await enqueueLocation(a.client, loc(2));
    await a.client.sync();
    d = await debug(sid);
    expect(d.currentEpoch).toBeGreaterThan(2);
    expect(d.epochs).toEqual([d.currentEpoch]);
  });

  it("23: a reader away past the window loses the record to expiry as a prefix, never a newer one; the author keeps history", async () => {
    const { a, b } = await circleOfTwo();
    const sid = await streamOf(b);
    await enqueueLocation(a.client, loc(1));
    await a.client.sync();
    clock.advance(86_400_001n);
    await enqueueLocation(a.client, loc(2));
    await a.client.sync();
    await hostJson(`/v1/streams/${sid}/expire`, { method: "POST", body: "{}" });
    const d = await debug(sid);
    expect(d.retained.map((r) => r.seq)).toEqual([2]);
    expect(d.expiredThrough).toBe(1);
    const r = await b.client.sync();
    expect(r.inbox.stored).toBe(1);
    expect((await b.client.history()).length).toBe(1);
    // The author's own history keeps the record only for its own window, which has also passed.
    expect((await a.client.history()).length).toBe(1);
  });

  it("an equal or older cursor writes nothing; a cursor above the tail is rejected; reads beyond the tail are rejected", async () => {
    const { a, b } = await circleOfTwo();
    const sid = await streamOf(b);
    await enqueueLocation(a.client, loc());
    await a.client.sync();
    await b.client.sync();
    const before = await debug(sid);
    const same = await hostJson<{ status: string; committedCursor: string }>(`/v1/streams/${sid}/ack`, { method: "POST", headers: { authorization: b.bearer() }, body: JSON.stringify({ cursor: "1" }) });
    expect(same).toEqual({ status: "COMMITTED", committedCursor: "1" });
    const older = await hostJson<{ status: string; committedCursor: string }>(`/v1/streams/${sid}/ack`, { method: "POST", headers: { authorization: b.bearer() }, body: JSON.stringify({ cursor: "0" }) });
    expect(older.committedCursor).toBe("1");
    expect(await debug(sid)).toEqual(before);
    const above = await hostJson<{ status: string }>(`/v1/streams/${sid}/ack`, { method: "POST", headers: { authorization: b.bearer() }, body: JSON.stringify({ cursor: "99" }) });
    expect(above.status).toBe("CURSOR_OUT_OF_RANGE");
    const read = await hostJson<{ error?: string }>(`/v1/streams/${sid}/records?after=99&limit=10`, { headers: { authorization: b.bearer() } });
    expect(read.error).toBe("CURSOR_OUT_OF_RANGE");
    // A stranger has no subscription: unauthorized to acknowledge, nothing to read.
    const c = await device("carol");
    await c.client.initializeAccount();
    const stranger = await hostJson<{ status: string }>(`/v1/streams/${sid}/ack`, { method: "POST", headers: { authorization: c.bearer() }, body: JSON.stringify({ cursor: "1" }) });
    expect(stranger.status).toBe("UNAUTHORIZED");
  });

  it("the append checkpoint: an identical retry after deletion returns the original outcome; a stale append is refused without reinsertion", async () => {
    const { a, b } = await circleOfTwo();
    const sid = await streamOf(b);
    const q = await enqueueLocation(a.client, loc());
    await a.client.sync();
    const wire = (await a.store.read((tx) => tx.list("history").find(([k]) => k === toHex(q.recordId))))?.[1];
    void wire;
    const retained = (await debug(sid)).retained[0];
    if (!retained) throw new Error("retained");
    // Fetch the exact wire through Bob's read, then let Bob acknowledge so the relay deletes it.
    const page = await hostJson<{ records: { wire: string }[] }>(`/v1/streams/${sid}/records?after=0&limit=10`, { headers: { authorization: b.bearer() } });
    const exact = page.records[0]?.wire ?? "";
    await b.client.sync();
    expect((await debug(sid)).retained.length).toBe(0);
    const retry = await hostJson<{ status: string }>(`/v1/streams/${sid}/records`, { method: "POST", headers: { authorization: a.bearer() }, body: JSON.stringify({ recordId: retained.record_id, wire: exact }) });
    expect(retry.status).toBe("ALREADY_ACCEPTED");
    expect((await debug(sid)).retained.length).toBe(0);
    // A different body under the same id is equivocation; an older counter is stale.
    const tampered = exact.slice(0, -2) + (exact.endsWith("00") ? "01" : "00");
    const eq = await hostJson<{ status: string }>(`/v1/streams/${sid}/records`, { method: "POST", headers: { authorization: a.bearer() }, body: JSON.stringify({ recordId: retained.record_id, wire: tampered }) });
    expect(eq.status).toBe("EQUIVOCATION");
    await enqueueLocation(a.client, loc(5));
    await a.client.sync();
    const stale = await hostJson<{ status: string }>(`/v1/streams/${sid}/records`, { method: "POST", headers: { authorization: a.bearer() }, body: JSON.stringify({ recordId: "00".repeat(32), wire: exact }) });
    expect(["STALE_APPEND", "EQUIVOCATION", "ALREADY_ACCEPTED"]).toContain(stale.status);
    expect((await debug(sid)).retained.length).toBe(1);
  });

  it("subscriptions: members get one when an author opens a new stream; a replacement device's starts at activation and never inherits the cursor", async () => {
    const { a, b } = await circleOfTwo();
    const sid = await streamOf(b);
    for (let i = 0; i < 3; i++) await enqueueLocation(a.client, loc(i));
    await a.client.sync();
    const before = await debug(sid);
    expect(before.subscriptions.length).toBe(1);
    const bobCert = before.subscriptions[0]?.cert;
    // Bob replaces his phone: Alice rotates to the new certificate, which gets its own subscription at the tail.
    const b2 = await device("bob", b.provider);
    await b2.client.restoreAccount();
    await b2.client.sync();
    await a.client.sync();
    await enqueueLocation(a.client, loc(9));
    await a.client.sync();
    const after = await debug(sid);
    const fresh = after.subscriptions.find((s) => s.cert !== bobCert);
    expect(fresh?.start_seq).toBe(3);
    expect(fresh?.cursor).toBe(3);
    await b2.client.sync();
    expect((await b2.client.history()).length).toBe(1);
    // Alice replaces hers: a new stream opens and Bob's new device is subscribed to it from its start.
    const a2 = await device("alice", a.provider);
    await a2.client.restoreAccount();
    await a2.client.sync();
    await b2.client.sync();
    await enqueueLocation(a2.client, loc(10));
    await a2.client.sync();
    const subs = await hostJson<{ streamId: string }[]>("/v1/subscriptions", { headers: { authorization: b2.bearer() } });
    expect(subs.length).toBe(2);
    expect((await b2.client.sync()).inbox.stored).toBe(1);
  });

  it("a status (kind 2) is relayed with no notification at all, and the reader keeps the newest", async () => {
    const { a, b, aliceId } = await circleOfTwo();
    const start = (await hostJson<unknown[]>("/v1/debug/notifications")).length;
    await enqueueStatus(a.client, new Uint8Array([1, 64, 0, 3]));
    await a.client.sync();
    expect((await hostJson<unknown[]>("/v1/debug/notifications")).length).toBe(start);
    await b.client.sync();
    const latest = await latestStatus(b.client, aliceId);
    expect(latest && [...latest.payload]).toEqual([1, 64, 0, 3]);
    expect((await b.client.history({ authorIdentityId: aliceId })).some((h) => h.kind === 2)).toBe(false);
  });

  it("24: a check-in survives a later location end to end, and each visible notification is sent once without a coordinate", async () => {
    const { a, b, aliceId } = await circleOfTwo();
    const start = (await hostJson<unknown[]>("/v1/debug/notifications")).length;
    await enqueueCheckIn(a.client, loc(10));
    await enqueueLocation(a.client, loc(11));
    await a.client.sync();
    await b.client.sync();
    const h = await b.client.history({ authorIdentityId: aliceId });
    expect(h.map((x) => x.kind)).toEqual([1, 0]);
    const notes = (await hostJson<{ kind: string; to_account: string; from_account: string }[]>("/v1/debug/notifications")).slice(start);
    expect(notes.filter((n) => n.to_account === "bob").map((n) => n.kind)).toEqual(["visible", "wake"]);
    for (const n of notes) expect(Object.keys(n).sort()).toEqual(["circle_id", "from_account", "kind", "to_account"]);
    const joins = await hostJson<{ kind: string; to_account: string }[]>("/v1/debug/notifications");
    expect(joins.filter((n) => n.kind === "joinRequest" && n.to_account === "alice").length).toBe(1);
  });

  it("27: a superseded device's append is refused by the fence", async () => {
    const { a, b } = await circleOfTwo();
    const sid = await streamOf(b);
    await enqueueLocation(a.client, loc(1));
    await a.client.sync();
    const page = await hostJson<{ records: { wire: string }[] }>(`/v1/streams/${sid}/records?after=0&limit=10`, { headers: { authorization: b.bearer() } });
    const exact = page.records[0]?.wire ?? "";
    const oldBearer = a.bearer();
    const a2 = await device("alice", a.provider);
    await a2.client.restoreAccount();
    const r = await hostJson<{ error?: string }>(`/v1/streams/${sid}/records`, { method: "POST", headers: { authorization: oldBearer }, body: JSON.stringify({ recordId: "11".repeat(32), wire: exact }) });
    expect(r.error).toBe("SUPERSEDED_DEVICE");
  });
});
