/**
 * Revision 13: an audience change holds queued records instead of cancelling them, and seals each
 * again under an epoch whose recipients could all read it before. A joiner never reads a record
 * from before it; a removed member never reads one sealed after; nothing is lost.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ready } from "../src/crypto.js";
import { testPolicy } from "../src/testing/clock.js";
import { world, type Dev, type World } from "./clientWorld.js";

beforeAll(() => ready());

/** Alice owns a circle; `names` join it; every device has synced fully. */
async function circle(w: World, names: string[]): Promise<{ a: Dev; members: Map<string, Dev>; circleId: Uint8Array; ids: Map<string, Uint8Array> }> {
  const a = await w.device("alice");
  await a.client.initializeAccount();
  const { circleId } = await a.client.circles.create();
  const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
  const ids = new Map<string, Uint8Array>([["alice", aliceId]]);
  const members = new Map<string, Dev>();
  for (const n of names) {
    const d = await w.device(n);
    await d.client.initializeAccount();
    ids.set(n, (await d.client.inspect()).identityId ?? new Uint8Array());
    await d.client.circles.requestJoin(circleId, aliceId);
    await w.sync(a);
    await a.client.circles.approve(circleId, n);
    members.set(n, d);
  }
  for (let i = 0; i < 2; i++) for (const d of [a, ...members.values()]) await w.sync(d);
  return { a, members, circleId, ids };
}

const fromBob = async (d: Dev, ids: Map<string, Uint8Array>): Promise<number[]> =>
  (await d.client.history({ authorIdentityId: ids.get("bob") ?? new Uint8Array() })).map((h) => h.plaintext[0] ?? -1).sort((x, y) => x - y);

/** Bob's own epochs, newest last: number, recipients, and whether it is a catch-up epoch. */
const epochsOf = (d: Dev) => d.store.read((tx) => tx.list("epochs").map(([, e]) => ({ epoch: e.epoch, recipients: e.audienceKey.split(",").length, catchUp: e.catchUpFor !== undefined })).sort((x, y) => x.epoch - y.epoch));
const newest = async (d: Dev): Promise<number> => Math.max(0, ...(await epochsOf(d)).map((e) => e.epoch));

describe("revision 13: queued records across an audience change", () => {
  it("a member who joins while records wait never reads them: a catch-up epoch carries them to the earlier audience, then the next one adds the joiner", async () => {
    const w = world();
    const { a, members, circleId, ids } = await circle(w, ["bob"]);
    const b = members.get("bob") as Dev;
    // Bob queues a backlog and does not sync (no signal); meanwhile Alice admits Carol.
    const queued = [await b.client.enqueue(0, Uint8Array.of(10)), await b.client.enqueue(1, Uint8Array.of(11)), await b.client.enqueue(0, Uint8Array.of(12))];
    const c = await w.device("carol");
    await c.client.initializeAccount();
    await c.client.circles.requestJoin(circleId, ids.get("alice") ?? new Uint8Array());
    await w.sync(a);
    await a.client.circles.approve(circleId, "carol");
    await w.sync(a);
    await w.sync(c);
    const n = b.events.length;
    const before = await newest(b);
    // Bob reconnects: the change holds the backlog, a catch-up epoch to Alice and Bob carries it, and
    // the epoch after it addresses Carol too.
    const r = await w.sync(b);
    expect(r.errors).toEqual([]);
    expect([r.outbox.resealed, r.outbox.accepted, r.outbox.cancelled]).toEqual([3, 3, 0]);
    expect(b.events.slice(n).filter((e) => e.kind === "cancelled")).toEqual([]);
    const epochs = (await epochsOf(b)).filter((e) => e.epoch > before);
    expect(epochs.map((e) => [e.recipients, e.catchUp])).toEqual([[2, true], [3, false]]); // the catch-up epoch, then the whole audience
    for (const q of queued) expect((await b.client.delivery(q.localId))?.status).toBe("accepted");
    expect(r.outbox.acceptedLocalIds.map(toHex).sort()).toEqual(queued.map((q) => toHex(q.localId)).sort());
    // Alice reads the backlog; Carol does not, but reads what Bob sends from now on.
    await w.sync(a);
    expect(await fromBob(a, ids)).toEqual(expect.arrayContaining([10, 11, 12]));
    await w.sync(c);
    expect(await fromBob(c, ids)).toEqual([]);
    await b.client.enqueue(1, Uint8Array.of(13));
    await w.sync(b);
    await w.sync(c);
    expect(await fromBob(c, ids)).toEqual([13]);
  });

  it("a member removed while records wait never reads them, and the backlog needs no extra epoch", async () => {
    const w = world();
    const { a, members, circleId, ids } = await circle(w, ["bob", "carol"]);
    const b = members.get("bob") as Dev;
    const c = members.get("carol") as Dev;
    const carolBefore = await fromBob(c, ids);
    const queued = [await b.client.enqueue(1, Uint8Array.of(20)), await b.client.enqueue(1, Uint8Array.of(21))];
    await a.client.circles.remove(circleId, ids.get("carol") ?? new Uint8Array());
    await w.sync(a);
    const before = await newest(b);
    const r = await w.sync(b);
    expect([r.outbox.resealed, r.outbox.accepted, r.outbox.cancelled]).toEqual([2, 2, 0]);
    expect((await epochsOf(b)).filter((e) => e.epoch > before).map((e) => [e.recipients, e.catchUp])).toEqual([[2, false]]); // one epoch, to Alice and Bob
    for (const q of queued) expect((await b.client.delivery(q.localId))?.status).toBe("accepted");
    await w.sync(a);
    expect(await fromBob(a, ids)).toEqual(expect.arrayContaining([20, 21]));
    await w.sync(c);
    expect(await fromBob(c, ids)).toEqual(carolBefore);
  });

  it("a hygiene rotation while records wait loses none of them", async () => {
    const w = world({ ...testPolicy, hygieneRotationMs: 3_600_000n });
    const { a, members, ids } = await circle(w, ["bob"]);
    const b = members.get("bob") as Dev;
    const queued = [await b.client.enqueue(1, Uint8Array.of(30)), await b.client.enqueue(1, Uint8Array.of(31))];
    w.clock.advance(2n * 3_600_000n); // the epoch's hygiene period has passed, the delivery window has not
    const late = await b.client.enqueue(1, Uint8Array.of(32)); // this enqueue retires the epoch and holds the two
    const r = await w.sync(b);
    expect([r.outbox.accepted, r.outbox.cancelled]).toEqual([3, 0]);
    for (const q of [...queued, late]) expect((await b.client.delivery(q.localId))?.status).toBe("accepted");
    await w.sync(a);
    expect(await fromBob(a, ids)).toEqual(expect.arrayContaining([30, 31, 32]));
  });

  it("a record enqueued while a catch-up epoch is active waits for the next epoch, so the joiner reads it and not the backlog", async () => {
    const w = world();
    const { a, members, circleId, ids } = await circle(w, ["bob"]);
    const b = members.get("bob") as Dev;
    await b.client.enqueue(1, Uint8Array.of(40));
    const c = await w.device("carol");
    await c.client.initializeAccount();
    await c.client.circles.requestJoin(circleId, ids.get("alice") ?? new Uint8Array());
    await w.sync(a);
    await a.client.circles.approve(circleId, "carol");
    await w.sync(a);
    await w.sync(c);
    // Bob's sync publishes the catch-up epoch, but its sends fail: it stays active.
    w.host.failAppends = true;
    await w.sync(b);
    expect((await epochsOf(b)).at(-1)?.catchUp).toBe(true);
    const fresh = await b.client.enqueue(1, Uint8Array.of(41));
    expect(fresh.recordId).toBeUndefined(); // not sealed to the catch-up audience
    w.host.failAppends = false;
    const r = await w.sync(b);
    expect([r.outbox.accepted, r.outbox.cancelled]).toEqual([2, 0]);
    await w.sync(c);
    expect(await fromBob(c, ids)).toEqual([41]);
    await w.sync(a);
    expect(await fromBob(a, ids)).toEqual(expect.arrayContaining([40, 41]));
  });

  it("a drain sends a record queued while it ran, and names it among those accepted", async () => {
    const w = world();
    const { members } = await circle(w, ["bob"]);
    const b = members.get("bob") as Dev;
    const relay = b.t.relay as { listSubscriptions: () => Promise<unknown> };
    const list = relay.listSubscriptions;
    let late: Uint8Array | undefined;
    relay.listSubscriptions = async () => {
      // After this round's outbox phase: a caller hands over a record and joins the running drain.
      if (!late) late = (await b.client.enqueue(1, Uint8Array.of(50))).localId;
      return list();
    };
    const report = await b.client.syncUntilDrained();
    relay.listSubscriptions = list;
    expect(report.stoppedBecause).toBe("drained");
    expect(report.outbox.acceptedLocalIds.map(toHex)).toContain(toHex(late ?? new Uint8Array()));
    expect((await b.client.delivery(late ?? new Uint8Array()))?.status).toBe("accepted");
  });

  it("a record whose send failed before a join, then fenced, goes out under a catch-up epoch: never held for good, never to the joiner", async () => {
    const w = world();
    const { a, members, circleId, ids } = await circle(w, ["bob"]);
    const b = members.get("bob") as Dev;
    const q = await b.client.enqueue(1, Uint8Array.of(60));
    w.host.failAppends = true; // the send fails: the record stays queued, handed off once
    await w.sync(b);
    w.host.failAppends = false;
    const c = await w.device("carol");
    await c.client.initializeAccount();
    await c.client.circles.requestJoin(circleId, ids.get("alice") ?? new Uint8Array());
    await w.sync(a);
    await a.client.circles.approve(circleId, "carol");
    await w.sync(a);
    await w.sync(c);
    // Bob's sync: the epoch with Carol goes live, the retried bytes are fenced and held, and the
    // same sync makes a catch-up epoch to Alice and Bob for them.
    const r = await b.client.syncUntilDrained();
    expect(r.stoppedBecause).toBe("drained");
    expect((await b.client.delivery(q.localId))?.status).toBe("accepted");
    expect(w.host.appendLog.some((l) => l.status === "EPOCH_FENCED")).toBe(true);
    expect((await epochsOf(b)).some((e) => e.catchUp && e.recipients === 2)).toBe(true);
    await w.sync(a);
    expect(await fromBob(a, ids)).toEqual(expect.arrayContaining([60]));
    await w.sync(c);
    expect(await fromBob(c, ids)).toEqual([]);
    await b.client.enqueue(1, Uint8Array.of(61));
    await w.sync(b);
    await w.sync(c);
    expect(await fromBob(c, ids)).toEqual([61]);
  });
});

