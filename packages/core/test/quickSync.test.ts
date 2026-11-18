/**
 * Revision 12: quick syncs over the host's change check, the AUDIENCE_STALE fence with hold and
 * reseal, and circles the host no longer serves. The first eight cases are the integrator's
 * conformance list; the last three cover what the design added to it.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ready } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { testPolicy } from "../src/testing/clock.js";
import type { RetentionPolicy } from "../src/policy.js";
import { DAY, thrown, world, type Dev, type World } from "./clientWorld.js";
import { enqueueLocation } from "./location.js";

beforeAll(() => ready());

const EVERY = Number(DAY);

/** The test profile plus a durable kind 3 with history and no slot: a trip, beside the checkpoint (0) and the check-in (1). */
const policy: RetentionPolicy = { ...testPolicy, kinds: [...testPolicy.kinds, { kind: 3, retentionMs: 86_400_000n, queue: "keepAll", history: true, newest: false, headerClass: 0 }] };

const METADATA = ["resolveAccounts", "resolveIdentities", "getCircle", "readRequests"];

/** Alice owns a circle; `names` join it; every device has synced fully, so each epoch addresses everyone. */
async function circle(w: World, names: string[]): Promise<{ a: Dev; members: Dev[]; circleId: Uint8Array; ids: Map<string, Uint8Array> }> {
  const a = await w.device("alice");
  await a.client.initializeAccount();
  const { circleId } = await a.client.circles.create();
  const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
  const ids = new Map<string, Uint8Array>([["alice", aliceId]]);
  const members: Dev[] = [];
  for (const n of names) {
    const d = await w.device(n);
    await d.client.initializeAccount();
    ids.set(n, (await d.client.inspect()).identityId ?? new Uint8Array());
    await d.client.circles.requestJoin(circleId, aliceId);
    await w.sync(a);
    await a.client.circles.approve(circleId, n);
    members.push(d);
  }
  for (let i = 0; i < 2; i++) for (const d of [a, ...members]) await w.sync(d);
  return { a, members, circleId, ids };
}

const quick = (d: Dev) => d.client.sync({ mode: "quick" });
const since = (d: Dev, n: number) => d.t.calls.slice(n);
const streamOf = async (d: Dev): Promise<string> => (await d.store.read((tx) => tx.get("self", "self")?.streamId)) ?? "";

describe("revision 12: quick sync", () => {
  it("1: a quick sync makes no metadata call; it asks the change check, not the subscription list", async () => {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    const { members } = await circle(w, ["bob"]);
    const b = members[0] as Dev;
    const n = b.t.calls.length;
    const r = await quick(b);
    expect([r.mode, r.promotedBecause, r.errors]).toEqual(["quick", undefined, []]);
    const calls = since(b, n);
    for (const m of METADATA) expect(calls, m).not.toContain(m);
    expect(calls).toContain("syncState");
    expect(calls).not.toContain("listSubscriptions");
  });

  it("2: a stream is read only when its head moved, the host holds something pending, a record is unresolved, or an ack is owed", async () => {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    const { a, members } = await circle(w, ["bob"]);
    const b = members[0] as Dev;
    const aliceStream = await streamOf(a);
    const reads = async (): Promise<number> => {
      const n = b.t.calls.length;
      const r = await quick(b);
      expect(r.errors).toEqual([]);
      return since(b, n).filter((c) => c === "readRecords").length;
    };
    // Nothing new: skipped.
    const idle = await quick(b);
    expect([idle.inbox.skipped, idle.inbox.streams]).toEqual([1, 0]);
    expect(await reads()).toBe(0);
    // The head moved: read, and the record lands.
    await enqueueLocation(a.client, w.loc(5));
    await w.sync(a);
    const moved = await quick(b);
    expect([moved.inbox.stored, moved.inbox.skipped]).toEqual([1, 0]);
    expect(await reads()).toBe(0);
    // The host holds something the head does not count.
    w.host.pendingStreams.add(aliceStream);
    expect(await reads()).toBe(1);
    w.host.pendingStreams.delete(aliceStream);
    expect(await reads()).toBe(0);
    // A record of the stream is unresolved here.
    const key = `${aliceStream}:${"1".padStart(20, "0")}`;
    await b.store.transaction((tx) => tx.put("unresolved", key, { streamId: aliceStream, deliverySeq: "1", reason: "KEY_PENDING", epoch: 1, recordedAt: "0" }));
    expect(await reads()).toBeGreaterThan(0);
    await b.store.transaction((tx) => tx.delete("unresolved", key));
    expect(await reads()).toBe(0);
    // An acknowledgement is owed: the eligible prefix is past the confirmed cursor.
    expect(BigInt((await b.store.read((tx) => tx.get("subscriptions", aliceStream)?.scanPos)) ?? "0")).toBeGreaterThan(0n);
    await b.store.transaction((tx) => {
      const sub = tx.get("subscriptions", aliceStream);
      if (sub) tx.put("subscriptions", aliceStream, { ...sub, ackPrefix: sub.scanPos, committedCursor: "0" });
    });
    expect(await reads()).toBe(1);
  });

  it("3: a quick sync runs full when work needs it, and the report says why", async () => {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    // A device that has never completed a full sync.
    const fresh = await w.device("dora");
    await fresh.client.initializeAccount();
    const first = await quick(fresh);
    expect([first.mode, first.promotedBecause]).toEqual(["full", "noFullSync"]);
    expect((await quick(fresh)).mode).toBe("quick");
    const { members } = await circle(w, ["bob"]);
    const b = members[0] as Dev;
    const promoted = async (): Promise<[string, string | undefined, boolean]> => {
      const n = b.t.calls.length;
      const r = await quick(b);
      return [r.mode, r.promotedBecause, since(b, n).includes("getCircle")];
    };
    // A chain verified only partly.
    await b.store.transaction((tx) => tx.put("chainProgress", "ab", { accountId: "ab", startIdentityId: "ab", links: [], nextGeneration: "2", complete: false }));
    expect(await promoted()).toEqual(["full", "chain", true]);
    await b.store.transaction((tx) => tx.delete("chainProgress", "ab"));
    // A refusal that needs the membership.
    await b.store.transaction((tx) => {
      const m = tx.get("meta", "meta");
      if (m) tx.put("meta", "meta", { ...m, fullSyncDue: true });
    });
    expect(await promoted()).toEqual(["full", "audienceStale", true]);
    expect(await promoted()).toEqual(["quick", undefined, false]); // the full sync answered it
    // The bound on quick syncs: past fullSyncEveryMs since the last full one.
    w.clock.advance(DAY);
    expect(await promoted()).toEqual(["full", "fullSyncEveryMs", true]);
    expect(await promoted()).toEqual(["quick", undefined, false]);
  });

  it("4: a change check that fails after the upload keeps the outbox report and leaves the drain incomplete; a missing endpoint is a mismatch, with no fallback", async () => {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    const { a } = await circle(w, ["bob"]);
    await a.client.enqueue(0, Uint8Array.of(1));
    a.t.knobs.failWith.set("syncState", new KavachError("NETWORK", "transport", "down"));
    const drained = await a.client.syncUntilDrained({ mode: "quick", maxRounds: 1 });
    expect(drained.outbox.accepted).toBe(1);
    expect(drained.errors.map((e) => `${e.operation}:${e.code}`)).toContain("listSubscriptions:NETWORK");
    expect([drained.stoppedBecause, drained.remaining.inboxHasMore]).toEqual(["incomplete", "unknown"]);
    // The host answers 404: UNSUPPORTED_OPERATION, and the subscription list is not asked instead.
    a.t.knobs.failWith.set("syncState", new KavachError("UNSUPPORTED_OPERATION", "transport", "404"));
    const n = a.t.calls.length;
    const r = await quick(a);
    expect(r.errors.map((e) => `${e.operation}:${e.code}`)).toEqual(["listSubscriptions:UNSUPPORTED_OPERATION"]);
    expect(since(a, n)).not.toContain("listSubscriptions");
    // A transport without the method, or an open() without the bound, is refused before anything runs.
    expect(await thrown(() => world(policy).device("erin").then((d) => d.client.sync({ mode: "quick" })))).toBe("MALFORMED");
    delete (a.t.relay as { syncState?: unknown }).syncState;
    expect(await thrown(() => quick(a))).toBe("UNSUPPORTED_OPERATION");
  });

  it("5: a full sync never calls the change check", async () => {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    const { a, members } = await circle(w, ["bob"]);
    const before = w.host.syncStateCalls;
    for (const d of [a, ...members]) {
      const n = d.t.calls.length;
      const r = await d.client.sync();
      expect(r.mode).toBe("full");
      expect(since(d, n)).toContain("listSubscriptions");
      expect(since(d, n)).not.toContain("syncState");
    }
    expect(w.host.syncStateCalls).toBe(before);
  });
});

describe("revision 12: the AUDIENCE_STALE fence", () => {
  /** Alice removes Carol; Bob, on quick syncs, still seals to her; the host fences his appends. */
  async function staleBob() {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    const { a, members, circleId, ids } = await circle(w, ["bob", "carol"]);
    const [b, c] = members as [Dev, Dev];
    await a.client.circles.remove(circleId, ids.get("carol") ?? new Uint8Array());
    await w.sync(a);
    w.host.audienceFence = true;
    return { w, a, b, c, circleId, ids };
  }

  it("6: a checkpoint, a trip and a check-in refused as AUDIENCE_STALE are held, not cancelled, then resealed once and accepted after the rotation", async () => {
    const { w, a, b, c, ids } = await staleBob();
    const sent = [await b.client.enqueue(0, Uint8Array.of(10)), await b.client.enqueue(3, Uint8Array.of(30)), await b.client.enqueue(1, Uint8Array.of(11))];
    const n = b.events.length;
    const first = await quick(b);
    expect([first.mode, first.outbox.accepted, first.outbox.held, first.outbox.cancelled]).toEqual(["quick", 0, 3, 0]);
    expect(b.events.slice(n).filter((e) => e.kind === "cancelled")).toEqual([]);
    expect(b.events.slice(n).find((e) => e.kind === "audienceStale")).toEqual({ kind: "audienceStale", held: 3 });
    expect((await b.client.inspect()).outbox.held).toBe(3);
    expect(await thrown(() => b.client.enqueue(0, Uint8Array.of(12)))).toBe("ROTATION_REQUIRED"); // the refused epoch takes nothing more
    // The next sync runs full, learns the removal, rotates without Carol and reseals the three.
    const second = await quick(b);
    expect([second.mode, second.promotedBecause]).toEqual(["full", "audienceStale"]);
    expect([second.outbox.resealed, second.outbox.accepted, second.outbox.held, second.outbox.cancelled]).toEqual([3, 3, 0, 0]);
    const resealed = b.events.slice(n).filter((e) => e.kind === "resealed");
    expect(resealed.map((e) => (e.kind === "resealed" ? toHex(e.recordId) : ""))).toEqual(sent.map((s) => toHex(s.recordId)));
    // Alice reads all three, under the new ids; Carol, removed, reads none of them.
    await w.sync(a);
    const fromBob = (await a.client.history({ authorIdentityId: ids.get("bob") ?? new Uint8Array() })).map((h) => [h.kind, h.plaintext[0]]);
    expect(fromBob).toEqual(expect.arrayContaining([[0, 10], [3, 30], [1, 11]]));
    const carolBefore = (await c.client.history({ authorIdentityId: ids.get("bob") ?? new Uint8Array() })).length;
    await w.sync(c);
    expect((await c.client.history({ authorIdentityId: ids.get("bob") ?? new Uint8Array() })).length).toBe(carolBefore);
    expect(w.host.appendLog.filter((l) => l.status === "AUDIENCE_STALE").length).toBe(1);
  });

  it("7: a record refused again after its reseal is cancelled once, with reason AUDIENCE_STALE", async () => {
    const { w, b, circleId } = await staleBob();
    // The host keeps the removal from Bob's full sync too: he rotates to the same audience.
    const lastSeen = await b.store.read((tx) => tx.get("circles", toHex(circleId))?.snapshot ?? "");
    b.t.knobs.replay.snapshots.set(toHex(circleId), Uint8Array.from(Buffer.from(lastSeen, "hex")));
    await b.client.enqueue(0, Uint8Array.of(10));
    await b.client.enqueue(1, Uint8Array.of(11));
    const n = b.events.length;
    expect((await quick(b)).outbox.held).toBe(2);
    const second = await quick(b);
    expect([second.outbox.resealed, second.outbox.accepted, second.outbox.cancelled]).toEqual([2, 0, 2]);
    const cancelled = b.events.slice(n).filter((e) => e.kind === "cancelled");
    expect(cancelled.map((e) => (e.kind === "cancelled" ? e.reason : ""))).toEqual(["AUDIENCE_STALE", "AUDIENCE_STALE"]);
    expect(b.events.slice(n).some((e) => e.kind === "refresh" && e.reason === "AUDIENCE_STALE")).toBe(true); // kind 0 keeps a slot
    // Nothing is held any more, and a third sync cancels nothing twice.
    const third = await w.sync(b);
    expect([third.outbox.held, third.outbox.cancelled]).toEqual([0, 0]);
    expect((await b.client.inspect()).outbox.held).toBe(0);
  });

  it("8: a circle the host answers it has none of is retired; a failed request keeps the cached state", async () => {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    const { members, circleId } = await circle(w, ["bob"]);
    const b = members[0] as Dev;
    const epochBefore = (await b.client.inspect()).activeEpoch ?? 0;
    b.t.knobs.failWith.set("getCircle", new KavachError("NETWORK", "transport", "down"));
    const failed = await b.client.sync();
    expect(failed.errors.length).toBeGreaterThan(0);
    expect((await b.client.circles.list())[0]?.status).toBe("member");
    b.t.knobs.withhold.add("snapshots");
    const n = b.events.length;
    const gone = await b.client.sync();
    expect((await b.client.circles.list())[0]?.status).toBe("gone");
    expect(gone.metadata.rotations).toBe(1);
    expect(b.events.slice(n).some((e) => e.kind === "circleChanged" && toHex(e.circleId) === toHex(circleId) && e.status === "gone")).toBe(true);
    // Bob's next epoch addresses nobody but himself.
    await b.client.sync();
    const bobStream = [...w.host.streams.values()].find((s) => s.accountName === "bob");
    expect(bobStream?.currentEpoch).toBeGreaterThan(epochBefore);
    expect(bobStream?.epochs.get(bobStream.currentEpoch)?.rows.length).toBe(1);
  });
});

describe("revision 12: what the design added", () => {
  it("a reseal moves the record's id everywhere the app could hold it: the idempotency key, the own history row, the event", async () => {
    const { w, b, ids } = await (async () => {
      const w = world(policy, { fullSyncEveryMs: EVERY });
      const { a, members, circleId, ids } = await circle(w, ["bob", "carol"]);
      await a.client.circles.remove(circleId, ids.get("carol") ?? new Uint8Array());
      await w.sync(a);
      w.host.audienceFence = true;
      return { w, b: members[0] as Dev, ids };
    })();
    const first = await b.client.enqueue(3, Uint8Array.of(30), { idempotencyKey: "trip-1" });
    await quick(b);
    await quick(b);
    const moved = b.events.find((e) => e.kind === "resealed");
    if (moved?.kind !== "resealed") throw new Error("not resealed");
    expect(toHex(moved.recordId)).toBe(toHex(first.recordId));
    const again = await b.client.enqueue(3, Uint8Array.of(30), { idempotencyKey: "trip-1" });
    expect([again.duplicate, toHex(again.recordId)]).toEqual([true, toHex(moved.newRecordId)]);
    const own = (await b.client.history({ authorIdentityId: ids.get("bob") ?? new Uint8Array() })).map((h) => toHex(h.recordId));
    expect(own).toContain(toHex(moved.newRecordId));
    expect(own).not.toContain(toHex(first.recordId));
    expect(b.events.some((e) => e.kind === "accepted" && toHex(e.recordId) === toHex(moved.newRecordId))).toBe(true);
    void w;
  });

  it("a gone circle comes back when the host serves its signed snapshot again", async () => {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    const { members } = await circle(w, ["bob"]);
    const b = members[0] as Dev;
    b.t.knobs.withhold.add("snapshots");
    await b.client.sync();
    expect((await b.client.circles.list())[0]?.status).toBe("gone");
    b.t.knobs.withhold.delete("snapshots");
    const back = await b.client.sync();
    expect((await b.client.circles.list())[0]?.status).toBe("member");
    expect(back.metadata.rotations).toBe(1);
    await b.client.sync();
    const bobStream = [...w.host.streams.values()].find((s) => s.accountName === "bob");
    expect(bobStream?.epochs.get(bobStream.currentEpoch)?.rows.length).toBe(2);
  });

  it("quick syncs alone never outlast fullSyncEveryMs, and a removal is learned at the next full one", async () => {
    const w = world(policy, { fullSyncEveryMs: EVERY });
    const { a, members, circleId, ids } = await circle(w, ["bob", "carol"]);
    const b = members[0] as Dev;
    await a.client.circles.remove(circleId, ids.get("carol") ?? new Uint8Array());
    await w.sync(a);
    w.clock.advance(DAY / 2n);
    expect((await quick(b)).mode).toBe("quick");
    expect((await b.client.circles.list())[0]?.members.length).toBe(3); // not learned yet
    w.clock.advance(DAY / 2n);
    const r = await quick(b);
    expect([r.mode, r.promotedBecause]).toEqual(["full", "fullSyncEveryMs"]);
    expect((await b.client.circles.list())[0]?.members.length).toBe(2);
  });
});
