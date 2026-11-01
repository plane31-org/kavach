import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { createCircleSnapshot, newCircleId } from "../src/circle.js";
import { ready } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { drain, enqueue, outboxCount } from "../src/outbox.js";


import { t3ApplyChange } from "../src/transactions.js";
import { FakeHost } from "../src/testing/fakeHost.js";
import { Clock, setupDevice, type Device } from "./harness.js";
import { encodeLocation, locationFromDegrees } from "./location.js";

beforeAll(() => ready());

async function code(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "OK";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

const sample = (clock: Clock): Uint8Array => encodeLocation(locationFromDegrees(37.7749, -122.4194, 5, clock.now()));

/** Alice owns a circle with Bob; both know each other; Alice has an active epoch. */
async function pair(): Promise<{ host: FakeHost; clock: Clock; alice: Device; bob: Device; circleId: Uint8Array }> {
  const host = new FakeHost();
  const clock = new Clock();
  host.now = clock.now;
  const alice = await setupDevice(host, clock, "alice");
  const bob = await setupDevice(host, clock, "bob");
  await alice.know(bob);
  await bob.know(alice);
  const circleId = newCircleId();
  const genesis = createCircleSnapshot({ identityId: alice.pin.identityId, accountSecretKey: alice.account.account.secretKey }, circleId);
  await alice.transport.directory.publishOwnedCircle({ circleId, expectedRevision: 0n, expectedHash: undefined, newSnapshot: genesis });
  const { successorSnapshot } = await import("../src/circle.js");
  const state = await alice.joinLocally(circleId, alice.pin, genesis);
  const withBob = successorSnapshot(state, { admit: bob.pin.identityId }, { identityId: alice.pin.identityId, accountSecretKey: alice.account.account.secretKey });
  if (!withBob) throw new Error("successor");
  await alice.transport.directory.publishOwnedCircle({ circleId, expectedRevision: 1n, expectedHash: undefined, newSnapshot: withBob });
  await alice.joinLocally(circleId, alice.pin, withBob);
  await bob.joinLocally(circleId, alice.pin, withBob);
  await alice.rotate();
  return { host, clock, alice, bob, circleId };
}

describe("enqueue (T6)", () => {
  it("S03: nothing is sealed without a promoted epoch", async () => {
    const host = new FakeHost();
    const clock = new Clock();
    const alice = await setupDevice(host, clock, "alice");
    expect(await code(() => enqueue(alice.outbox, 0, sample(clock)))).toBe("ROTATION_REQUIRED");
    await alice.rotate();
    const q = await enqueue(alice.outbox, 0, sample(clock));
    expect(q.epoch).toBe(1);
    expect(q.counter).toBe(0);
  });

  it("S05 and S17: counters never repeat across a restart, and two unsent records are both durable", async () => {
    const { alice, clock } = await pair();
    const a = await enqueue(alice.outbox, 0, sample(clock));
    // A restart: another handle on the same durable state.
    const reopened = { ...alice.outbox, store: alice.store.fork() };
    const b = await enqueue(reopened, 1, sample(clock));
    expect([a.counter, b.counter]).toEqual([0, 1]);
    expect(await outboxCount(alice.store)).toBe(2);
    const rows = await alice.store.read((tx) => tx.list("outbox").map(([, r]) => [r.epoch, r.counter, r.kind]).sort((a, b) => (a[1] ?? 0) - (b[1] ?? 0)));
    expect(rows).toEqual([
      [1, 0, 0],
      [1, 1, 1]
    ]);
    // Own history is written in the same transaction.
    expect(await alice.store.read((tx) => tx.list("history").length)).toBe(2);
  });

  it("S06: a known change cancels queued rows, keeps history, and makes the next enqueue rotate", async () => {
    const { alice, clock } = await pair();
    await enqueue(alice.outbox, 0, sample(clock));
    await enqueue(alice.outbox, 0, sample(clock));
    const r = await alice.store.transaction((tx) => t3ApplyChange(tx, { kind: "disable", circleId: new Uint8Array(16) }));
    expect(r.cancelled.length).toBe(2);
    expect(await outboxCount(alice.store)).toBe(0);
    expect(await alice.store.read((tx) => tx.list("history").length)).toBe(2);
    expect(await code(() => enqueue(alice.outbox, 0, sample(clock)))).toBe("ROTATION_REQUIRED");
    await alice.rotate();
    expect((await enqueue(alice.outbox, 0, sample(clock))).epoch).toBe(2);
  });

  it("hygiene, clock reversal and the queue limit", async () => {
    const { alice, clock } = await pair();
    await enqueue(alice.outbox, 0, sample(clock));
    clock.advance(-10n);
    expect(await code(() => enqueue(alice.outbox, 0, sample(clock)))).toBe("ROTATION_REQUIRED");
    clock.advance(10n);
    await alice.rotate();
    clock.advance(31n * 86_400_000n);
    expect(await code(() => enqueue(alice.outbox, 0, sample(clock)))).toBe("ROTATION_REQUIRED");
    await alice.rotate();
    expect(await alice.store.read((tx) => tx.list("outbox").map(([, r]) => [r.epoch, r.counter, r.status]))).toEqual([[1, 0, "cancelled"]]);
    const small = { ...alice.outbox, policy: { ...alice.outbox.policy, maxOutboxRecords: 2 } };
    await enqueue(small, 0, sample(clock));
    await enqueue(small, 0, sample(clock));
    expect(await code(() => enqueue(small, 0, sample(clock)))).toBe("QUEUE_FULL");
  });
});

describe("the sender (T6h)", () => {
  it("drains in order, deletes accepted rows, and the relay holds the exact bytes", async () => {
    const { host, alice, clock } = await pair();
    const a = await enqueue(alice.outbox, 0, sample(clock));
    const b = await enqueue(alice.outbox, 1, sample(clock));
    const summary = await drain(alice.outbox);
    expect(summary).toMatchObject({ sent: 2, accepted: 2, cancelled: 0 });
    expect(await outboxCount(alice.store)).toBe(0);
    const s = host.streams.get(toHex(alice.pin.streamId));
    expect([...(s?.records.values() ?? [])].map((r) => r.recordId)).toEqual([toHex(a.recordId), toHex(b.recordId)]);
    expect(host.notifications.filter((n) => n.to === "bob").map((n) => n.kind)).toEqual(["wake", "visible"]);
  });

  it("a crash after T6 and before the send retries the exact wire", async () => {
    const { host, alice, clock } = await pair();
    const q = await enqueue(alice.outbox, 0, sample(clock));
    const wire = await alice.store.read((tx) => tx.get("outbox", toHex(q.recordId))?.wire);
    // Restart before any send: a new handle drains the persisted row.
    const reopened = { ...alice.outbox, store: alice.store.fork() };
    await drain(reopened);
    const s = host.streams.get(toHex(alice.pin.streamId));
    expect(toHex([...(s?.records.values() ?? [])][0]?.wire ?? new Uint8Array())).toBe(wire);
  });

  it("a lost response leaves the row queued, the retry gets the original outcome, and a changed audience cancels it instead", async () => {
    const { host, alice, clock } = await pair();
    await enqueue(alice.outbox, 0, sample(clock));
    host.dropAppendResponses = true;
    const first = await drain(alice.outbox);
    expect(first).toMatchObject({ sent: 1, retry: 1, accepted: 0 });
    expect(host.appendCalls).toBe(1);
    expect(await alice.store.read((tx) => tx.list("outbox")[0]?.[1].status)).toBe("queued");
    host.dropAppendResponses = false;
    // The relay accepted the first attempt; the identical retry is answered from the checkpoint.
    const second = await drain(alice.outbox);
    expect(second).toMatchObject({ sent: 1, accepted: 1 });
    expect(host.retainedCount(alice.pin.streamId)).toBe(1);
    // Now a row whose response was lost and whose audience then changed: cancelled, never resent.
    await enqueue(alice.outbox, 0, sample(clock));
    host.dropAppendResponses = true;
    await drain(alice.outbox);
    host.dropAppendResponses = false;
    const calls = host.appendCalls;
    await alice.store.transaction((tx) => t3ApplyChange(tx, { kind: "leave", circleId: new Uint8Array(16) }));
    const third = await drain(alice.outbox);
    expect(third.sent).toBe(0);
    expect(host.appendCalls).toBe(calls);
    expect(await alice.store.read((tx) => tx.list("outbox").map(([, r]) => r.status))).toEqual(["cancelled"]);
  });

  it("a synchronous transport failure rolls the in-flight mark back", async () => {
    const { host, alice, clock } = await pair();
    await enqueue(alice.outbox, 0, sample(clock));
    host.failAppends = true;
    const summary = await drain(alice.outbox);
    expect(summary).toMatchObject({ sent: 0, retry: 1 });
    expect(await alice.store.read((tx) => tx.list("outbox")[0]?.[1])).toMatchObject({ status: "queued", attempts: 1 });
    host.failAppends = false;
    expect((await drain(alice.outbox)).accepted).toBe(1);
  });

  it("STALE_APPEND is recorded as acceptance unknown with a request for a fresh location, and never re-creates a check-in", async () => {
    const { alice, clock } = await pair();
    const events: string[] = [];
    const deps = { ...alice.outbox, events: { refresh: (r: string) => events.push("refresh:" + r), cancelled: (_: Uint8Array, r: string) => events.push("cancelled:" + r) } };
    await enqueue(deps, 0, sample(clock));
    await enqueue(deps, 1, sample(clock));
    // The relay rule itself is covered by the fake host; here the client-side disposition is exercised
    // through the outcome recorder with two rows in flight.
    await alice.store.transaction((tx) => {
      for (const [k, r] of tx.list("outbox")) tx.put("outbox", k, { ...r, status: "inflight" });
    });
    const rows = (await alice.store.read((tx) => tx.list("outbox"))).sort(([, a], [, b]) => a.counter - b.counter);
    const { recordOutcomeForTest } = await import("./outboxInternals.js");
    const outcome = await recordOutcomeForTest(deps, rows[0]?.[0] ?? "", { status: "STALE_APPEND" });
    expect(outcome).toBe("unknown");
    const outcome2 = await recordOutcomeForTest(deps, rows[1]?.[0] ?? "", { status: "STALE_APPEND" });
    expect(outcome2).toBe("unknown");
    expect(events).toEqual(["cancelled:acceptanceUnknown", "refresh:acceptanceUnknown", "cancelled:acceptanceUnknown"]);
    expect(await alice.store.read((tx) => tx.list("outbox").map(([, r]) => r.status))).toEqual(["unknown", "unknown"]);
    expect(await alice.store.read((tx) => tx.list("history").length)).toBe(2);
  });

  it("the handoff race: a change in another context cannot slip between the check and the send", async () => {
    const { host, alice, clock } = await pair();
    await enqueue(alice.outbox, 0, sample(clock));
    const order: string[] = [];
    const slowRelay = {
      ...alice.transport.relay,
      appendRecord: (id: Uint8Array, wire: Uint8Array) => {
        order.push("send");
        return alice.transport.relay.appendRecord(id, wire);
      }
    };
    const other = alice.store.fork();
    // Start the drain, and in the same tick ask the background context to apply a change.
    const draining = drain({ ...alice.outbox, relay: slowRelay });
    const changing = other.transaction((tx) => {
      order.push("T3");
      return t3ApplyChange(tx, { kind: "disable", circleId: new Uint8Array(16) });
    });
    await Promise.all([draining, changing]);
    // Whichever ran first, the send never happened after a T3 that would have cancelled the row.
    if (order[0] === "send") expect(host.retainedCount(alice.pin.streamId)).toBe(1);
    else expect(host.retainedCount(alice.pin.streamId)).toBe(0);
    expect(order.length).toBe(2);
  });
});
