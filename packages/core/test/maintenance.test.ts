/** 0.4.0: a sync that leaves its housekeeping for later, and the timings every report carries. */
import { beforeAll, describe, expect, it } from "vitest";
import { ready } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { enqueueLocation } from "./location.js";
import { DAY, pair, world } from "./clientWorld.js";

beforeAll(() => ready());

describe("skipMaintenance", () => {
  it("leaves the purge and the periodic list re-check to a later sync, but still fetches a stale list", async () => {
    const w = world();
    const { a, b } = await pair(w);
    // Expired history: a record older than its kind's retention (kind 0 keeps a day in the test policy).
    await enqueueLocation(a.client, w.loc(5));
    await w.sync(a);
    await w.sync(b);
    w.clock.advance(2n * DAY);
    const skipped = await b.client.sync({ skipMaintenance: true });
    expect([skipped.maintenance, skipped.purged]).toEqual(["skipped", 0]);
    expect(await b.store.read((tx) => tx.count("history"))).toBeGreaterThan(0);
    // No periodic re-check of a fresh list while skipping; a stale list is fetched regardless.
    const listCalls = () => b.t.calls.filter((c) => c === "getResetKeyList").length;
    const before = listCalls();
    await b.client.sync({ skipMaintenance: true });
    expect(listCalls()).toBe(before); // a day and more has passed, but maintenance was skipped
    w.clock.advance(31n * DAY); // the list itself has expired: verification needs a new one
    w.host.resetKeyList = undefined;
    await b.client.sync({ skipMaintenance: true });
    expect(listCalls()).toBe(before + 1);
    // The next ordinary sync does the housekeeping.
    const done = await b.client.sync();
    expect([done.maintenance, done.purged > 0]).toEqual(["done", true]);
    expect(await b.store.read((tx) => tx.count("history"))).toBe(0);
  });

  it("syncUntilDrained passes the option through and reports it", async () => {
    const w = world();
    const { a } = await pair(w);
    const r = await a.client.syncUntilDrained({ skipMaintenance: true, maxRounds: 2 });
    expect(r.maintenance).toBe("skipped");
  });
});

describe("timings", () => {
  it("every report carries non-negative phase durations, a total, and the bytes moved", async () => {
    const w = world();
    const { a, b } = await pair(w);
    await enqueueLocation(a.client, w.loc(1));
    const sent = await w.sync(a);
    expect(sent.timings.bytesSent).toBeGreaterThan(100);
    const got = await w.sync(b);
    expect(got.timings.bytesReceived).toBe(sent.timings.bytesSent);
    for (const r of [sent, got]) {
      const t = r.timings;
      for (const k of ["resume", "bootstrap", "metadata", "preferences", "epoch", "outbox", "inbox", "maintenance", "total"] as const) expect(t[k]).toBeGreaterThanOrEqual(0);
      expect(t.total).toBeGreaterThanOrEqual(t.resume + t.bootstrap + t.metadata + t.preferences + t.epoch + t.outbox + t.inbox + t.maintenance - 1);
    }
    const drained = await b.client.syncUntilDrained({ maxRounds: 2 });
    expect(drained.timings.total).toBeGreaterThanOrEqual(0);
  });
});

describe("review of 0.4.0", () => {
  it("1: a throttled send reaches the report with its wait, and the record stays queued for the next sync", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    a.t.knobs.failWith.set("appendRecord", new KavachError("RATE_LIMITED", "transport", "429", { retryAfterMs: 5000 }));
    await enqueueLocation(a.client, w.loc(2)); // the handoff happens here and is refused
    const r = await w.sync(a);
    expect(r.errors.map((e) => [e.operation, e.code, e.retryable, e.retryAfterMs])).toEqual([["outbox", "RATE_LIMITED", true, 5000]]);
    expect([r.outbox.accepted, (await a.client.getState()).outbox]).toEqual([0, 1]);
    const next = await w.sync(a);
    expect([next.errors, next.outbox.accepted, (await a.client.getState()).outbox]).toEqual([[], 1, 0]);
    await w.sync(b);
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(2);
  });

  it("2: a download that fails on its second page still reports the first page's records and bytes", async () => {
    const w = world();
    const { a, b } = await pair(w);
    for (let i = 0; i < 150; i++) await enqueueLocation(a.client, w.loc(i % 90));
    await w.sync(a);
    b.t.knobs.failReadsAfter = 1;
    const r = await w.sync(b);
    expect(r.errors.map((e) => [e.operation, e.code])).toEqual([["inbox", "NETWORK"]]);
    expect([r.inbox.stored, r.timings.bytesReceived > 10_000]).toEqual([100, true]);
    const rest = await w.sync(b);
    expect([rest.errors, rest.inbox.stored]).toEqual([[], 50]);
  });
});

describe("RATE_LIMITED", () => {
  it("is a retryable code and carries the wait the host named", () => {
    const e = new KavachError("RATE_LIMITED", "transport", "429", { retryAfterMs: 4000 });
    expect([e.retryable, e.retryAfterMs, new KavachError("NETWORK").retryAfterMs]).toEqual([true, 4000, undefined]);
  });
});
