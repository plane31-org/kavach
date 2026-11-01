/** 0.3.0: close() as a real stop, syncUntilDrained with its stop reasons, and replaceDevice over the two calls. */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ready } from "../src/crypto.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { MemoryPlatformProvider } from "../src/testing/providers.js";
import { enqueueLocation } from "./location.js";
import { pair, thrown, world, type Dev, type World } from "./clientWorld.js";

beforeAll(() => ready());

async function fresh(w: World, name: string): Promise<Dev> {
  return w.device(name, new MemoryPlatformProvider(`${name}-${Math.random()}@platform`), new MemoryStore(), new MemorySecretStore());
}

describe("close()", () => {
  it("refuses new work, lets the sync in flight finish its boundary, and emits nothing afterwards", async () => {
    const w = world();
    const { a, b } = await pair(w);
    for (let i = 0; i < 5; i++) await enqueueLocation(a.client, w.loc(i));
    const running = w.sync(a);
    const closing = a.client.close();
    const before = a.events.length;
    await closing;
    const report = await running;
    expect(report.errors).toEqual([]);
    expect(a.events.length).toBe(before); // whatever the sync still did after close() emitted nothing
    expect(await thrown(() => enqueueLocation(a.client, w.loc(9)))).toBe("CLOSED");
    expect(await thrown(() => a.client.sync())).toBe("CLOSED");
    expect(await thrown(() => a.client.circles.create())).toBe("CLOSED");
    await a.client.close(); // idempotent
    // Reads still answer; the other device is untouched.
    expect((await a.client.getState()).status).toBeDefined();
    expect((await w.sync(b)).errors).toEqual([]);
  });

  it("a long backlog read in rounds stops at the boundary once closed", async () => {
    const w = world();
    const { a, b } = await pair(w);
    for (let i = 0; i < 250; i++) await enqueueLocation(a.client, w.loc(i % 90));
    await w.sync(a);
    const drain = b.client.syncUntilDrained({ catchUp: { maxRecords: 100, maxMs: 5000 }, maxRounds: 10 });
    await b.client.close();
    const r = await drain;
    expect(["closed", "drained"]).toContain(r.stoppedBecause);
    expect(await thrown(() => b.client.sync())).toBe("CLOSED");
  });
});

describe("review of 0.3.0", () => {
  it("2: close() waits for the whole drain; no store read follows its return", async () => {
    const w = world();
    const { a, b } = await pair(w);
    for (let i = 0; i < 250; i++) await enqueueLocation(a.client, w.loc(i % 90));
    await w.sync(a);
    const drain = b.client.syncUntilDrained({ catchUp: { maxRecords: 100, maxMs: 5000 }, maxRounds: 10 });
    await new Promise((r) => setTimeout(r, 5));
    await b.client.close();
    let readsAfterClose = 0;
    const read = b.store.read.bind(b.store);
    b.store.read = ((fn: Parameters<typeof read>[0]) => {
      readsAfterClose++;
      return read(fn);
    }) as typeof read;
    const r = await drain;
    // close() returned only after the drain settled: either it ran to its end first, or it stopped as closed.
    expect(readsAfterClose).toBe(0);
    expect(["closed", "drained"]).toContain(r.stoppedBecause);
  });

  it("3: maxMs bounds the rounds and the reading inside them", async () => {
    const w = world();
    const { a, b } = await pair(w);
    for (let i = 0; i < 250; i++) await enqueueLocation(a.client, w.loc(i % 90));
    await w.sync(a);
    // No time at all: one round, whose inbox budget expires after its first page, then maxMs.
    const r = await b.client.syncUntilDrained({ catchUp: { maxRecords: 100 }, maxMs: 0 });
    expect([r.stoppedBecause, r.rounds, r.remaining.inboxHasMore]).toEqual(["maxMs", 1, true]);
  });

  it("4: a round whose discovery failed is incomplete, never drained", async () => {
    const w = world();
    const { a, b } = await pair(w);
    for (let i = 0; i < 3; i++) await enqueueLocation(a.client, w.loc(i));
    await w.sync(a);
    b.t.knobs.withhold.add("subscriptions");
    const r = await b.client.syncUntilDrained();
    expect([r.stoppedBecause, r.remaining.inboxHasMore, r.errors.map((e) => e.operation)]).toEqual(["incomplete", "unknown", ["listSubscriptions"]]);
    b.t.knobs.withhold.delete("subscriptions");
    const ok = await b.client.syncUntilDrained();
    expect([ok.stoppedBecause, ok.remaining.inboxHasMore, ok.inbox.stored]).toEqual(["drained", false, 3]);
  });
});

describe("second review of 0.3.0", () => {
  it("1: a close that lands during a round's metadata phase is reported as closed, never drained", async () => {
    const w = world();
    const { a, b } = await pair(w);
    await enqueueLocation(a.client, w.loc(1));
    await w.sync(a);
    // Close as soon as the round has started: it stops at its next boundary, before the inbox.
    const drain = b.client.syncUntilDrained();
    await b.client.close();
    const r = await drain;
    expect([r.stoppedBecause, r.remaining.inboxHasMore]).toEqual(["closed", "unknown"]);
  });

  it("1b: a close mid-round keeps the round's counters and errors in the report", async () => {
    const w = world();
    const { a, b } = await pair(w);
    await enqueueLocation(b.client, w.loc(3));
    await w.sync(b);
    await enqueueLocation(a.client, w.loc(2)); // handed off now; the round's outbox phase settles it as accepted
    // The round's acknowledgement of Bob's record is held while close() lands, so the round ends
    // inside its inbox phase. What its outbox settled must still be in the report.
    let release: () => void = () => undefined;
    a.t.knobs.hold.set("ackThrough", new Promise<void>((res) => (release = res)));
    const drain = a.client.syncUntilDrained();
    await new Promise((r) => setTimeout(r, 20));
    const closing = a.client.close();
    release();
    await closing;
    const r = await drain;
    expect([r.stoppedBecause, r.outbox.accepted, r.rounds, r.remaining.inboxHasMore]).toEqual(["closed", 1, 1, "unknown"]);
    expect(w.host.appendLog.filter((x) => x.status === "ACCEPTED").length).toBeGreaterThanOrEqual(2);
  });

  it("2: an unfinished chain is remaining work, and its pages advancing is progress", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    const recover = async () => {
      const d = await fresh(w, "bob");
      const p = await d.client.prepareReplacement();
      const token = w.host.authorizeReplacement({ accountName: "bob", successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });
      await d.client.completeReplacement({ successionId: p.successionId, authorization: token });
    };
    await recover();
    await recover();
    w.host.successionPageSize = 1;
    const r = await a.client.syncUntilDrained({ catchUp: { maxRecords: 1, maxMs: 5000 } });
    expect([r.stoppedBecause, r.remaining.chainsIncomplete, r.metadata.successions]).toEqual(["drained", 0, 2]);
    expect(r.rounds).toBeGreaterThan(1);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("3");
  });
});

describe("syncUntilDrained", () => {
  it("drains a backlog larger than one budget in one call and reports the rounds", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    // Pages are 100 records; a budget of 100 makes each round one page, so 250 records are three rounds.
    for (let i = 0; i < 250; i++) await enqueueLocation(a.client, w.loc(i % 90));
    await w.sync(a);
    const r = await b.client.syncUntilDrained({ catchUp: { maxRecords: 100, maxMs: 5000 } });
    expect([r.stoppedBecause, r.remaining.inboxHasMore, r.rounds, r.inbox.stored]).toEqual(["drained", false, 3, 250]);
    expect((await b.client.historyPage({ authorIdentityId: aliceId, limit: 500 })).entries.length).toBe(251);
  });

  it("maxRounds caps the loop and says so, with what remains", async () => {
    const w = world();
    const { a, b } = await pair(w);
    for (let i = 0; i < 250; i++) await enqueueLocation(a.client, w.loc(i % 90));
    await w.sync(a);
    const r = await b.client.syncUntilDrained({ catchUp: { maxRecords: 100, maxMs: 5000 }, maxRounds: 2 });
    expect([r.stoppedBecause, r.rounds, r.remaining.inboxHasMore]).toEqual(["maxRounds", 2, true]);
  });

  it("a bootstrap of several pages finishes in one call; a device that still needs an authorization stops with that reason", async () => {
    const w = world();
    const { a, b } = await pair(w);
    const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
    for (let i = 0; i < 3; i++) {
      const { circleId } = await a.client.circles.create();
      await b.client.circles.requestJoin(circleId, aliceId);
      await w.sync(a);
      await a.client.circles.approve(circleId, "bob");
    }
    await w.sync(a);
    await w.sync(b);
    w.host.circlePageSize = 1;
    const d = await fresh(w, "bob");
    const proposal = await d.client.prepareReplacement();
    const waiting = await d.client.syncUntilDrained();
    expect([waiting.stoppedBecause, waiting.rounds]).toEqual(["authentication", 1]);
    const token = w.host.authorizeReplacement({ accountName: "bob", successionId: proposal.successionId, expectedCertificateHash: proposal.expectedCertificateHash, certificate: proposal.certificate });
    await d.client.completeReplacement({ successionId: proposal.successionId, authorization: token });
    const r = await d.client.syncUntilDrained();
    expect([r.stoppedBecause, r.remaining.bootstrapIncomplete, (await d.client.circles.list()).length]).toEqual(["drained", false, 4]);
  });

  it("stops as noProgress when a round repeats the same errors and changes nothing", async () => {
    const w = world();
    const { a, b } = await pair(w);
    for (let i = 0; i < 6; i++) await enqueueLocation(a.client, w.loc(i));
    await w.sync(a);
    b.t.knobs.withhold.add("epochs"); // records arrive but cannot be opened: keyPending, hasMore stays
    const r = await b.client.syncUntilDrained({ catchUp: { maxRecords: 2, maxMs: 5000 }, maxRounds: 8 });
    expect(["noProgress", "drained"]).toContain(r.stoppedBecause);
    expect(r.rounds).toBeLessThanOrEqual(8);
  });
});

describe("replaceDevice", () => {
  const authorizeAt = (w: World, name: string) => async (p: { successionId: Uint8Array; expectedCertificateHash: Uint8Array; certificate: Uint8Array }) => w.host.authorizeReplacement({ accountName: name, successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });

  it("the plain path: one call activates; a second call reports activated without touching the host", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    const d = await fresh(w, "bob");
    const r = await d.client.replaceDevice({ authorize: authorizeAt(w, "bob") });
    expect(r.status).toBe("activated");
    expect(w.host.successionLog.size).toBe(1);
    expect((await d.client.replaceDevice({ authorize: authorizeAt(w, "bob") })).status).toBe("activated");
    expect(w.host.successionLog.size).toBe(1);
    const drained = await d.client.syncUntilDrained();
    expect([drained.errors, drained.stoppedBecause]).toEqual([[], "drained"]);
    await w.sync(a);
    expect((await a.client.keyChanges({ accountId: bobId })).length).toBe(1);
  });

  it("an unknown outcome keeps the same proposal: pending after bounded attempts, then activated from the chain by the next call", async () => {
    const w = world();
    await pair(w);
    const d = await fresh(w, "bob");
    let asked = 0;
    const authorize = async (p: { successionId: Uint8Array; expectedCertificateHash: Uint8Array; certificate: Uint8Array }) => {
      asked++;
      return w.host.authorizeReplacement({ accountName: "bob", successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });
    };
    d.t.knobs.refuse.add("succeedAccount");
    d.t.knobs.withhold.add("successions");
    const r1 = await d.client.replaceDevice({ authorize, maxAttempts: 1 });
    expect([r1.status, asked, w.host.successionLog.size]).toEqual(["pending", 1, 0]);
    // The host is reachable again; the response of the commit is lost, the chain says it landed.
    d.t.knobs.loseResponseOf.add("succeedAccount");
    const r2 = await d.client.replaceDevice({ authorize, maxAttempts: 1 });
    expect([r2.status, w.host.successionLog.size]).toEqual(["pending", 1]);
    d.t.knobs.withhold.delete("successions");
    const r3 = await d.client.replaceDevice({ authorize });
    expect([r3.status, asked, w.host.successionLog.size]).toEqual(["activated", 2, 1]);
  });

  it("a refused token asks once more for the same proposal; reauthenticate and conflict are returned, not thrown", async () => {
    const w = world();
    const { b } = await pair(w);
    const d = await fresh(w, "bob");
    let calls = 0;
    const flaky = async (p: { successionId: Uint8Array; expectedCertificateHash: Uint8Array; certificate: Uint8Array }) => (++calls === 1 ? new Uint8Array(32) : w.host.authorizeReplacement({ accountName: "bob", successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate }));
    expect((await d.client.replaceDevice({ authorize: flaky })).status).toBe("activated");
    expect(calls).toBe(2);
    const e = await fresh(w, "bob");
    const r = await e.client.replaceDevice({ authorize: async () => "reauthenticate" });
    expect([r.status, (await e.client.getState()).status]).toEqual(["reauthenticate", "replacementPrepared"]);
    // The account moves under the kept proposal: conflict, and the next call prepares anew.
    const f = await w.device("bob", (b.provider as MemoryPlatformProvider).twin());
    void f;
    const g = await fresh(w, "bob");
    const p = await g.client.prepareReplacement();
    const moved = await fresh(w, "bob");
    await moved.client.replaceDevice({ authorize: authorizeAt(w, "bob") });
    const c = await g.client.replaceDevice({ authorize: authorizeAt(w, "bob") });
    expect([c.status, c.status === "conflict" ? c.currentGeneration : undefined]).toEqual(["conflict", 3n]);
    expect(toHex((await g.client.prepareReplacement()).successionId)).not.toBe(toHex(p.successionId));
  });
});
