/**
 * Regressions from the external feedback on the vault commit: a sharing preference changed while
 * sync held an older copy of the circle row, and a crash between the two halves of a reset.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { open } from "../src/client.js";
import { ready } from "../src/crypto.js";
import { locationFromDegrees } from "../src/record.js";
import { testPolicy } from "../src/testing/clock.js";
import { FaultyStore } from "../src/testing/faults.js";
import { KavachError } from "../src/errors.js";
import { MemoryStore, type Store, type Tx } from "../src/store.js";
import type { Directory, Relay } from "../src/transport.js";
import { META, VAULT } from "../src/transactions.js";
import { pair, resetTrust, thrown, world, type World } from "./clientWorld.js";

beforeAll(() => ready());

describe("feedback findings", () => {
  it("1: disabling sharing while sync fetches a newer snapshot keeps sharing disabled", async () => {
    const w = world();
    const { a, b, aliceId, circleId } = await pair(w);
    // A third member makes the host's snapshot newer than Bob's copy.
    const c = await w.device("carol");
    await c.client.initializeAccount();
    await c.client.circles.requestJoin(circleId, aliceId);
    await w.sync(a);
    await a.client.circles.approve(circleId, "carol");
    await w.sync(a);
    expect(w.host.circles.get(toHex(circleId))?.revision).toBe(3n);
    // Bob turns sharing off after sync has read his circle rows and before it stores the snapshot.
    const directory = b.t.directory as { getCircle: Directory["getCircle"] };
    const fetch = directory.getCircle;
    directory.getCircle = async (id) => {
      directory.getCircle = fetch;
      await b.client.circles.setEnabled(circleId, false);
      return fetch(id);
    };
    const r = await w.sync(b);
    expect(r.errors).toEqual([]);
    expect(r.metadata.snapshots).toBe(1);
    const circle = (await b.client.circles.list()).find((x) => toHex(x.circleId) === toHex(circleId));
    expect([circle?.revision, circle?.enabled, circle?.members.length]).toEqual([3n, false, 3]);
    expect(await b.store.read((tx) => tx.get("circles", toHex(circleId))?.enabled)).toBe(false);
  });

  it("2: a crash between the new roots and the new store header still reopens under the new identity", async () => {
    let covered = 0;
    for (let at = 1; at < 8 && covered === 0; at++) {
      const w = world();
      const { a } = await pair(w);
      const oldSeed = toHex((await a.secrets.get("accountSeed")) ?? new Uint8Array());
      const faulty = new FaultyStore(a.store.fork(), { at, phase: "beforeCommit" });
      const crashing = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: faulty, transport: a.t, now: w.clock.now });
      await crashing.resetAccount({ confirmed: true }).catch(() => undefined);
      const newSeed = toHex((await a.secrets.get("accountSeed")) ?? new Uint8Array());
      if (!faulty.crashed || newSeed === oldSeed) continue;
      covered++;
      // The roots name the new identity, the store header still the old one.
      expect(await a.store.read((tx) => tx.get("pendingReset", "pending"))).toBeDefined();
      const host = w.host.accounts.get("alice");
      const again = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: a.store.fork(), transport: a.t, now: w.clock.now });
      const state = await again.getState();
      expect([state.status, toHex(state.identityId ?? new Uint8Array())]).toEqual(["ready", host?.identityId]);
      expect(await a.secrets.get("pendingReset")).toBeUndefined();
      expect(await a.store.read((tx) => tx.get("pendingReset", "pending"))).toBeUndefined();
      w.clock.advance(1_000n);
      expect((await again.sync()).errors).toEqual([]);
    }
    expect(covered).toBe(1);
  });

  it("3: a crash right after sharing is turned off, before the vault is prepared, still reaches a replacement device as off", async () => {
    let covered = 0;
    for (let at = 1; at < 6; at++) {
      const w = world();
      const { b, circleId } = await pair(w);
      const faulty = new FaultyStore(b.store.fork(), { at, phase: "afterCommit" });
      const crashing = await open({ accountName: "bob", retentionPolicy: testPolicy, recoveryProvider: b.provider, resetTrust, secretStore: b.secrets, store: faulty, transport: b.t, now: w.clock.now });
      await crashing.circles.setEnabled(circleId, false).catch(() => undefined);
      if (!faulty.crashed) break;
      covered++;
      const again = await open({ accountName: "bob", retentionPolicy: testPolicy, recoveryProvider: b.provider, resetTrust, secretStore: b.secrets, store: b.store.fork(), transport: b.t, now: w.clock.now });
      w.clock.advance(1_000n);
      expect((await again.sync()).errors, `crash after transaction ${at}`).toEqual([]);
      const twin = await w.device("bob", b.provider.twin());
      await twin.client.restoreAccount();
      const restored = (await twin.client.circles.list()).find((c) => toHex(c.circleId) === toHex(circleId));
      expect(restored?.enabled, `crash after transaction ${at}`).toBe(false);
    }
    expect(covered).toBeGreaterThan(1);
  });

  it("4: a crash right after a circle is first persisted still backs the circle up once sync has published it", async () => {
    let covered = 0;
    for (let at = 1; at < 5; at++) {
      const w = world();
      const a = await w.device("alice");
      await a.client.initializeAccount();
      const faulty = new FaultyStore(a.store.fork(), { at, phase: "afterCommit" });
      const crashing = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: faulty, transport: a.t, now: w.clock.now });
      await crashing.circles.create().catch(() => undefined);
      if (!faulty.crashed) break;
      covered++;
      const again = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: a.store.fork(), transport: a.t, now: w.clock.now });
      w.clock.advance(1_000n);
      expect((await again.sync()).errors, `crash after transaction ${at}`).toEqual([]);
      expect((await again.circles.list()).map((c) => c.status), `crash after transaction ${at}`).toEqual(["member"]);
      const twin = await w.device("alice", a.provider.twin());
      await twin.client.restoreAccount();
      expect((await twin.client.circles.list()).length, `crash after transaction ${at}`).toBe(1);
    }
    expect(covered).toBeGreaterThan(0);
  });

  it("5: asking to join again after leaving moves the circle back to requested, and the owner's approval makes it a member", async () => {
    const w = world();
    const { a, b, aliceId, circleId } = await pair(w);
    await b.client.circles.leave(circleId);
    await w.sync(a);
    expect((await b.client.circles.list())[0]?.status).toBe("left");
    // Another owner cannot be pinned over the one this circle has.
    expect(await thrown(() => b.client.circles.requestJoin(circleId, new Uint8Array(32).fill(1)))).toBe("NOT_AUTHORIZED");
    await b.client.circles.requestJoin(circleId, aliceId, { shareOnApproval: true });
    const row = await b.store.read((tx) => tx.get("circles", toHex(circleId)));
    expect([row?.status, row?.enabled, row?.revision]).toEqual(["requested", true, "2"]);
    await w.sync(a);
    await a.client.circles.approve(circleId, "bob");
    await w.sync(a);
    expect((await w.sync(b)).errors).toEqual([]);
    const circle = (await b.client.circles.list())[0];
    expect([circle?.status, circle?.enabled, circle?.revision]).toEqual(["member", true, 4n]);
    // The backup has it again: a replacement device restores the circle.
    const twin = await w.device("bob", b.provider.twin());
    await twin.client.restoreAccount();
    expect((await twin.client.circles.list()).map((c) => toHex(c.circleId))).toEqual([toHex(circleId)]);
  });

  it("6: a subscriber that throws on an acceptance neither undoes it nor stops the other listeners", async () => {
    const w = world();
    const { a } = await pair(w);
    const seen: string[] = [];
    a.client.subscribe((e) => {
      if (e.kind === "accepted") throw new Error("boom");
    });
    a.client.subscribe((e) => seen.push(e.kind));
    await a.client.enqueueLocation(w.loc(2));
    const r = await w.sync(a);
    expect([r.errors, r.outbox.accepted]).toEqual([[], 1]);
    expect(await a.store.read((tx) => tx.count("outbox"))).toBe(0);
    expect(seen).toContain("accepted");
    expect((await w.sync(a)).outbox.sent).toBe(0);
  });

  it("7: a cancelled record keeps only its summary and goes after the delivery window", async () => {
    const w = world();
    const { a, circleId } = await pair(w);
    const { recordId } = await a.client.enqueueLocation(w.loc(2));
    await a.client.circles.setEnabled(circleId, false);
    const row = await a.store.read((tx) => tx.get("outbox", toHex(recordId)));
    expect([row?.status, row?.reason, row?.wire]).toEqual(["cancelled", "rotation", ""]);
    const before = await a.client.inspect();
    expect([before.outbox.cancelled, before.outbox.queued, before.paused]).toEqual([1, 0, "rotation"]);
    await a.client.circles.setEnabled(circleId, true);
    expect((await w.sync(a)).purged).toBe(0);
    expect(await a.store.read((tx) => tx.get("outbox", toHex(recordId)))).toBeDefined();
    w.clock.advance(86_400_000n);
    expect((await w.sync(a)).purged).toBeGreaterThanOrEqual(1);
    expect(await a.store.read((tx) => tx.get("outbox", toHex(recordId)))).toBeUndefined();
  });

  it("8: inspect shows the outbox by state, the oldest pending age and the vault's state, never a secret", async () => {
    const w = world();
    const { a } = await pair(w);
    await a.client.enqueueLocation(w.loc(3));
    w.clock.advance(5_000n);
    const i = await a.client.inspect();
    expect([i.outbox.queued, i.outbox.inflight, i.outbox.oldestPendingAgeMs, i.pendingEpoch, i.paused]).toEqual([1, 0, 5_000n, undefined, undefined]);
    const vault = await a.store.read((tx) => tx.get("vault", VAULT));
    expect(i.vault).toEqual({ revision: BigInt(vault?.revision ?? "0"), pending: false, dirty: false });
    expect(JSON.stringify(i, (_, v) => (typeof v === "bigint" ? v.toString() : v))).not.toContain(toHex((await a.secrets.get("accountSeed")) ?? new Uint8Array(1)));
    await w.sync(a);
    expect((await a.client.inspect()).outbox).toEqual({ queued: 0, inflight: 0, cancelled: 0, unknown: 0, oldestPendingAgeMs: undefined });
  });

  it("9: an expired backlog does not delay a fresh location: one sync cancels the old rows and delivers the new one", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    for (const lat of [2, 3, 4]) await a.client.enqueueLocation(w.loc(lat));
    w.clock.advance(86_400_000n + 1n);
    const fresh = await a.client.enqueueLocation(w.loc(5));
    const r = await w.sync(a);
    expect([r.errors, r.outbox.cancelled, r.outbox.sent, r.outbox.accepted]).toEqual([[], 3, 1, 1]);
    expect((await w.sync(b)).inbox.stored).toBe(1);
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(toHex(fresh.recordId));
  });

  it("10: a throwing subscriber is reported through onListenerError, with the event, and the call still succeeds", async () => {
    const w = world();
    const { a } = await pair(w);
    const seen: string[] = [];
    const client = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: a.store.fork(), transport: a.t, now: w.clock.now, onListenerError: (e, ev) => seen.push(`${ev.kind}:${e instanceof Error ? e.message : String(e)}`) });
    client.subscribe((e) => {
      if (e.kind === "queued") throw new Error("boom");
    });
    await client.enqueueLocation(w.loc(6));
    expect(seen).toEqual(["queued:boom"]);
  });

  it("11: a host that cannot be reached is a NETWORK error, retryable, in the thrown error and in the sync report", async () => {
    const w = world();
    const { b, circleId } = await pair(w);
    b.t.knobs.refuse.add("publishVault");
    expect(await thrown(() => b.client.circles.setEnabled(circleId, false))).toBe("NETWORK");
    b.t.knobs.refuse.add("publishVault");
    const r = await w.sync(b);
    expect(r.errors).toEqual([{ operation: "vault", code: "NETWORK", stage: "transport", retryable: true }]);
    expect((await w.sync(b)).errors).toEqual([]);
  });

  it("12: a backlog of a thousand expired rows is cancelled in a handful of transactions, and the fresh location still goes out", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    for (let i = 0; i < 1000; i++) await a.client.enqueueLocation(w.loc(1 + (i % 80)));
    w.clock.advance(86_400_000n + 1n);
    const fresh = await a.client.enqueueLocation(w.loc(5));
    const faulty = new FaultyStore(a.store.fork());
    const counted = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: faulty, transport: a.t, now: w.clock.now });
    const before = faulty.transactions;
    const r = await counted.sync();
    expect([r.errors, r.outbox.cancelled, r.outbox.accepted]).toEqual([[], 1000, 1]);
    expect(faulty.transactions - before).toBeLessThan(40);
    expect((await w.sync(b)).inbox.stored).toBe(1);
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(toHex(fresh.recordId));
  });

  it("13: a stream whose download fails is named in the sync report, is not counted as synced, and the other streams are still read", async () => {
    const w = world();
    const { a, b } = await pair(w);
    const c = await thirdAuthor(w, b);
    await a.client.enqueueLocation(w.loc(2));
    await c.client.enqueueLocation(w.loc(3));
    await w.sync(a);
    await w.sync(c);
    // The first read of this sync fails before reaching the host; the second stream is served.
    const relay = b.t.relay as { readRecords: Relay["readRecords"] };
    const read = relay.readRecords;
    relay.readRecords = async () => {
      relay.readRecords = read;
      throw new KavachError("NETWORK", "transport", "network unreachable");
    };
    const r = await w.sync(b);
    expect(r.errors).toEqual([{ operation: "inbox", code: "NETWORK", stage: "transport", retryable: true }]);
    expect([r.inbox.streams, r.inbox.stored]).toEqual([1, 1]);
    const again = await w.sync(b);
    expect([again.errors, again.inbox.streams, again.inbox.stored]).toEqual([[], 2, 1]);
  });

  it("14: the same idempotency key from a retry or another runtime yields the one record; a new key or an expired one makes a new record", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    const first = await a.client.enqueueLocation(w.loc(4), { idempotencyKey: "fix:1" });
    const retry = await a.client.enqueueLocation(w.loc(4), { idempotencyKey: "fix:1" });
    expect([retry.duplicate, toHex(retry.recordId)]).toEqual([true, toHex(first.recordId)]);
    // Another runtime on the same store, as the background task would be.
    const other = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: a.store.fork(), transport: a.t, now: w.clock.now });
    const fromOther = await other.enqueueLocation(w.loc(4), { idempotencyKey: "fix:1" });
    expect([fromOther.duplicate, toHex(fromOther.recordId)]).toEqual([true, toHex(first.recordId)]);
    expect(a.events.filter((e) => e.kind === "queued").length).toBe(2); // the pair's location and this one
    expect(await a.store.read((tx) => tx.list("outbox").filter(([, r]) => r.status === "queued").length)).toBe(1);
    const second = await a.client.enqueueLocation(w.loc(4), { idempotencyKey: "fix:2" });
    expect([second.duplicate, toHex(second.recordId) === toHex(first.recordId)]).toEqual([false, false]);
    expect(await thrown(() => a.client.enqueueLocation(w.loc(4), { idempotencyKey: "" }))).toBe("MALFORMED");
    expect(await thrown(() => a.client.enqueueLocation(w.loc(4), { idempotencyKey: "k".repeat(129) }))).toBe("MALFORMED");
    await w.sync(a);
    expect((await w.sync(b)).inbox.stored).toBe(2);
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(3);
    // Keys live for the delivery window; after it the same key is a new hand-over.
    w.clock.advance(testPolicy.deliveryWindowMs + 1n);
    await w.sync(a);
    expect(await a.store.read((tx) => tx.count("enqueueKeys"))).toBe(0);
    const later = await a.client.enqueueLocation(w.loc(4), { idempotencyKey: "fix:1" });
    expect([later.duplicate, toHex(later.recordId) === toHex(first.recordId)]).toEqual([false, false]);
  });

  it("15: history pages are served from the index in time order, with a stable cursor, a window, a kind filter and a newest query", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    const c = await thirdAuthor(w, b);
    const carolId = (await c.client.inspect()).identityId ?? new Uint8Array();
    const pairRecord = toHex((await b.client.history())[0]?.recordId ?? new Uint8Array());
    const sent: string[] = [];
    for (let i = 0; i < 6; i++) {
      w.clock.advance(60_000n);
      const r = i % 3 === 2 ? await a.client.enqueueCheckIn(w.loc(10 + i)) : await (i % 2 ? c : a).client.enqueueLocation(w.loc(10 + i));
      sent.push(toHex(r.recordId));
    }
    await w.sync(a);
    await w.sync(c);
    await w.sync(b);
    // The history table itself is never listed: every query goes through the index.
    const guarded = guardListing(b.store, "history");
    const all = await b.client.history();
    expect(all.map((h) => toHex(h.recordId))).toEqual([pairRecord, ...sent]);
    const { historyPage, newest } = await import("../src/inbox.js");
    const pages: string[][] = [];
    let cursor: string | undefined;
    do {
      const page = await historyPage(guarded, testPolicy, { order: "desc", limit: 3, cursor });
      pages.push(page.entries.map((h) => toHex(h.recordId)));
      cursor = page.cursor;
      // A record arriving mid-pagination does not move the cursor's position.
      if (pages.length === 1) await c.client.enqueueLocation(w.loc(30));
    } while (cursor);
    expect(pages.flat()).toEqual([...sent].reverse().concat([pairRecord]));
    expect(pages.map((p) => p.length)).toEqual([3, 3, 1]);
    expect((await historyPage(guarded, testPolicy, { kind: 1 })).entries.map((h) => toHex(h.recordId))).toEqual([sent[2], sent[5]]);
    expect((await historyPage(guarded, testPolicy, { authorIdentityId: carolId })).entries.map((h) => toHex(h.recordId))).toEqual([sent[1], sent[3]]);
    expect((await historyPage(guarded, testPolicy, { since: all[2]?.sentAt, before: all[4]?.sentAt })).entries.map((h) => toHex(h.recordId))).toEqual([sent[1], sent[2]]);
    expect((await historyPage(guarded, testPolicy, { kind: 2 })).entries).toEqual([]);
    expect(toHex((await newest(guarded, testPolicy, { authorIdentityId: aliceId }))?.recordId ?? new Uint8Array())).toBe(sent[5] ?? "");
    expect(toHex((await newest(guarded, testPolicy, { kind: 0 }))?.recordId ?? new Uint8Array())).toBe(sent[4] ?? "");
    expect(toHex((await b.client.newest())?.recordId ?? new Uint8Array())).toBe(sent[5] ?? "");
    // Expiry removes the index entries with the rows, and the payload of the slot that pointed at one of them.
    w.clock.advance((testPolicy.kinds[0]?.retentionMs ?? 0n));
    const r = await w.sync(b);
    expect(r.purged).toBeGreaterThan(0);
    expect(await b.store.read((tx) => [tx.count("history"), tx.count("historyIndex"), tx.list("newest").filter(([, r]) => r.payload !== null).length])).toEqual([2, 4, 0]);
    expect((await b.client.history()).map((h) => h.kind)).toEqual([1, 1]);
  });

  it("16: a store written before the index exists is indexed on open, and its history reads the same", async () => {
    const w = world();
    const { b, aliceId } = await pair(w);
    const before = (await b.client.history()).map((h) => toHex(h.recordId));
    await b.store.transaction((tx) => {
      for (const [k] of tx.list("historyIndex")) tx.delete("historyIndex", k);
      const meta = tx.get("meta", META);
      if (!meta) throw new Error("no meta");
      const legacy = { ...meta };
      delete legacy.historyIndex;
      tx.put("meta", META, legacy);
    });
    expect(await b.client.history()).toEqual([]);
    const reopened = await open({ accountName: "bob", retentionPolicy: testPolicy, recoveryProvider: b.provider, resetTrust, secretStore: b.secrets, store: b.store.fork(), transport: b.t, now: w.clock.now });
    expect((await reopened.history({ authorIdentityId: aliceId })).map((h) => toHex(h.recordId))).toEqual(before);
    expect(await b.store.read((tx) => [tx.get("meta", META)?.historyIndex, tx.count("historyIndex")])).toEqual([1, 2]);
  });

  it("17: two runtimes enqueueing the same key at once get one committed record, and a key is not kept for a refused enqueue", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    const other = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: a.store.fork(), transport: a.t, now: w.clock.now });
    const [x, y] = await Promise.all([a.client.enqueueLocation(w.loc(7), { idempotencyKey: "race" }), other.enqueueLocation(w.loc(7), { idempotencyKey: "race" })]);
    expect(toHex(x.recordId)).toBe(toHex(y.recordId));
    expect([x.duplicate, y.duplicate].sort()).toEqual([false, true]);
    // The record is durable before either call returned.
    expect(await a.store.read((tx) => tx.get("outbox", toHex(x.recordId))?.status)).toBe("queued");
    expect(await a.store.read((tx) => tx.get("enqueueKeys", "race")?.recordId)).toBe(toHex(x.recordId));
    await w.sync(a);
    expect((await w.sync(b)).inbox.stored).toBe(1);
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(2);
    // A refused enqueue stores no key: the retry is checked again, not answered from the key.
    for (let i = 0; i < testPolicy.maxOutboxRecords; i++) await a.client.enqueueLocation(w.loc(1 + (i % 80)));
    expect(await thrown(() => a.client.enqueueLocation(w.loc(8), { idempotencyKey: "full" }))).toBe("QUEUE_FULL");
    expect(await a.store.read((tx) => tx.get("enqueueKeys", "full"))).toBeUndefined();
  });

  it("18: a backlog is read in pages within the sync's budget, hasMore says when to come back, and the rest follows", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    for (let i = 0; i < 250; i++) await a.client.enqueueLocation(w.loc(1 + (i % 80)));
    expect((await w.sync(a)).outbox.accepted).toBe(250);
    // No time left after the first page: one page per stream, and the report asks for another sync.
    const timed = await b.client.sync({ catchUp: { maxMs: 0 } });
    expect([timed.inbox.stored, timed.inbox.hasMore, timed.errors]).toEqual([100, true, []]);
    // A record budget stops after the page that spends it; here the backlog ends inside it.
    const second = await b.client.sync({ catchUp: { maxRecords: 150 } });
    expect([second.inbox.stored, second.inbox.hasMore]).toEqual([150, false]);
    const rest = await w.sync(b);
    expect([rest.inbox.stored, rest.inbox.hasMore]).toEqual([0, false]);
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(251);
    expect((await w.sync(b)).inbox.hasMore).toBe(false);
  });

  it("19: the live pin follows the measurement time within a generation: a late older sample never moves it back, a clock set ahead cannot hold it", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    const at = (lat: number, capturedAt: bigint) => locationFromDegrees(lat, -122.4194, 5, capturedAt);
    const fresh = await a.client.enqueueLocation(at(10, w.clock.now()));
    const stale = await a.client.enqueueLocation(at(11, w.clock.now() - 60_000n)); // a buffered sample flushed later, higher counter
    await w.sync(a);
    await w.sync(b);
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(toHex(fresh.recordId));
    expect((await b.client.history({ authorIdentityId: aliceId })).map((h) => toHex(h.recordId))).toContain(toHex(stale.recordId));
    expect(b.events.filter((e) => e.kind === "latestUpdated").length).toBe(2); // the pair's location and the fresh one
    // A sample claiming to be captured a day ahead counts as captured when sent, so the next honest sample still wins.
    w.clock.advance(1_000n);
    const ahead = await a.client.enqueueLocation(at(12, w.clock.now() + 86_400_000n));
    await w.sync(a);
    await w.sync(b);
    const pinned = await b.client.latest(aliceId);
    expect([toHex(pinned?.recordId ?? new Uint8Array()), pinned?.eventTime]).toEqual([toHex(ahead.recordId), pinned?.sentAt]);
    w.clock.advance(1_000n);
    const honest = await a.client.enqueueLocation(at(13, w.clock.now()));
    await w.sync(a);
    await w.sync(b);
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(toHex(honest.recordId));
  });

  it("20: a store from before the slot table rebuilds its newest slots from history on open", async () => {
    const w = world();
    const { b, aliceId } = await pair(w);
    const before = toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array());
    await b.store.transaction((tx) => {
      for (const [k] of tx.list("newest")) tx.delete("newest", k);
      const meta = tx.get("meta", META);
      if (!meta) throw new Error("no meta");
      const legacy = { ...meta };
      delete legacy.newest;
      tx.put("meta", META, legacy);
    });
    expect(await b.client.latest(aliceId)).toBeUndefined();
    const reopened = await open({ accountName: "bob", retentionPolicy: testPolicy, recoveryProvider: b.provider, resetTrust, secretStore: b.secrets, store: b.store.fork(), transport: b.t, now: w.clock.now });
    expect(toHex((await reopened.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(before);
    expect(await b.store.read((tx) => tx.get("meta", META)?.newest)).toBe(1);
  });

  it("21: the sender's own pin and status are kept under the reader's rules, with the same events and expiry", async () => {
    const w = world();
    const { a, aliceId } = await pair(w);
    const at = (lat: number, capturedAt: bigint) => locationFromDegrees(lat, -122.4194, 5, capturedAt);
    const own = await a.client.latest(aliceId);
    expect(own).toBeDefined(); // the pair's location already pinned itself
    const fresh = await a.client.enqueueLocation(at(10, w.clock.now()));
    expect(toHex((await a.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(toHex(fresh.recordId));
    await a.client.enqueueLocation(at(11, w.clock.now() - 60_000n)); // measured earlier, sent later: history only
    expect(toHex((await a.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(toHex(fresh.recordId));
    expect(await a.client.latestStatus(aliceId)).toBeUndefined();
    await a.client.enqueueStatus(Uint8Array.of(1, 80, 0, 3));
    expect(Array.from((await a.client.latestStatus(aliceId))?.payload ?? [])).toEqual([1, 80, 0, 3]);
    await a.client.enqueueStatus(Uint8Array.of(1, 79, 0, 3));
    expect(Array.from((await a.client.latestStatus(aliceId))?.payload ?? [])).toEqual([1, 79, 0, 3]);
    const self = (e: { kind: string; identityId?: Uint8Array }) => e.identityId !== undefined && toHex(e.identityId) === toHex(aliceId);
    expect(a.events.filter((e) => e.kind === "latestUpdated" && self(e)).length).toBe(2); // the pair's location and the fresh one
    expect(a.events.filter((e) => e.kind === "statusUpdated" && self(e)).length).toBe(2);
    // The same key answered twice moves nothing twice.
    const before = a.events.length;
    await a.client.enqueueLocation(at(12, w.clock.now()), { idempotencyKey: "k" });
    await a.client.enqueueLocation(at(12, w.clock.now()), { idempotencyKey: "k" });
    expect(a.events.slice(before).filter((e) => e.kind === "latestUpdated").length).toBe(1);
    // Expiry treats the own row like any author's.
    w.clock.advance((testPolicy.kinds[0]?.retentionMs ?? 0n) + 1n);
    await w.sync(a);
    expect(await a.client.latest(aliceId)).toBeUndefined();
    expect(await a.client.latestStatus(aliceId)).toBeUndefined();
  });

  it("22: the public entry points carry the location codec and the key-list builder", async () => {
    const pub = await import("../src/index.js");
    const adapters = await import("../src/adapters/index.js");
    const loc = locationFromDegrees(1, 2, 3, 4n);
    expect(pub.decodeLocation(pub.encodeLocation(loc))).toEqual(loc);
    expect(typeof adapters.buildResetKeyList).toBe("function");
  });

  it("23: every per-kind behaviour follows the declaration, not the kind number, and an undeclared kind is refused on both sides", async () => {
    // The same three numbers with other roles: 0 a position (history, slot), 1 a state (slot only,
    // latest wins), 2 an event (history, no slot), with windows of one, two and three hours.
    const policy = {
      ...testPolicy,
      kinds: [
        { kind: 0, retentionMs: 3_600_000n, queue: "keepAll" as const, history: true, newest: true },
        { kind: 1, retentionMs: 7_200_000n, queue: "latestWins" as const, history: false, newest: true },
        { kind: 2, retentionMs: 10_800_000n, queue: "keepAll" as const, history: true, newest: false }
      ]
    };
    const w = world(policy);
    const { a, b, aliceId } = await pair(w);
    const first = await a.client.enqueueCheckIn(Uint8Array.of(1));
    await a.client.enqueueCheckIn(Uint8Array.of(2));
    expect(await a.store.read((tx) => tx.get("outbox", toHex(first.recordId))?.reason)).toBe("superseded"); // latest wins for kind 1 now
    const s1 = await a.client.enqueueStatus(Uint8Array.of(9));
    const s2 = await a.client.enqueueStatus(Uint8Array.of(8));
    expect(await a.store.read((tx) => [tx.get("outbox", toHex(s1.recordId))?.status, tx.get("outbox", toHex(s2.recordId))?.status])).toEqual(["queued", "queued"]); // keep all for kind 2 now
    await w.sync(a);
    const r = await w.sync(b);
    expect([r.inbox.stored, r.inbox.invalid]).toEqual([3, 0]);
    expect((await b.client.history({ authorIdentityId: aliceId })).map((h) => h.kind).sort()).toEqual([0, 2, 2]); // kind 1 keeps no history, kind 2 does
    expect(Array.from((await b.client.newestOf(aliceId, 1))?.payload ?? [])).toEqual([2]);
    expect(await b.client.newestOf(aliceId, 2)).toBeUndefined(); // no slot for kind 2
    expect(Array.from((await a.client.newestOf(aliceId, 1))?.payload ?? [])).toEqual([2]); // the sender's own slot too
    // Retention per kind: one hour clears kind 0, two hours kind 1's slot, three hours kind 2's history.
    w.clock.advance(3_600_000n + 1n);
    await w.sync(b);
    expect([await b.client.newestOf(aliceId, 0), (await b.client.history({ authorIdentityId: aliceId })).map((h) => h.kind).sort()]).toEqual([undefined, [2, 2]]);
    expect(await b.client.newestOf(aliceId, 1)).toBeDefined();
    w.clock.advance(3_600_000n);
    await w.sync(b);
    expect(await b.client.newestOf(aliceId, 1)).toBeUndefined();
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(2);
    w.clock.advance(3_600_000n);
    await w.sync(b);
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(0);
    // A kind the product did not declare: refused at enqueue, and invalid on a reader that lacks it.
    const narrow = { ...policy, kinds: policy.kinds.filter((k) => k.kind !== 2) };
    const c = await w.device("carol", undefined, undefined, undefined, narrow);
    await c.client.initializeAccount();
    expect(await thrown(() => c.client.enqueueStatus(Uint8Array.of(1)))).toBe("MALFORMED");
    const d = await w.device("dave", undefined, undefined, undefined, narrow);
    await d.client.initializeAccount();
    const { circleId } = await a.client.circles.create();
    await d.client.circles.requestJoin(circleId, aliceId);
    await w.sync(a);
    await a.client.circles.approve(circleId, "dave");
    await w.sync(a);
    await w.sync(d);
    await w.sync(a);
    await a.client.enqueueStatus(Uint8Array.of(7));
    await w.sync(a);
    const rd = await w.sync(d);
    expect([rd.inbox.stored, rd.inbox.invalid]).toEqual([0, 1]);
    expect(d.events.some((e) => e.kind === "securityError" && e.code === "BAD_PAYLOAD")).toBe(true);
  });

  it("24: the envelope carries the kind and the event time, the slot orders by it, and the host sees only the declared header class", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    const t = w.clock.now();
    // A byte payload with an event time: the reader orders by it and reports it; without one, it orders at sentAt.
    const older = await a.client.enqueueCheckIn(Uint8Array.of(1), { eventTime: t - 5_000n });
    await a.client.enqueueCheckIn(Uint8Array.of(2));
    await w.sync(a);
    await w.sync(b);
    const entries = await b.client.history({ authorIdentityId: aliceId, kind: 1 });
    expect(entries.map((h) => [toHex(h.recordId) === toHex(older.recordId), h.eventTime])).toEqual([[true, t - 5_000n], [false, undefined]]);
    // An event time ahead of the send time is clamped: the slot never trusts it past sentAt.
    const ahead = await a.client.enqueueLocation(locationFromDegrees(1, 2, 3, t + 999_999n));
    await w.sync(a);
    await w.sync(b);
    const pin = await b.client.latest(aliceId);
    expect([toHex(pin?.recordId ?? new Uint8Array()), pin?.eventTime]).toEqual([toHex(ahead.recordId), pin?.sentAt]);
    // The relay notifies by header class, never by kind: the same kind 1 declared with class 0 is a plain wake-up.
    const hidden = { ...testPolicy, kinds: testPolicy.kinds.map((k) => (k.kind === 1 ? { ...k, headerClass: 0 as const } : k)) };
    const c = await w.device("carol", undefined, undefined, undefined, hidden);
    await c.client.initializeAccount();
    const { circleId } = await c.client.circles.create();
    const carolId = (await c.client.inspect()).identityId ?? new Uint8Array();
    await b.client.circles.requestJoin(circleId, carolId);
    await w.sync(c);
    await c.client.circles.approve(circleId, "bob");
    await w.sync(c);
    await w.sync(b);
    await w.sync(c);
    const before = w.host.notifications.length;
    await a.client.enqueueCheckIn(Uint8Array.of(3));
    await c.client.enqueueCheckIn(Uint8Array.of(4));
    await w.sync(a);
    await w.sync(c);
    expect(w.host.notifications.slice(before).filter((n) => n.to === "bob").map((n) => n.kind).sort()).toEqual(["checkIn", "wake"]);
  });
});

/** Carol: a third author who shares with Bob through a circle of her own. */
async function thirdAuthor(w: World, b: Awaited<ReturnType<World["device"]>>): Promise<Awaited<ReturnType<World["device"]>>> {
  const c = await w.device("carol");
  await c.client.initializeAccount();
  const { circleId } = await c.client.circles.create();
  const carolId = (await c.client.inspect()).identityId ?? new Uint8Array();
  await b.client.circles.requestJoin(circleId, carolId);
  await w.sync(c);
  await c.client.circles.approve(circleId, "bob");
  await w.sync(c);
  await w.sync(b);
  await w.sync(c);
  return c;
}

/** A store whose reads refuse to list one table, so a test can prove a query never scans it. */
function guardListing(store: MemoryStore, table: string): Store {
  const guard = <T extends object>(tx: T): T =>
    new Proxy(tx, {
      get(target, prop, receiver) {
        const v = Reflect.get(target, prop, receiver) as unknown;
        if (prop === "list") return (t: string, prefix?: string) => {
          if (t === table) throw new Error(`listed ${table}`);
          return (target as unknown as Tx).list(t as never, prefix);
        };
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      }
    });
  return {
    transaction: (fn) => store.transaction((tx) => fn(guard(tx))),
    read: (fn) => store.read((tx) => fn(guard(tx)))
  };
}
