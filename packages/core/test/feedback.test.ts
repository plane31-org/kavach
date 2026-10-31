/**
 * Regressions from the external feedback on the vault commit: a sharing preference changed while
 * sync held an older copy of the circle row, and a crash between the two halves of a reset.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { open } from "../src/client.js";
import { ready } from "../src/crypto.js";
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
      const page = await historyPage(guarded, { order: "desc", limit: 3, cursor });
      pages.push(page.entries.map((h) => toHex(h.recordId)));
      cursor = page.cursor;
      // A record arriving mid-pagination does not move the cursor's position.
      if (pages.length === 1) await c.client.enqueueLocation(w.loc(30));
    } while (cursor);
    expect(pages.flat()).toEqual([...sent].reverse().concat([pairRecord]));
    expect(pages.map((p) => p.length)).toEqual([3, 3, 1]);
    expect((await historyPage(guarded, { kind: 1 })).entries.map((h) => toHex(h.recordId))).toEqual([sent[2], sent[5]]);
    expect((await historyPage(guarded, { authorIdentityId: carolId })).entries.map((h) => toHex(h.recordId))).toEqual([sent[1], sent[3]]);
    expect((await historyPage(guarded, { since: all[2]?.sentAt, before: all[4]?.sentAt })).entries.map((h) => toHex(h.recordId))).toEqual([sent[1], sent[2]]);
    expect((await historyPage(guarded, { kind: 2 })).entries).toEqual([]);
    expect(toHex((await newest(guarded, { authorIdentityId: aliceId }))?.recordId ?? new Uint8Array())).toBe(sent[5] ?? "");
    expect(toHex((await newest(guarded, { kind: 0 }))?.recordId ?? new Uint8Array())).toBe(sent[4] ?? "");
    expect(toHex((await b.client.newest())?.recordId ?? new Uint8Array())).toBe(sent[5] ?? "");
    // Expiry removes the index entries with the rows, and the pin that pointed at one of them.
    w.clock.advance(testPolicy.locationHistoryMs);
    const r = await w.sync(b);
    expect(r.purged).toBeGreaterThan(0);
    expect(await b.store.read((tx) => [tx.count("history"), tx.count("historyIndex"), tx.count("livePins")])).toEqual([2, 4, 0]);
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
