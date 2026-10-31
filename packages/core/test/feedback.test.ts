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
import type { Directory } from "../src/transport.js";
import { VAULT } from "../src/transactions.js";
import { pair, resetTrust, thrown, world } from "./clientWorld.js";

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
});
