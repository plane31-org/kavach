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
import { pair, resetTrust, world } from "./clientWorld.js";

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
});
