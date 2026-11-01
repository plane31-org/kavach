/**
 * Account recovery through the client (amendment A1, sections 4 and 5): prepare, authorize,
 * commit, activate, bootstrap, and the outcomes of a commit that did not plainly succeed.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ready } from "../src/crypto.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { testPolicy } from "../src/testing/clock.js";
import { MemoryPlatformProvider } from "../src/testing/providers.js";
import { enqueueLocation } from "./location.js";
import { pair, thrown, world, type Dev, type World } from "./clientWorld.js";

beforeAll(() => ready());

/** A fresh device for `name` with no secret from any earlier one, prepared and authorized. */
async function prepared(w: World, name: string, fresh?: Dev) {
  const d = fresh ?? (await w.device(name, new MemoryPlatformProvider(`${name}-new@platform`)));
  const proposal = await d.client.prepareReplacement();
  const authorization = w.host.authorizeReplacement({ accountName: name, successionId: proposal.successionId, expectedCertificateHash: proposal.expectedCertificateHash, certificate: proposal.certificate });
  return { d, proposal, authorization };
}

describe("account recovery: prepare and commit", () => {
  it("scenario 4 by account recovery: a member's replacement with no recovery material keeps membership, peers rotate, sharing resumes", async () => {
    const w = world();
    const { a, b, circleId, aliceId, bobId } = await pair(w);
    const { d: b2, proposal, authorization } = await prepared(w, "bob");
    expect((await b2.client.getState()).status).toBe("replacementPrepared");
    expect([toHex(proposal.accountId), proposal.expectedGeneration, proposal.accountName]).toEqual([toHex(bobId), 1n, "bob"]);
    // A second call returns the same proposal; nothing was sent.
    expect(toHex((await b2.client.prepareReplacement()).successionId)).toBe(toHex(proposal.successionId));
    expect(w.host.accounts.get("bob")?.generation).toBe(1n);
    const done = await b2.client.completeReplacement({ successionId: proposal.successionId, authorization });
    expect(done.generation).toBe(2n);
    const state = await b2.client.getState();
    const insp = await b2.client.inspect();
    // Paused for rotation until the first sync seals an epoch, exactly as after an identity-continuity restore.
    expect([state.status, state.paused, toHex(state.identityId ?? new Uint8Array()), toHex(insp.identityId ?? new Uint8Array()) === toHex(insp.keyIdentityId ?? new Uint8Array()), insp.replacement, insp.bootstrap]).toEqual(["paused", "rotation", toHex(bobId), false, undefined, { cursor: undefined, complete: false }]);
    expect(await b2.secrets.get("pendingReplacement")).toBeUndefined();
    // Bootstrap: the circle is discovered as a member, with the preference the first phone set when it asked to join.
    const first = await w.sync(b2);
    expect(first.bootstrap).toEqual({ circles: 1, pending: 0, failed: 0 });
    expect(first.errors).toEqual([]);
    const circles = await b2.client.circles.list();
    expect(circles.map((c) => [toHex(c.circleId), toHex(c.ownerIdentityId), c.status, c.enabled, c.owned])).toEqual([[toHex(circleId), toHex(aliceId), "member", true, false]]);
    expect([(await b2.client.inspect()).bootstrap, (await b2.client.getState()).status]).toEqual([{ cursor: undefined, complete: true }, "ready"]);
    // Alice applies the chain and rotates; she records the key change.
    const ar = await w.sync(a);
    expect([ar.errors, ar.metadata.successions, ar.epoch]).toEqual([[], 1, "prepared"]);
    const changes = await a.client.keyChanges();
    expect(changes.map((c) => [toHex(c.accountId), c.accountName, c.generation, c.reason, toHex(c.successionId ?? new Uint8Array())])).toEqual([[toHex(bobId), "bob", 2n, "succession", toHex(proposal.successionId)]]);
    // Bob shares from the new phone; Alice reads him under the same account id.
    expect(w.host.preferences.get(`${toHex(bobId)}:${toHex(circleId)}`)).toEqual({ enabled: true, revision: 1n });
    await w.sync(b2);
    await enqueueLocation(b2.client, w.loc(2));
    await w.sync(b2);
    await w.sync(a);
    expect((await a.client.history({ authorIdentityId: bobId })).length).toBe(1);
    // And Alice's next record reaches the new phone, never the old one.
    await enqueueLocation(a.client, w.loc(3));
    await w.sync(a);
    await w.sync(b2);
    expect((await b2.client.history({ authorIdentityId: aliceId })).length).toBe(1);
    await w.sync(b);
    expect((await b.client.getState()).status).toBe("retired");
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(1); // only what it had before
    // The vault the succession installed carries the discovered circle, so identity continuity works next time.
    const vault = w.host.accounts.get("bob")?.vault;
    expect(vault?.revision).toBeGreaterThanOrEqual(2n);
  });

  it("scenario 3 by account recovery: the owner's replacement republishes at the next revision and keeps its power over membership", async () => {
    const w = world();
    const { a, b, circleId, aliceId, bobId } = await pair(w);
    const { d: a2, proposal, authorization } = await prepared(w, "alice");
    await a2.client.completeReplacement({ successionId: proposal.successionId, authorization });
    const r = await w.sync(a2);
    expect([r.errors, r.bootstrap]).toEqual([[], { circles: 1, pending: 0, failed: 0 }]);
    // Served at revision 2 (the approval), republished under the new key at 3.
    expect(w.host.circles.get(toHex(circleId))?.revision).toBe(3n);
    expect((await a2.client.circles.list()).map((c) => [c.owned, c.revision, c.status])).toEqual([[true, 3n, "member"]]);
    // Bob verifies the republished snapshot under Alice's new key after applying her chain.
    const br = await w.sync(b);
    expect([br.errors, br.metadata.successions, br.metadata.snapshots]).toEqual([[], 1, 1]);
    expect((await b.client.circles.list()).map((c) => [toHex(c.ownerIdentityId), c.revision, c.status])).toEqual([[toHex(aliceId), 3n, "member"]]);
    // The successor owner can still change membership: a removal lands at revision 4.
    await a2.client.circles.remove(circleId, bobId);
    expect(w.host.circles.get(toHex(circleId))?.revision).toBe(4n);
    await w.sync(b);
    expect((await b.client.circles.list())[0]?.status).toBe("left");
    await w.sync(a);
    expect((await a.client.getState()).status).toBe("retired");
  });

  it("the previous device's preference is what the replacement sees, and its own actions order against the host revision", async () => {
    const w = world();
    const { b, circleId, bobId } = await pair(w);
    await b.client.circles.setEnabled(circleId, false);
    expect(w.host.preferences.get(`${toHex(bobId)}:${toHex(circleId)}`)).toEqual({ enabled: false, revision: 2n }); // 1 was set at the join request
    const { d: b2, proposal, authorization } = await prepared(w, "bob");
    await b2.client.completeReplacement({ successionId: proposal.successionId, authorization });
    await w.sync(b2);
    expect((await b2.client.circles.list())[0]?.enabled).toBe(false);
    // A delayed enable from elsewhere against the old revision loses.
    const stale = await w.host.asDevice("bob", (await b2.client.getState()).certificateHash ?? new Uint8Array()).directory.setSharingPreference(circleId, true, 0n);
    expect(stale.status).toBe("CONFLICT");
    // A disable while the host is unreachable stops sharing at once, and lands on the next sync.
    await b2.client.circles.setEnabled(circleId, true);
    expect(w.host.preferences.get(`${toHex(bobId)}:${toHex(circleId)}`)).toEqual({ enabled: true, revision: 3n });
    b2.t.knobs.refuse.add("setSharingPreference");
    await b2.client.circles.setEnabled(circleId, false);
    expect((await b2.client.circles.list())[0]?.enabled).toBe(false);
    expect(w.host.preferences.get(`${toHex(bobId)}:${toHex(circleId)}`)).toEqual({ enabled: true, revision: 3n });
    const r = await w.sync(b2);
    expect(r.errors).toEqual([]);
    expect(w.host.preferences.get(`${toHex(bobId)}:${toHex(circleId)}`)).toEqual({ enabled: false, revision: 4n });
    // A change the host moved under us is re-sent as the latest persisted action at the served revision.
    w.host.preferences.set(`${toHex(bobId)}:${toHex(circleId)}`, { enabled: false, revision: 7n });
    await b2.client.circles.setEnabled(circleId, true);
    expect(w.host.preferences.get(`${toHex(bobId)}:${toHex(circleId)}`)).toEqual({ enabled: true, revision: 8n });
  });
});

describe("chain paging at a peer", () => {
  it("a chain served in pages is applied whole; a chain the host cannot finish serving keeps the account out of every audience", async () => {
    const w = world();
    const { a, bobId, circleId } = await pair(w);
    const first = await prepared(w, "bob");
    await first.d.client.completeReplacement({ successionId: first.proposal.successionId, authorization: first.authorization });
    const second = await prepared(w, "bob", await w.device("bob", new MemoryPlatformProvider("bob-3@platform"), new MemoryStore(), new MemorySecretStore()));
    await second.d.client.completeReplacement({ successionId: second.proposal.successionId, authorization: second.authorization });
    w.host.successionPageSize = 1;
    const epochBefore = (await a.client.inspect()).activeEpoch;
    // The second page is withheld: nothing moves, the circle pauses for metadata, no epoch is sealed to the intermediate key.
    a.t.knobs.withhold.add("successions");
    const held = await w.sync(a);
    expect(held.metadata.successions).toBe(0);
    expect(held.errors.map((e) => [e.operation, e.code, e.retryable])).toEqual([["succession", "METADATA_REQUIRED", true]]);
    // The epoch sealed to the pinned key stays; nothing is sealed to the key the first page produced.
    expect([held.epoch, (await a.client.getState()).status, (await a.client.inspect()).activeEpoch]).toEqual(["unchanged", "ready", epochBefore]);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("1");
    expect(await a.store.read((tx) => tx.get("chainProgress", toHex(bobId)))).toMatchObject({ complete: false, nextGeneration: "2" });
    // A rotation meanwhile cannot include Bob: the audience is incomplete and the stream pauses for metadata.
    await a.client.circles.setEnabled(circleId, false);
    await a.client.circles.setEnabled(circleId, true);
    const rotated = await w.sync(a);
    expect([rotated.epoch, (await a.client.getState()).status, (await a.client.getState()).paused]).toEqual(["paused", "paused", "metadata"]);
    // The pages arrive: both links are applied in one sync, the pin lands at generation 3, sharing resumes.
    a.t.knobs.withhold.delete("successions");
    const done = await w.sync(a);
    expect([done.errors, done.metadata.successions, done.epoch]).toEqual([[], 2, "prepared"]);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("3");
    expect(await a.store.read((tx) => tx.get("chainProgress", toHex(bobId)))).toBeUndefined();
    expect((await a.client.keyChanges({ accountId: bobId })).map((c) => c.generation)).toEqual([3n, 2n]);
    expect((await a.client.circles.list())[0]?.members.map(toHex)).toContain(toHex(bobId));
    expect((await a.client.getState()).status).toBe("ready");
  });
});

describe("account recovery: commits that did not plainly succeed", () => {
  it("a lost response finishes from the chain; an unreachable host leaves the proposal intact for the same call again", async () => {
    const w = world();
    await pair(w);
    const { d: b2, proposal, authorization } = await prepared(w, "bob");
    b2.t.knobs.refuse.add("succeedAccount");
    expect(await thrown(() => b2.client.completeReplacement({ successionId: proposal.successionId, authorization }))).toBe("SUCCESSION_PENDING");
    expect([(await b2.client.getState()).status, w.host.successionLog.size]).toEqual(["replacementPrepared", 0]);
    b2.t.knobs.loseResponseOf.add("succeedAccount");
    const done = await b2.client.completeReplacement({ successionId: proposal.successionId, authorization });
    expect([done.generation, w.host.successionLog.size, (await b2.client.getState()).generation]).toEqual([2n, 1, 2n]);
  });

  it("a lost response with the chain withheld, then a restart: sync finishes from ALREADY_COMMITTED without a second identity", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    const { d: b2, proposal, authorization } = await prepared(w, "bob");
    b2.t.knobs.loseResponseOf.add("succeedAccount");
    b2.t.knobs.withhold.add("successions");
    expect(await thrown(() => b2.client.completeReplacement({ successionId: proposal.successionId, authorization }))).toBe("SUCCESSION_PENDING");
    expect(w.host.successionLog.size).toBe(1);
    // The same device again, from its store: still prepared, and a plain sync finishes it.
    const again = await w.device("bob", b2.provider, b2.store, b2.secrets);
    expect((await again.client.getState()).status).toBe("replacementPrepared");
    const r = await w.sync(again);
    expect(r.errors).toEqual([]);
    expect([(await again.client.getState()).status, (await again.client.getState()).generation, w.host.successionLog.size]).toEqual(["ready", 2n, 1]);
    // completeReplacement after the fact is idempotent.
    expect((await again.client.completeReplacement({ successionId: proposal.successionId, authorization })).generation).toBe(2n);
    await w.sync(again);
    await w.sync(a);
    expect((await a.client.keyChanges({ accountId: bobId })).length).toBe(1);
  });

  it("a definitive conflict discards the proposal's keys; the next prepare is against the current state", async () => {
    const w = world();
    const { b } = await pair(w);
    const { d: b2, proposal, authorization } = await prepared(w, "bob");
    // Meanwhile Bob restores by identity continuity on a third phone: generation 2 under the same key.
    const b3 = await w.device("bob", (b.provider as MemoryPlatformProvider).twin());
    expect((await b3.client.restoreAccount()).generation).toBe(2n);
    expect(await thrown(() => b2.client.completeReplacement({ successionId: proposal.successionId, authorization }))).toBe("REPLACEMENT_CONFLICT");
    const insp = await b2.client.inspect();
    expect([insp.replacement?.stale, insp.replacement?.conflictGeneration, (await b2.client.getState()).status]).toEqual([true, 2n, "fresh"]);
    expect(await b2.secrets.get("pendingReplacement")).toBeUndefined();
    expect(await thrown(() => b2.client.completeReplacement({ successionId: proposal.successionId, authorization }))).toBe("REPLACEMENT_CONFLICT");
    const next = await b2.client.prepareReplacement();
    expect([next.expectedGeneration, toHex(next.successionId) === toHex(proposal.successionId)]).toEqual([2n, false]);
    const token = w.host.authorizeReplacement({ accountName: "bob", successionId: next.successionId, expectedCertificateHash: next.expectedCertificateHash, certificate: next.certificate });
    expect((await b2.client.completeReplacement({ successionId: next.successionId, authorization: token })).generation).toBe(3n);
  });

  it("two replacements racing for one account: exactly one commits", async () => {
    const w = world();
    await pair(w);
    const x = await prepared(w, "bob");
    const y = await prepared(w, "bob", await w.device("bob", new MemoryPlatformProvider("bob-third@platform"), new MemoryStore(), new MemorySecretStore()));
    const [rx, ry] = await Promise.all([thrown(() => x.d.client.completeReplacement({ successionId: x.proposal.successionId, authorization: x.authorization })), thrown(() => y.d.client.completeReplacement({ successionId: y.proposal.successionId, authorization: y.authorization }))]);
    expect([rx, ry].sort()).toEqual(["OK", "REPLACEMENT_CONFLICT"]);
    expect(w.host.successionLog.size).toBe(1);
  });

  it("a refused authorization leaves the proposal intact; a fresh token for the same proposal commits", async () => {
    const w = world();
    await pair(w);
    const { d: b2, proposal } = await prepared(w, "bob");
    expect(await thrown(() => b2.client.completeReplacement({ successionId: proposal.successionId, authorization: new Uint8Array(32) }))).toBe("AUTHORIZATION_REQUIRED");
    expect((await b2.client.getState()).status).toBe("replacementPrepared");
    const token = w.host.authorizeReplacement({ accountName: "bob", successionId: proposal.successionId, expectedCertificateHash: proposal.expectedCertificateHash, certificate: proposal.certificate });
    expect((await b2.client.completeReplacement({ successionId: proposal.successionId, authorization: token })).generation).toBe(2n);
    // Once activated, the call is idempotent whatever it names: the device is this account now.
    expect((await b2.client.completeReplacement({ successionId: new Uint8Array(16), authorization: token })).generation).toBe(2n);
  });

  it("the profile decides the model: continuity-only refuses to prepare, recovery-only refuses to restore", async () => {
    const cw = world({ ...testPolicy, replacement: "continuity" });
    const { b } = await pair(cw);
    const c2 = await cw.device("bob", new MemoryPlatformProvider("x@platform"));
    expect(await thrown(() => c2.client.prepareReplacement())).toBe("NOT_AUTHORIZED");
    void b;
    const rw = world({ ...testPolicy, replacement: "recovery" });
    const { b: rb } = await pair(rw);
    const r2 = await rw.device("bob", (rb.provider as MemoryPlatformProvider).twin());
    expect(await thrown(() => r2.client.restoreAccount())).toBe("NOT_AUTHORIZED");
    expect((await r2.client.prepareReplacement()).expectedGeneration).toBe(1n);
  });
});
