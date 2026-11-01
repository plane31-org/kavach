/**
 * Amendment A1, section 8: the required tests not covered by the fixture cases, the host tests and
 * the client replacement tests. Every scenario runs over the fake host behind a MaliciousTransport.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.js";
import { buildResetKeyList, buildResetReceipt } from "../src/codec.js";
import { C, H, randomBytes, ready, signingKeypairFromSeed } from "../src/crypto.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { MemoryPlatformProvider } from "../src/testing/providers.js";
import { enqueueLocation } from "./location.js";
import { DAY, management, operational, operationalId, pair, thrown, world, type Dev, type World } from "./clientWorld.js";

beforeAll(() => ready());

async function recover(w: World, name: string, provider = new MemoryPlatformProvider(`${name}-${Math.random()}@platform`)): Promise<Dev> {
  const d = await w.device(name, provider, new MemoryStore(), new MemorySecretStore());
  const proposal = await d.client.prepareReplacement();
  const authorization = w.host.authorizeReplacement({ accountName: name, successionId: proposal.successionId, expectedCertificateHash: proposal.expectedCertificateHash, certificate: proposal.certificate });
  await d.client.completeReplacement({ successionId: proposal.successionId, authorization });
  return d;
}

/** Alice owns a circle with Bob and Carol; everyone has synced. */
async function trio(w: World) {
  const p = await pair(w);
  const c = await w.device("carol");
  await c.client.initializeAccount();
  const carolId = (await c.client.inspect()).identityId ?? new Uint8Array();
  await c.client.circles.requestJoin(p.circleId, p.aliceId);
  await w.sync(p.a);
  await p.a.client.circles.approve(p.circleId, "carol");
  await w.sync(p.a);
  await w.sync(c);
  await w.sync(p.b);
  await w.sync(p.a);
  return { ...p, c, carolId };
}

describe("peers and owners around a succession", () => {
  it("a member succeeds while the owner is offline: another member rotates first, the owner when it returns, both to the same key", async () => {
    const w = world();
    const { a, c, bobId } = await trio(w);
    const b2 = await recover(w, "bob");
    await w.sync(b2);
    const cr = await w.sync(c);
    expect([cr.errors, cr.metadata.successions, cr.epoch]).toEqual([[], 1, "prepared"]);
    const ar = await w.sync(a);
    expect([ar.errors, ar.metadata.successions, ar.epoch]).toEqual([[], 1, "prepared"]);
    const pins = await Promise.all([a, c].map((d) => d.store.read((tx) => tx.get("pins", toHex(bobId))?.certificateHash)));
    expect(pins[0]).toBe(pins[1]);
    expect(pins[0]).toBe(toHex((await b2.client.getState()).certificateHash ?? new Uint8Array()));
  });

  it("mixed transitions: an identity-continuity activation the peer never saw, then a succession from it, accepted on the succession alone", async () => {
    const w = world();
    const { a, b, bobId } = await pair(w);
    const b2 = await w.device("bob", (b.provider as MemoryPlatformProvider).twin());
    expect((await b2.client.restoreAccount()).generation).toBe(2n);
    await w.sync(b2);
    const b3 = await recover(w, "bob");
    expect((await b3.client.getState()).generation).toBe(3n);
    const r = await w.sync(a); // Alice is pinned at generation 1 under the old key
    expect([r.errors, r.metadata.successions]).toEqual([[], 1]);
    const pin = await a.store.read((tx) => tx.get("pins", toHex(bobId)));
    expect([pin?.generation, pin?.accountKey]).toEqual(["3", toHex(w.host.accounts.get("bob")?.accountKey ?? new Uint8Array())]);
    expect((await a.client.keyChanges({ accountId: bobId })).map((c) => c.generation)).toEqual([3n]);
  });

  it("an owner's succession: the host refuses the retired key, a member bootstrapping in the window verifies the retired-key snapshot, and follows the republication", async () => {
    const w = world();
    const { b, circleId, aliceId } = await pair(w);
    const oldCert = fromHex(w.host.accounts.get("alice")?.certificateHash ?? "");
    const servedBefore = w.host.circles.get(toHex(circleId))?.snapshot ?? new Uint8Array();
    const a2 = await recover(w, "alice"); // not synced yet: no republication
    expect(w.host.circles.get(toHex(circleId))?.revision).toBe(2n);
    // The retired device cannot publish: the host's fence.
    const refused = await w.host.asDevice("alice", oldCert).directory.publishOwnedCircle({ circleId, expectedRevision: 2n, expectedHash: undefined, newSnapshot: servedBefore });
    expect(refused.status).toBe("UNAUTHORIZED");
    // Bob's replacement bootstraps in the window: the served snapshot is signed by Alice's retired key.
    const b2 = await recover(w, "bob");
    const br = await w.sync(b2);
    expect([br.errors, br.bootstrap]).toEqual([[], { circles: 1, pending: 0, failed: 0 }]);
    expect((await b2.client.circles.list()).map((c) => [toHex(c.ownerIdentityId), c.revision, c.status])).toEqual([[toHex(aliceId), 2n, "member"]]);
    const ownerPin = await b2.store.read((tx) => tx.get("pins", toHex(aliceId)));
    expect(ownerPin?.accountKey).toBe(toHex(w.host.accounts.get("alice")?.accountKey ?? new Uint8Array()));
    // The successor owner republishes at 3; Bob's replacement follows it under the new key.
    const ar = await w.sync(a2);
    expect([ar.errors, ar.bootstrap?.circles, w.host.circles.get(toHex(circleId))?.revision]).toEqual([[], 1, 3n]);
    const br2 = await w.sync(b2);
    expect([br2.errors, br2.metadata.snapshots, (await b2.client.circles.list())[0]?.revision]).toEqual([[], 1, 3n]);
    // Bob's old phone was replaced along the way: it retires, and reads nothing of this.
    await w.sync(b);
    expect((await b.client.getState()).status).toBe("retired");
  });

  it("removed, departed, pending, disabled and closed circles across a succession: discovery pins exactly what the account still has", async () => {
    const w = world();
    const { a, b, circleId: main, bobId } = await pair(w);
    const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
    // A circle Bob was removed from, one he left, one he is pending in, one disabled, one closed.
    const removed = (await a.client.circles.create()).circleId;
    const left = (await a.client.circles.create()).circleId;
    const pending = (await a.client.circles.create()).circleId;
    const disabled = (await a.client.circles.create()).circleId;
    const closed = (await a.client.circles.create()).circleId;
    for (const id of [removed, left, disabled, closed]) {
      await b.client.circles.requestJoin(id, aliceId);
      await w.sync(a);
      await a.client.circles.approve(id, "bob");
    }
    await b.client.circles.requestJoin(pending, aliceId);
    await w.sync(a);
    await w.sync(b);
    await a.client.circles.remove(removed, bobId);
    await b.client.circles.leave(left);
    await w.sync(a);
    await b.client.circles.setEnabled(disabled, false);
    await a.client.circles.closeCircle(closed);
    await w.sync(b);
    const b2 = await recover(w, "bob");
    const r = await w.sync(b2);
    expect(r.errors).toEqual([]);
    expect(r.bootstrap).toEqual({ circles: 2, pending: 1, failed: 0 });
    const list = new Map((await b2.client.circles.list()).map((c) => [toHex(c.circleId), c]));
    expect([...list.keys()].sort()).toEqual([toHex(main), toHex(pending), toHex(disabled)].sort());
    expect([list.get(toHex(main))?.status, list.get(toHex(main))?.enabled]).toEqual(["member", true]);
    expect([list.get(toHex(disabled))?.status, list.get(toHex(disabled))?.enabled]).toEqual(["member", false]);
    // The preference chosen at request time (share on approval) travelled through the host.
    expect([list.get(toHex(pending))?.status, list.get(toHex(pending))?.enabled]).toEqual(["requested", true]);
    // The pending request is still the owner's to approve, and lands on the replacement.
    await w.sync(a);
    await a.client.circles.approve(pending, "bob");
    await w.sync(a);
    await w.sync(b2);
    expect((await b2.client.circles.list()).find((c) => toHex(c.circleId) === toHex(pending))?.status).toBe("member");
  });

  it("discovery pages interrupted and resumed: a restart continues from the cursor and never erases a circle already pinned", async () => {
    const w = world();
    const { a, b } = await pair(w);
    const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
    const ids = [(await a.client.circles.create()).circleId, (await a.client.circles.create()).circleId];
    for (const id of ids) {
      await b.client.circles.requestJoin(id, aliceId);
      await w.sync(a);
      await a.client.circles.approve(id, "bob");
    }
    await w.sync(a);
    await w.sync(b);
    w.host.circlePageSize = 1;
    w.host.failCircleListAt = 2;
    const b2 = await recover(w, "bob");
    const first = await w.sync(b2);
    expect([first.bootstrap, first.errors.map((e) => e.operation)]).toEqual([{ circles: 1, pending: 0, failed: 0 }, ["bootstrap"]]);
    const mid = await b2.client.inspect();
    expect([mid.bootstrap?.complete, mid.bootstrap?.cursor !== undefined]).toEqual([false, true]);
    expect((await b2.client.circles.list()).length).toBe(1);
    // A restart from the same store resumes at the cursor.
    const again = await w.device("bob", b2.provider, b2.store, b2.secrets);
    const second = await w.sync(again);
    expect([second.errors, second.bootstrap]).toEqual([[], { circles: 2, pending: 0, failed: 0 }]);
    expect([(await again.client.inspect()).bootstrap, (await again.client.circles.list()).length]).toEqual([{ cursor: undefined, complete: true }, 3]);
    const third = await w.sync(again);
    expect(third.bootstrap).toBeUndefined();
  });

  it("the bootstrap limit: a host serving a pre-removal snapshot makes the fresh device share with a once-admitted member until the newer snapshot arrives", async () => {
    const w = world();
    const { a, circleId, carolId } = await trio(w);
    const stale = { ...w.host.circles.get(toHex(circleId)) };
    await a.client.circles.remove(circleId, carolId);
    const current = { ...w.host.circles.get(toHex(circleId)) };
    expect([stale.revision, current.revision]).toEqual([3n, 4n]);
    // The malicious host serves the old snapshot to the fresh device.
    w.host.circles.set(toHex(circleId), stale as never);
    const b2 = await recover(w, "bob");
    await w.sync(b2);
    expect((await b2.client.circles.list())[0]?.members.map(toHex)).toContain(toHex(carolId));
    // Carol was once admitted: that is the bound. The newer snapshot corrects it.
    w.host.circles.set(toHex(circleId), current as never);
    const r = await w.sync(b2);
    expect([r.errors, r.metadata.snapshots]).toEqual([[], 1]);
    expect((await b2.client.circles.list())[0]?.members.map(toHex)).not.toContain(toHex(carolId));
  });
});

describe("authority keys over time", () => {
  function rotateAuthority(w: World, version: bigint) {
    const key = signingKeypairFromSeed(H(C("fixture-rotated-authority")));
    const keyId = new Uint8Array(16).fill(9);
    w.host.resetSigner = { key, keyId };
    w.host.resetKeyList = buildResetKeyList({ version, issuedAt: w.clock.now(), expiresAt: w.clock.now() + 30n * DAY, keys: [{ keyId, publicKey: key.publicKey }] }, management.secretKey);
    return { key, keyId };
  }

  it("a long-offline peer across an authority-key rotation verifies a re-attested link, and refuses an unseen link under a revoked key without re-attestation", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    const b2 = await recover(w, "bob"); // attested under the first operational key
    await w.sync(b2);
    rotateAuthority(w, 2n);
    w.clock.advance(2n * DAY); // the peer's list is stale: it refetches and installs version 2
    const r = await w.sync(a);
    expect([r.errors, r.metadata.successions]).toEqual([[], 1]);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("2");
    // The same, with a host that does not re-attest: the link's signer is revoked.
    const w2 = world();
    const { a: a2, bobId: bob2Id } = await pair(w2);
    const c2 = await recover(w2, "bob");
    await w2.sync(c2);
    rotateAuthority(w2, 2n);
    w2.host.reattest = false;
    w2.clock.advance(2n * DAY);
    const r2 = await w2.sync(a2);
    expect([r2.metadata.successions, r2.metadata.rotations, r2.errors.map((e) => e.code)]).toEqual([0, 0, ["RESET_KEY_REVOKED"]]);
    expect((await a2.store.read((tx) => tx.get("pins", toHex(bob2Id))))?.generation).toBe("1");
  });

  it("a succession by an authority key the list never allowed is refused by the replacing device and by every peer", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    const rogue = signingKeypairFromSeed(H(C("fixture-rogue-authority")));
    w.host.resetSigner = { key: rogue, keyId: new Uint8Array(16).fill(3) };
    w.host.reattest = false;
    // The replacing device itself cannot verify what the host signed: it stays prepared, the host has moved.
    const d = await w.device("bob", new MemoryPlatformProvider("bob-rogue@platform"), new MemoryStore(), new MemorySecretStore());
    const p = await d.client.prepareReplacement();
    const token = w.host.authorizeReplacement({ accountName: "bob", successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });
    expect(await thrown(() => d.client.completeReplacement({ successionId: p.successionId, authorization: token }))).toBe("RESET_KEY_REVOKED");
    expect([(await d.client.getState()).status, w.host.accounts.get("bob")?.generation]).toEqual(["replacementPrepared", 2n]);
    const r = await w.sync(a);
    expect([r.metadata.successions, r.metadata.quarantined, r.errors.map((e) => e.code)]).toEqual([0, 0, ["RESET_KEY_REVOKED"]]);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("1");
    expect(a.events.some((e) => e.kind === "accountKeyChanged")).toBe(false);
  });
});

describe("crashes and restarts", () => {
  it("a crash between the acceptance transaction and the event: on restart the key-change row is present and the succession is a duplicate", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    const b2 = await recover(w, "bob");
    await w.sync(b2);
    await w.sync(a);
    const again = await w.device("alice", a.provider, a.store, a.secrets);
    const r = await w.sync(again);
    expect([r.errors, r.metadata.successions, r.epoch]).toEqual([[], 0, "unchanged"]);
    expect((await again.client.keyChanges({ accountId: bobId })).length).toBe(1);
    expect(again.events.some((e) => e.kind === "accountKeyChanged")).toBe(false);
  });

  it("crashes around T11 and the commit: before the row nothing exists, after it the same proposal returns, after the commit a restart finishes", async () => {
    const w = world();
    await pair(w);
    const d = await w.device("bob", new MemoryPlatformProvider("bob-new@platform"), new MemoryStore(), new MemorySecretStore());
    // Roots written, row not yet (a crash inside T11): the next prepare starts over.
    await d.secrets.set("pendingReplacement", randomBytes(128));
    const p1 = await d.client.prepareReplacement();
    expect((await d.client.getState()).status).toBe("replacementPrepared");
    // Restart: the same proposal.
    const d2 = await w.device("bob", d.provider, d.store, d.secrets);
    const p2 = await d2.client.prepareReplacement();
    expect(toHex(p2.successionId)).toBe(toHex(p1.successionId));
    // Commit, then a crash before the activation's own roots were deleted: the device is ready either way.
    const token = w.host.authorizeReplacement({ accountName: "bob", successionId: p2.successionId, expectedCertificateHash: p2.expectedCertificateHash, certificate: p2.certificate });
    await d2.client.completeReplacement({ successionId: p2.successionId, authorization: token });
    const d3 = await w.device("bob", d.provider, d.store, d.secrets);
    expect((await d3.client.getState()).generation).toBe(2n);
    expect((await d3.client.completeReplacement({ successionId: p2.successionId, authorization: token })).generation).toBe(2n);
  });
});

describe("the lost device, resets and the composition of both models", () => {
  it("the attacker with the complete old state cannot obtain a succession without the product's authentication", async () => {
    const w = world();
    const { b } = await pair(w);
    const b2 = await recover(w, "bob");
    await w.sync(b2);
    // The old phone, in the attacker's hands, prepares a replacement like anyone, and gets nowhere without a token.
    const attacker = await w.device("bob", b.provider, new MemoryStore(), new MemorySecretStore());
    const p = await attacker.client.prepareReplacement();
    expect(p.expectedGeneration).toBe(2n);
    expect(await thrown(() => attacker.client.completeReplacement({ successionId: p.successionId, authorization: randomBytes(32) }))).toBe("AUTHORIZATION_REQUIRED");
    expect(w.host.accounts.get("bob")?.generation).toBe(2n);
    // Nor through the recovery key: the vault the succession installed is under a key the old phone never had.
    expect(await thrown(() => attacker.client.restoreAccount())).not.toBe("OK");
  });

  it("succession, then reset: a receipt naming the current key closes the account's circles everywhere; one naming the retired key is RESET_BINDING", async () => {
    const w = world();
    const { b, circleId, aliceId } = await pair(w);
    const a2 = await recover(w, "alice");
    await w.sync(a2);
    await w.sync(b);
    const oldKeyIdentity = fromHex((await b.store.read((tx) => tx.list("identities").find(([, i]) => i.accountId === toHex(aliceId) && i.retired)?.[0])) ?? "");
    expect(oldKeyIdentity.length).toBe(32);
    // The current device resets. The host first serves a receipt forged to name the retired key A
    // as the old identity: RESET_BINDING, the key quarantined, nothing closed.
    await a2.client.resetAccount({ confirmed: true });
    const acct = w.host.accounts.get("alice");
    const real = acct?.resetReceipt;
    const forged = buildResetReceipt({ accountName: "alice", oldIdentityId: oldKeyIdentity, newIdentityId: fromHex(acct?.identityId ?? ""), resetId: randomBytes(16), issuedAt: w.clock.now(), authorityKeyId: operationalId }, operational.secretKey);
    if (acct) acct.resetReceipt = forged;
    const r = await w.sync(b);
    expect([r.errors.map((e) => e.code), r.metadata.quarantined]).toEqual([["RESET_BINDING"], 1]);
    expect((await b.client.circles.list()).find((c) => toHex(c.circleId) === toHex(circleId))?.status).toBe("member");
    // The real receipt names B, the current key: the circle closes, the whole chain is retired.
    if (acct) acct.resetReceipt = real;
    const r2 = await w.sync(b);
    expect([r2.errors, r2.metadata.resets]).toEqual([[], 1]);
    expect((await b.client.circles.list()).find((c) => toHex(c.circleId) === toHex(circleId))?.status).toBe("closed");
    const ids = await b.store.read((tx) => tx.list("identities").filter(([, i]) => i.accountId === toHex(aliceId)));
    expect(ids.every(([, i]) => i.retired)).toBe(true);
    expect(ids.find(([k]) => k === toHex(aliceId))?.[1].resetAt).toBeDefined();
  });

  it("the composition of both models: enrollment under A, a succession to B, a bootstrap with a fresh vault, then identity continuity on a third device", async () => {
    const w = world();
    const { a, circleId, bobId, aliceId } = await pair(w);
    const b2 = await recover(w, "bob");
    await w.sync(b2);
    await b2.client.circles.setEnabled(circleId, true);
    await w.sync(b2);
    await w.sync(a);
    const b3 = await w.device("bob", (b2.provider as MemoryPlatformProvider).twin());
    const restored = await b3.client.restoreAccount();
    expect(restored.generation).toBe(3n);
    const insp = await b3.client.inspect();
    expect([toHex(insp.identityId ?? new Uint8Array()), toHex(insp.keyIdentityId ?? new Uint8Array()) === toHex(bobId)]).toEqual([toHex(bobId), false]);
    const evidence = await b3.store.read((tx) => ({ successions: tx.list("successions").map(([, s]) => [s.previousGeneration, s.newGeneration]), identities: tx.list("identities").filter(([, i]) => i.accountId === toHex(bobId)).length }));
    expect([evidence.successions, evidence.identities]).toEqual([[["1", "2"]], 2]);
    await w.sync(b3);
    expect((await b3.client.circles.list()).map((c) => [toHex(c.circleId), c.status, c.enabled])).toEqual([[toHex(circleId), "member", true]]);
    await w.sync(a);
    await enqueueLocation(b3.client, w.loc(4));
    await w.sync(b3);
    await w.sync(a);
    expect((await a.client.history({ authorIdentityId: bobId })).length).toBeGreaterThanOrEqual(1);
    await enqueueLocation(a.client, w.loc(5));
    await w.sync(a);
    await w.sync(b3);
    expect((await b3.client.history({ authorIdentityId: aliceId })).length).toBe(1);
    await w.sync(b2);
    expect((await b2.client.getState()).status).toBe("retired");
  });

  it("a late success for an older preference request leaves the newer change in place and never moves the revision back", async () => {
    const w = world();
    const { b, circleId, bobId } = await pair(w);
    const key = `${toHex(bobId)}:${toHex(circleId)}`;
    let release: () => void = () => undefined;
    b.t.knobs.hold.set("setSharingPreference", new Promise<void>((res) => (release = res)));
    expect(w.host.preferences.get(key)).toEqual({ enabled: true, revision: 1n }); // set when Bob asked to join
    const first = b.client.circles.setEnabled(circleId, false); // held after the host took it at revision 2
    await new Promise((r) => setTimeout(r, 10));
    await b.client.circles.setEnabled(circleId, true); // conflicts at 1, retries at 2, lands at 3
    expect(w.host.preferences.get(key)).toEqual({ enabled: true, revision: 3n });
    release();
    await first;
    const row = await b.store.read((tx) => tx.get("preferences", toHex(circleId)));
    expect([row?.pending, row?.revision, row?.enabled]).toEqual([undefined, "3", true]);
    expect((await b.client.circles.list())[0]?.enabled).toBe(true);
  });
});
