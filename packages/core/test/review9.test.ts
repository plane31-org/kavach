/** Regressions from the revision 9 review: the five reproductions, and the optional recovery provider. */
import { beforeAll, describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.js";
import { open } from "../src/client.js";
import { DocumentType, buildCircleSnapshot, buildResetKeyList, buildSuccession, expectType, parseDocument, verifyDocument, type AccountDevice, type AccountSuccession, type CircleSnapshot } from "../src/codec.js";
import { C, H, randomBytes, ready, signingKeypairFromSeed } from "../src/crypto.js";
import { certify, newAccountSeed, newDevice, openAccount, pinFromCertificate } from "../src/identity.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { testPolicy } from "../src/testing/clock.js";
import { MemoryPlatformProvider } from "../src/testing/providers.js";
import { hostTransport } from "../src/testing/sweep.js";
import type { Transport } from "../src/transport.js";
import { DAY, management, pair, resetTrust, thrown, world, type Dev, type World } from "./clientWorld.js";

beforeAll(() => ready());

/** A succession committed at the host without any client: a fresh key for `name` at the next generation. */
async function hostSuccession(w: World, name: string) {
  const a = w.host.accounts.get(name);
  if (!a) throw new Error("unknown account");
  const account = openAccount(name, newAccountSeed());
  const device = newDevice();
  const certificate = certify(account, device, a.generation + 1n);
  const successionId = randomBytes(16);
  const expectedCertificateHash = fromHex(a.certificateHash);
  const authorization = w.host.authorizeReplacement({ accountName: name, successionId, expectedCertificateHash, certificate });
  const outcome = await w.host.asDevice(name, expectedCertificateHash).directory.succeedAccount({ accountName: name, expectedCertificateHash, newCertificate: certificate, newVault: undefined, successionId, authorization });
  expect(outcome.status).toBe("COMMITTED");
  return { account, device, certificate, pin: pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice)) };
}

async function recover(w: World, name: string): Promise<Dev> {
  const d = await w.device(name, new MemoryPlatformProvider(`${name}-${Math.random()}@platform`), new MemoryStore(), new MemorySecretStore());
  const p = await d.client.prepareReplacement();
  const token = w.host.authorizeReplacement({ accountName: name, successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });
  await d.client.completeReplacement({ successionId: p.successionId, authorization: token });
  return d;
}

/** Carol joins Alice's circle after Bob's key changed, so her first contact with Bob comes with a chain. */
async function carolAfterBobsChain(w: World) {
  const p = await pair(w);
  await hostSuccession(w, "bob");
  const c = await w.device("carol");
  await c.client.initializeAccount();
  await c.client.circles.requestJoin(p.circleId, p.aliceId);
  await w.sync(p.a);
  await p.a.client.circles.approve(p.circleId, "carol");
  await w.sync(p.a);
  return { ...p, c };
}

describe("1: first contact under the policy gate and verification", () => {
  it("a continuity-only client meeting a chained account at first contact pins nothing and quarantines the key", async () => {
    const w = world({ ...testPolicy, replacement: "continuity" });
    const { c, bobId } = await carolAfterBobsChain(w);
    const r = await w.sync(c);
    expect(r.errors.map((e) => e.code)).toContain("UNSUPPORTED_TYPE");
    expect(r.metadata.quarantined).toBe(1);
    expect(await c.store.read((tx) => tx.get("pins", toHex(bobId)))).toBeUndefined();
    expect(await c.store.read((tx) => tx.get("quarantine", "bob"))).toMatchObject({ reason: "succession refused" });
    expect(c.events.some((e) => e.kind === "accountKeyChanged" && e.quarantined)).toBe(true);
    // Bob is a member she cannot seal to: the stream pauses for metadata rather than guessing.
    expect([(await c.client.getState()).status, (await c.client.getState()).paused]).toEqual(["paused", "metadata"]);
  });

  it("a client that enables account recovery refuses a chain whose attestation does not verify, and pins nothing", async () => {
    const w = world();
    const { c, bobId } = await carolAfterBobsChain(w);
    c.t.knobs.tamper.add("succession");
    const r = await w.sync(c);
    expect(r.errors.map((e) => e.code)).toContain("BAD_SIGNATURE");
    expect(await c.store.read((tx) => tx.get("pins", toHex(bobId)))).toBeUndefined();
    expect(await c.store.read((tx) => tx.count("identities"))).toBe(2); // herself and Alice
    // Honest bytes on the next sync: pinned under the root id with the chain recorded.
    c.t.knobs.tamper.delete("succession");
    const ok = await w.sync(c);
    expect(ok.errors).toEqual([]);
    const pin = await c.store.read((tx) => tx.get("pins", toHex(bobId)));
    expect([pin?.accountId, pin?.generation]).toEqual([toHex(bobId), "2"]);
    expect(await c.store.read((tx) => tx.list("successions").filter(([, s]) => s.accountId === toHex(bobId)).length)).toBe(1);
  });
});

describe("2: retired owner keys", () => {
  it("after the successor owner is accepted, a snapshot under the retired key does not advance an established circle", async () => {
    const w = world();
    const { a, b, circleId, aliceId } = await pair(w);
    const oldSeed = (await a.secrets.get("accountSeed")) ?? new Uint8Array(32);
    const oldOwner = openAccount("alice", oldSeed);
    const a2 = await recover(w, "alice");
    await w.sync(a2); // republishes at revision 3 under the new key
    const br = await w.sync(b);
    expect([br.errors, (await b.client.circles.list())[0]?.revision]).toEqual([[], 3n]);
    // The host now serves a revision 100 signed by the retired key.
    const forged = buildCircleSnapshot({ circleId, ownerIdentityId: aliceId, revision: 100n, members: [aliceId] }, oldOwner.account.secretKey);
    const doc = expectType<CircleSnapshot>(parseDocument(forged), DocumentType.CircleSnapshot);
    const row = w.host.circles.get(toHex(circleId));
    if (row) w.host.circles.set(toHex(circleId), { ...row, snapshot: forged, revision: 100n, hash: toHex(doc.bodyHash) });
    const r = await w.sync(b);
    expect(r.errors.map((e) => e.code)).toEqual(["BAD_SIGNATURE"]);
    expect((await b.client.circles.list())[0]).toMatchObject({ revision: 3n, status: "member" });
    expect((await b.client.circles.list())[0]?.members.length).toBe(2);
  });
});

describe("4: bootstrap failures are retried, never skipped", () => {
  it("an owner that cannot be resolved on one sync is adopted on the next, and the error names the circle", async () => {
    const w = world();
    const { circleId } = await pair(w);
    const b2 = await recover(w, "bob");
    b2.t.knobs.withhold.add("certificates");
    const first = await w.sync(b2);
    expect(first.bootstrap).toEqual({ circles: 0, pending: 0, failed: 1 });
    const err = first.errors.find((e) => e.operation === "bootstrap");
    expect([err?.code, toHex(err?.circleId ?? new Uint8Array())]).toEqual(["METADATA_REQUIRED", toHex(circleId)]);
    expect((await b2.client.inspect()).bootstrap?.complete).toBe(false);
    expect((await b2.client.circles.list()).length).toBe(0);
    b2.t.knobs.withhold.delete("certificates");
    const second = await w.sync(b2);
    expect([second.errors, second.bootstrap]).toEqual([[], { circles: 1, pending: 0, failed: 0 }]);
    expect([(await b2.client.inspect()).bootstrap?.complete, (await b2.client.circles.list()).length]).toEqual([true, 1]);
    const third = await w.sync(b2);
    expect(third.bootstrap).toBeUndefined();
  });
});

describe("5: chain paging resumes within the budget", () => {
  it("a chain longer than one sync's budget is verified across syncs from where it stopped, and the pin moves once, at the end", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    await recover(w, "bob");
    await recover(w, "bob");
    w.host.successionPageSize = 1;
    const calls = w.host.successionCalls.length;
    const first = await a.client.sync({ catchUp: { maxRecords: 1, maxMs: 5000 } });
    expect(first.errors.map((e) => e.code)).toEqual(["METADATA_REQUIRED"]);
    expect(first.metadata.successions).toBe(0);
    // The first link (served with the account) used the budget: nothing was fetched, the prefix is kept.
    expect(w.host.successionCalls.length - calls).toBe(0);
    expect(await a.store.read((tx) => tx.get("chainProgress", toHex(bobId)))).toMatchObject({ nextGeneration: "2", links: [expect.any(Object)] });
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("1");
    const second = await w.sync(a);
    expect([second.errors, second.metadata.successions]).toEqual([[], 2]);
    // Resumed after the verified prefix: the only fetch asked for what follows generation 2.
    expect(w.host.successionCalls.slice(calls).map((c) => c.afterGeneration)).toEqual([2n]);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("3");
    expect(await a.store.read((tx) => tx.get("chainProgress", toHex(bobId)))).toBeUndefined();
  });
});

describe("second review: chains over time", () => {
  it("a second replacement after a peer accepted the first: the served chain is reconciled with the accepted prefix and applied", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    await recover(w, "bob");
    const first = await w.sync(a);
    expect([first.errors, first.metadata.successions]).toEqual([[], 1]);
    await recover(w, "bob");
    const second = await w.sync(a);
    expect([second.errors, second.metadata.successions]).toEqual([[], 1]);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("3");
    expect((await a.client.keyChanges({ accountId: bobId })).map((c) => c.generation)).toEqual([3n, 2n]);
    // And a third, with a sync in between again.
    await recover(w, "bob");
    const third = await w.sync(a);
    expect([third.errors, third.metadata.successions, (await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation]).toEqual([[], 1, "4"]);
  });

  it("a return to a retired identity is refused by a first contact exactly as by an established peer", async () => {
    const w = world();
    const { a, b, circleId, aliceId, bobId } = await pair(w);
    const seedA = (await b.secrets.get("accountSeed")) ?? new Uint8Array(32);
    await recover(w, "bob"); // A -> B
    // The host signs a succession back to A's key (it checks only that the key differs from the current one).
    const acct = w.host.accounts.get("bob");
    if (!acct) throw new Error("bob");
    const accountA = openAccount("bob", seedA);
    const device = newDevice();
    const certificate = certify(accountA, device, acct.generation + 1n);
    const successionId = randomBytes(16);
    const expected = fromHex(acct.certificateHash);
    const token = w.host.authorizeReplacement({ accountName: "bob", successionId, expectedCertificateHash: expected, certificate });
    expect((await w.host.asDevice("bob", expected).directory.succeedAccount({ accountName: "bob", expectedCertificateHash: expected, newCertificate: certificate, newVault: undefined, successionId, authorization: token })).status).toBe("COMMITTED");
    // Carol, a first contact, and Alice, established at A: both refuse, neither pins A again.
    const c = await w.device("carol");
    await c.client.initializeAccount();
    await c.client.circles.requestJoin(circleId, aliceId);
    await w.sync(a);
    await a.client.circles.approve(circleId, "carol");
    await w.sync(a);
    const cr = await w.sync(c);
    expect(cr.errors.map((e) => e.code)).toContain("SUPERSEDED_IDENTITY");
    expect(await c.store.read((tx) => tx.get("pins", toHex(bobId)))).toBeUndefined();
    const ar = await w.sync(a);
    expect(ar.errors.map((e) => e.code)).toContain("SUPERSEDED_IDENTITY");
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("1");
    expect(a.events.some((e) => e.kind === "securityError" && e.code === "SUPERSEDED_IDENTITY")).toBe(true);
  });
});

describe("third review: chains under rotation, budgets and forgeries", () => {
  function rotateAuthority(w: World) {
    const key = signingKeypairFromSeed(H(C("fixture-rotated-authority-3")));
    const keyId = new Uint8Array(16).fill(11);
    w.host.resetSigner = { key, keyId };
    w.host.resetKeyList = buildResetKeyList({ version: 2n, issuedAt: w.clock.now(), expiresAt: w.clock.now() + 30n * DAY, keys: [{ keyId, publicKey: key.publicKey }] }, management.secretKey);
  }

  it("1: an authority rotation after a cached page: the stale prefix is refreshed from the host, and the chain completes", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    await recover(w, "bob");
    await recover(w, "bob");
    w.host.successionPageSize = 1;
    const held = await a.client.sync({ catchUp: { maxRecords: 1, maxMs: 5000 } });
    expect(held.errors.map((e) => e.code)).toEqual(["METADATA_REQUIRED"]);
    rotateAuthority(w);
    w.clock.advance(2n * DAY);
    const done = await w.sync(a);
    expect([done.errors, done.metadata.successions]).toEqual([[], 2]);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("3");
    // Without re-attestation the stale link stays refused, the pin stays, and nothing is recorded.
    const w2 = world();
    const { a: a2, bobId: bob2 } = await pair(w2);
    await recover(w2, "bob");
    await recover(w2, "bob");
    w2.host.successionPageSize = 1;
    await a2.client.sync({ catchUp: { maxRecords: 1, maxMs: 5000 } });
    rotateAuthority(w2);
    w2.host.reattest = false;
    w2.clock.advance(2n * DAY);
    const refused = await w2.sync(a2);
    expect([refused.errors.map((e) => e.code), refused.metadata.successions]).toEqual([["RESET_KEY_REVOKED"], 0]);
    expect((await a2.store.read((tx) => tx.get("pins", toHex(bob2))))?.generation).toBe("1");
  });

  it("2: with one-link pages and a budget of one, a peer that accepted two replacements still reaches the third", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    await recover(w, "bob");
    await w.sync(a);
    await recover(w, "bob");
    await w.sync(a);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("3");
    await recover(w, "bob");
    w.host.successionPageSize = 1;
    let generation = "3";
    for (let i = 0; i < 5 && generation !== "4"; i++) {
      await a.client.sync({ catchUp: { maxRecords: 1, maxMs: 5000 } });
      generation = (await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation ?? "";
    }
    expect(generation).toBe("4");
    expect(await a.store.read((tx) => tx.get("chainProgress", toHex(bobId)))).toBeUndefined();
  });

  it("3: a forged change to an accepted transition is a bad signature, never evidence of equivocation", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    await recover(w, "bob");
    await w.sync(a);
    await recover(w, "bob");
    const rogue = signingKeypairFromSeed(H(C("fixture-forger")));
    const forgeFirst = (links: readonly { wire: Uint8Array; certificate: Uint8Array }[]) => {
      const [first, ...rest] = links;
      if (!first) return links;
      const doc = expectType<AccountSuccession>(parseDocument(first.wire), DocumentType.AccountSuccession);
      const { type: _t, ...f } = doc;
      void _t;
      // The same succession id and state, a different successor certificate, signed by nobody the list allows.
      const wire = buildSuccession({ ...f, newCertificateHash: randomBytes(32) }, rogue.secretKey);
      return [{ wire, certificate: first.certificate }, ...rest];
    };
    const inner = a.t;
    const transport: Transport = {
      directory: new Proxy(inner.directory, {
        get: (d, prop) =>
          prop === "resolveIdentities"
            ? async (ids: readonly Uint8Array[]) => (await d.resolveIdentities(ids)).map((r) => (r.accountName === "bob" && r.successions ? { ...r, successions: forgeFirst(r.successions) } : r))
            : Reflect.get(d, prop)
      }),
      relay: inner.relay
    };
    const alice = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: a.store, transport, now: w.clock.now });
    const events: string[] = [];
    alice.subscribe((e) => {
      if (e.kind === "securityError") events.push(e.code);
    });
    w.clock.advance(1_000n);
    const r = await alice.sync();
    expect(r.errors.map((e) => e.code)).toEqual(["BAD_SIGNATURE"]);
    expect(events).toEqual([]);
    expect((await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation).toBe("2");
  });

  it("4: a recovery code is issued only where identity continuity can use it", async () => {
    const recovery = { ...testPolicy, replacement: "recovery" as const };
    const w = world(recovery);
    const bare = await open({ accountName: "alice", retentionPolicy: recovery, resetTrust, secretStore: new MemorySecretStore(), store: new MemoryStore(), transport: hostTransport(w.host, "alice"), now: w.clock.now });
    await bare.initializeAccount();
    expect(await thrown(() => bare.recoveryCode())).toBe("NOT_AUTHORIZED");
    const withProvider = await w.device("bob");
    await withProvider.client.initializeAccount();
    expect(await thrown(() => withProvider.client.recoveryCode())).toBe("NOT_AUTHORIZED");
    const both = world();
    const { a } = await pair(both);
    expect((await a.client.recoveryCode()).startsWith("KV1R-")).toBe(true);
  });
});

describe("fourth review: the replacement device holds its account's whole chain", () => {
  it("an owner replaced twice without a bootstrap between: the newest phone still verifies the circle it owns", async () => {
    const w = world();
    const { b, aliceId } = await pair(w);
    await recover(w, "alice"); // A -> B, never synced
    const a3 = await recover(w, "alice"); // B -> C
    const r = await w.sync(a3);
    expect([r.errors, r.bootstrap]).toEqual([[], { circles: 1, pending: 0, failed: 0 }]);
    expect((await a3.client.circles.list()).map((c) => [c.owned, c.revision, c.status])).toEqual([[true, 3n, "member"]]);
    const chain = await a3.store.read((tx) => ({ successions: tx.list("successions").filter(([, s]) => s.accountId === toHex(aliceId)).map(([, s]) => s.newGeneration), keys: tx.list("identities").filter(([, i]) => i.accountId === toHex(aliceId) && !!i.accountKey).length }));
    expect([chain.successions, chain.keys]).toEqual([["2", "3"], 3]);
    await w.sync(b);
    expect((await b.client.circles.list()).map((c) => [toHex(c.ownerIdentityId), c.revision])).toEqual([[toHex(aliceId), 3n]]);
  });

  it("A -> B -> C -> D: phone C follows the whole chain, retires and erases its account seed", async () => {
    const w = world();
    await pair(w);
    const b2 = await recover(w, "bob");
    await w.sync(b2);
    const b3 = await recover(w, "bob");
    await w.sync(b3);
    const b4 = await recover(w, "bob");
    await w.sync(b4);
    const r = await w.sync(b3);
    expect(r.errors).toEqual([]);
    expect((await b3.client.getState()).status).toBe("retired");
    expect(await b3.secrets.get("accountSeed")).toBeUndefined();
    // And the first replacement phone, which never saw the later ones, retires the same way.
    const r2 = await w.sync(b2);
    expect([r2.errors, (await b2.client.getState()).status, await b2.secrets.get("accountSeed")]).toEqual([[], "retired", undefined]);
  });

  it("a device that cannot follow its own chain says so in the report", async () => {
    const w = world();
    await pair(w);
    const b2 = await recover(w, "bob");
    await w.sync(b2);
    await recover(w, "bob");
    b2.t.knobs.tamper.add("succession");
    const r = await w.sync(b2);
    expect(r.errors.map((e) => [e.operation, e.code])).toContainEqual(["ownSuccession", "BAD_SIGNATURE"]);
    expect((await b2.client.getState()).status).not.toBe("retired");
  });
});

describe("fifth review: a paged history at activation", () => {
  it("with one-link pages, a third replacement activates on the retried commit and on a sync resume alike", async () => {
    const w = world();
    const { a, bobId } = await pair(w);
    await recover(w, "bob");
    await recover(w, "bob");
    w.host.successionPageSize = 1;
    // Through the commit's own answer.
    const d = await w.device("bob", new MemoryPlatformProvider("bob-4@platform"), new MemoryStore(), new MemorySecretStore());
    const p = await d.client.prepareReplacement();
    const token = w.host.authorizeReplacement({ accountName: "bob", successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });
    expect((await d.client.completeReplacement({ successionId: p.successionId, authorization: token })).generation).toBe(4n);
    expect(await d.store.read((tx) => tx.list("successions").map(([, s]) => s.newGeneration))).toEqual(["2", "3", "4"]);
    const r = await w.sync(d);
    expect([r.errors, r.bootstrap?.circles]).toEqual([[], 1]);
    // Through the chain, after a lost response.
    const e = await w.device("bob", new MemoryPlatformProvider("bob-5@platform"), new MemoryStore(), new MemorySecretStore());
    const q = await e.client.prepareReplacement();
    const token2 = w.host.authorizeReplacement({ accountName: "bob", successionId: q.successionId, expectedCertificateHash: q.expectedCertificateHash, certificate: q.certificate });
    e.t.knobs.loseResponseOf.add("succeedAccount");
    e.t.knobs.withhold.add("successions");
    expect(await thrown(() => e.client.completeReplacement({ successionId: q.successionId, authorization: token2 }))).toBe("SUCCESSION_PENDING");
    e.t.knobs.withhold.delete("successions");
    const resumed = await w.sync(e);
    expect([resumed.errors, (await e.client.getState()).generation]).toEqual([[], 5n]);
    expect(await e.store.read((tx) => tx.list("successions").map(([, s]) => s.newGeneration))).toEqual(["2", "3", "4", "5"]);
    const ar = await w.sync(a);
    expect([ar.errors, (await a.store.read((tx) => tx.get("pins", toHex(bobId))))?.generation]).toEqual([[], "5"]);
  });
});

describe("a recovery-only client without a provider has no vault", () => {
  it("registers without one, publishes none, and the host holds none", async () => {
    const recovery = { ...testPolicy, replacement: "recovery" as const };
    const w = world(recovery);
    const alice = await open({ accountName: "alice", retentionPolicy: recovery, resetTrust, secretStore: new MemorySecretStore(), store: new MemoryStore(), transport: hostTransport(w.host, "alice"), now: w.clock.now });
    await alice.initializeAccount();
    const { circleId } = await alice.circles.create();
    await alice.circles.setEnabled(circleId, false);
    await alice.sync();
    expect(w.host.accounts.get("alice")?.vault).toBeUndefined();
    expect((await alice.inspect()).vault).toBeUndefined();
    const a2 = await open({ accountName: "alice", retentionPolicy: recovery, resetTrust, secretStore: new MemorySecretStore(), store: new MemoryStore(), transport: hostTransport(w.host, "alice"), now: w.clock.now });
    const p = await a2.prepareReplacement();
    const token = w.host.authorizeReplacement({ accountName: "alice", successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });
    await a2.completeReplacement({ successionId: p.successionId, authorization: token });
    const r = await a2.sync();
    expect([r.errors, r.bootstrap?.circles, (await a2.inspect()).vault, w.host.accounts.get("alice")?.vault]).toEqual([[], 1, undefined, undefined]);
    expect((await a2.circles.list())[0]?.enabled).toBe(false);
  });
});

describe("the recovery provider on a recovery-only profile", () => {
  it("is optional there, required where identity continuity is enabled, and the account works without it", async () => {
    const recovery = { ...testPolicy, replacement: "recovery" as const };
    const w = world(recovery);
    const openWithout = (name: string, policy = recovery) =>
      open({ accountName: name, retentionPolicy: policy, resetTrust, secretStore: new MemorySecretStore(), store: new MemoryStore(), transport: hostTransport(w.host, name), now: w.clock.now });
    await expect(openWithout("alice", testPolicy)).rejects.toMatchObject({ code: "MALFORMED" });
    const alice = await openWithout("alice");
    await alice.initializeAccount();
    expect((await alice.recoveryStatus()).status).toBe("unsupported");
    const { circleId } = await alice.circles.create();
    expect(circleId.length).toBe(16);
    const a2 = await openWithout("alice");
    expect(await thrown(() => a2.restoreAccount())).toBe("NOT_AUTHORIZED");
    const p = await a2.prepareReplacement();
    const token = w.host.authorizeReplacement({ accountName: "alice", successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });
    expect((await a2.completeReplacement({ successionId: p.successionId, authorization: token })).generation).toBe(2n);
    const r = await a2.sync();
    expect([r.errors, r.bootstrap?.circles]).toEqual([[], 1]);
  });
});
