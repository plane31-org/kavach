/** Regressions from the revision 9 review: the five reproductions, and the optional recovery provider. */
import { beforeAll, describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.js";
import { open } from "../src/client.js";
import { DocumentType, buildCircleSnapshot, expectType, parseDocument, verifyDocument, type AccountDevice, type CircleSnapshot } from "../src/codec.js";
import { randomBytes, ready } from "../src/crypto.js";
import { certify, newAccountSeed, newDevice, openAccount, pinFromCertificate } from "../src/identity.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { testPolicy } from "../src/testing/clock.js";
import { MemoryPlatformProvider } from "../src/testing/providers.js";
import { hostTransport } from "../src/testing/sweep.js";
import { pair, resetTrust, thrown, world, type Dev, type World } from "./clientWorld.js";

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
