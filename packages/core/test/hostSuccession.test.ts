/**
 * Revision 9, host side: a replacement without recovery material commits through
 * `succeedAccount`, the fake host serves the chain, peers apply it and keep sharing, the retired
 * device is fenced, and discovery and preferences answer as the amendment's section 7 says.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.js";
import { DocumentType, expectType, parseDocument, verifyDocument, type AccountDevice, type AccountSuccession, type EpochManifest } from "../src/codec.js";
import { randomBytes, ready } from "../src/crypto.js";
import { certify, newAccountSeed, newDevice, openAccount, pinFromCertificate } from "../src/identity.js";
import { testPolicy } from "../src/testing/clock.js";
import type { FakeHost } from "../src/testing/fakeHost.js";
import { enqueueLocation } from "./location.js";
import { pair, world, type World } from "./clientWorld.js";

beforeAll(() => ready());

/** A fresh device with no secret from the old one: new account and device keys, a certificate at the next generation. */
function proposal(host: FakeHost, accountName: string) {
  const a = host.accounts.get(accountName);
  if (!a) throw new Error("unknown account");
  const account = openAccount(accountName, newAccountSeed());
  const device = newDevice();
  const certificate = certify(account, device, a.generation + 1n);
  const successionId = randomBytes(16);
  const expectedCertificateHash = fromHex(a.certificateHash);
  return { account, device, certificate, successionId, expectedCertificateHash, pin: pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice)) };
}

async function replace(w: World, accountName: string) {
  const p = proposal(w.host, accountName);
  const authorization = w.host.authorizeReplacement({ accountName, successionId: p.successionId, expectedCertificateHash: p.expectedCertificateHash, certificate: p.certificate });
  const dir = w.host.asDevice(accountName, p.expectedCertificateHash).directory;
  const outcome = await dir.succeedAccount({ accountName, expectedCertificateHash: p.expectedCertificateHash, newCertificate: p.certificate, newVault: undefined, successionId: p.successionId, authorization });
  return { ...p, authorization, outcome };
}

describe("succeedAccount at the fake host", () => {
  it("commits once, answers a repeat before the authorization, refuses a spent token and a stale expectation", async () => {
    const w = world();
    const { b } = await pair(w);
    const before = { ...w.host.accounts.get("bob") };
    const r = await replace(w, "bob");
    expect(r.outcome.status).toBe("COMMITTED");
    const doc = expectType<AccountSuccession>(parseDocument(r.outcome.succession ?? new Uint8Array()), DocumentType.AccountSuccession);
    expect([toHex(doc.accountId), toHex(doc.previousIdentityId), toHex(doc.newIdentityId), doc.previousGeneration, doc.newGeneration]).toEqual([before.accountId, before.identityId, toHex(r.pin.identityId), 1n, 2n]);
    const after = w.host.accounts.get("bob");
    expect([after?.accountId, after?.identityId, after?.generation, after?.successions.length]).toEqual([before.accountId, toHex(r.pin.identityId), 2n, 1]);
    // The same proposal again, token already spent: the original document, before any check.
    const dir = w.host.asDevice("bob", r.expectedCertificateHash).directory;
    const again = await dir.succeedAccount({ accountName: "bob", expectedCertificateHash: r.expectedCertificateHash, newCertificate: r.certificate, newVault: undefined, successionId: r.successionId, authorization: new Uint8Array(32) });
    expect([again.status, toHex(again.succession ?? new Uint8Array())]).toEqual(["ALREADY_COMMITTED", toHex(r.outcome.succession ?? new Uint8Array())]);
    // A known id with different bytes, a reused token, and a proposal against the superseded certificate.
    const other = proposal(w.host, "bob");
    expect((await dir.succeedAccount({ accountName: "bob", expectedCertificateHash: other.expectedCertificateHash, newCertificate: other.certificate, newVault: undefined, successionId: r.successionId, authorization: r.authorization })).status).toBe("UNAUTHORIZED");
    expect((await dir.succeedAccount({ accountName: "bob", expectedCertificateHash: other.expectedCertificateHash, newCertificate: other.certificate, newVault: undefined, successionId: other.successionId, authorization: r.authorization })).status).toBe("UNAUTHORIZED");
    const stale = proposal(w.host, "bob");
    const staleToken = w.host.authorizeReplacement({ accountName: "bob", successionId: stale.successionId, expectedCertificateHash: r.expectedCertificateHash, certificate: stale.certificate });
    const conflict = await dir.succeedAccount({ accountName: "bob", expectedCertificateHash: r.expectedCertificateHash, newCertificate: stale.certificate, newVault: undefined, successionId: stale.successionId, authorization: staleToken });
    expect([conflict.status, toHex(conflict.current ?? new Uint8Array())]).toEqual(["CONFLICT", toHex(r.certificate)]);
    // An expired token.
    const late = proposal(w.host, "bob");
    const lateToken = w.host.authorizeReplacement({ accountName: "bob", successionId: late.successionId, expectedCertificateHash: late.expectedCertificateHash, certificate: late.certificate });
    w.clock.advance(w.host.authorizationTtlMs + 1n);
    expect((await dir.succeedAccount({ accountName: "bob", expectedCertificateHash: late.expectedCertificateHash, newCertificate: late.certificate, newVault: undefined, successionId: late.successionId, authorization: lateToken })).status).toBe("UNAUTHORIZED");
    void b;
  });

  it("the directory serves the chain under the account id, from any of its identities, and pages it", async () => {
    const w = world();
    await pair(w);
    const bob0 = w.host.accounts.get("bob");
    const first = await replace(w, "bob");
    const second = await replace(w, "bob");
    expect([first.outcome.status, second.outcome.status]).toEqual(["COMMITTED", "COMMITTED"]);
    const dir = w.host.asDevice("alice", fromHex(w.host.accounts.get("alice")?.certificateHash ?? "")).directory;
    const byAccountId = await dir.resolveIdentities([fromHex(bob0?.accountId ?? "")]);
    const byRetired = await dir.resolveIdentities([first.pin.identityId]);
    const byCurrent = await dir.resolveIdentities([second.pin.identityId]);
    for (const [r] of [byAccountId, byRetired, byCurrent]) {
      expect(r?.accountName).toBe("bob");
      expect(r?.successions?.length).toBe(2);
      expect(r?.successionsNext).toBeUndefined();
      expect(toHex(r?.successions?.[1]?.certificate ?? new Uint8Array())).toBe(toHex(second.certificate));
    }
    w.host.successionPageSize = 1;
    const [paged] = await dir.resolveAccounts(["bob"]);
    expect([paged?.successions?.length, paged?.successionsNext]).toEqual([1, 2n]);
    const page2 = await dir.getSuccessions(fromHex(bob0?.accountId ?? ""), 2n, 1);
    expect([page2.successions.length, page2.nextGeneration, toHex(page2.successions[0]?.certificate ?? new Uint8Array())]).toEqual([1, undefined, toHex(second.certificate)]);
    // A retired identity is not an account id: no chain is served under it.
    expect((await dir.getSuccessions(first.pin.identityId, 0n, 10)).successions.length).toBe(0);
  });
});

describe("peers across a succession", () => {
  it("an established peer applies the chain, rotates to the new key, keeps the account id, and shares on", async () => {
    const w = world();
    const { a, b, bobId, circleId } = await pair(w);
    const r = await replace(w, "bob");
    const n = a.events.length;
    const report = await w.sync(a);
    expect(report.errors).toEqual([]);
    expect([report.metadata.successions, report.metadata.quarantined, report.epoch]).toEqual([1, 0, "prepared"]);
    expect(a.events.slice(n).some((e) => e.kind === "accountKeyChanged" && !e.quarantined)).toBe(true);
    expect(a.events.slice(n).some((e) => e.kind === "deviceChanged" && toHex(e.identityId) === toHex(bobId) && e.generation === 2n)).toBe(true);
    const rows = await a.store.read((tx) => ({ pin: tx.get("pins", toHex(bobId)), ids: tx.list("identities").filter(([, i]) => i.accountId === toHex(bobId)).map(([k, i]) => [k, i.retired, i.sinceGeneration]), succ: tx.list("successions").length, changes: tx.list("keyChanges").length }));
    expect(rows.pin?.accountKey).toBe(toHex(r.account.account.publicKey));
    expect(rows.pin?.identityId).toBe(toHex(r.pin.identityId));
    expect(rows.pin?.accountId).toBe(toHex(bobId));
    expect(rows.ids.sort()).toEqual([[toHex(bobId), true, "1"], [toHex(r.pin.identityId), false, "2"]].sort());
    expect([rows.succ, rows.changes]).toEqual([1, 1]);
    // The new epoch names Bob's account id with his new certificate.
    const aliceStream = w.host.streams.get(toHex((await a.store.read((tx) => tx.get("stream", "stream")))?.streamId ?? "")) ?? [...w.host.streams.values()].find((s) => s.accountName === "alice");
    const current = aliceStream?.epochs.get(aliceStream.currentEpoch);
    const manifest = expectType<EpochManifest>(parseDocument(current?.manifest ?? new Uint8Array()), DocumentType.EpochManifest);
    const bobRow = manifest.audience.find((x) => toHex(x.identityId) === toHex(bobId));
    expect(toHex(bobRow?.certificateHash ?? new Uint8Array())).toBe(toHex(r.pin.certificateHash));
    expect(current?.wraps.has(toHex(bobId))).toBe(true);
    // Membership is untouched: still one circle, Bob still a member under the same id.
    const circles = await a.client.circles.list();
    expect(circles.map((c) => [toHex(c.circleId), c.members.map(toHex).includes(toHex(bobId)), c.status])).toEqual([[toHex(circleId), true, "member"]]);
    // A second sync: the chain is a duplicate, nothing rotates again.
    const again = await w.sync(a);
    expect([again.errors, again.metadata.successions, again.epoch]).toEqual([[], 0, "unchanged"]);
    // The old Bob device learns it is retired, and its account seed goes with it.
    await w.sync(b);
    expect((await b.client.getState()).status).toBe("retired");
    expect(await b.secrets.get("accountSeed")).toBeUndefined();
    expect(await b.secrets.get("deviceSeed")).toBeUndefined();
    // A reopened retired device still reports retired, and refuses to enqueue.
    const b2 = await w.device("bob", b.provider, b.store, b.secrets);
    expect((await b2.client.getState()).status).toBe("retired");
    await expect(enqueueLocation(b2.client, w.loc(5))).rejects.toMatchObject({ code: "SUPERSEDED_DEVICE" });
  });

  it("on a deployment that enables identity continuity only, a served succession is refused and the key stays quarantined", async () => {
    const continuity = { ...testPolicy, replacement: "continuity" as const };
    const w = world(continuity);
    const { a, bobId } = await pair(w);
    await replace(w, "bob");
    const n = a.events.length;
    const epochBefore = (await a.client.inspect()).activeEpoch;
    const report = await w.sync(a);
    expect(report.metadata.successions).toBe(0);
    expect(report.metadata.quarantined).toBe(1);
    expect(report.errors.map((e) => e.code)).toContain("UNSUPPORTED_TYPE");
    expect(a.events.slice(n).some((e) => e.kind === "accountKeyChanged" && e.quarantined)).toBe(true);
    const pin = await a.store.read((tx) => tx.get("pins", toHex(bobId)));
    expect(pin?.generation).toBe("1");
    expect((await a.client.inspect()).activeEpoch).toBe(epochBefore);
    expect(await a.store.read((tx) => tx.count("quarantine"))).toBe(1);
  });
});

describe("the fence, discovery and preferences", () => {
  it("the retired device reads nothing and lists nothing; the successor sees its circles and orders its preference", async () => {
    const w = world();
    const { a, circleId, aliceId, bobId } = await pair(w);
    const oldHash = fromHex(w.host.accounts.get("bob")?.certificateHash ?? "");
    const r = await replace(w, "bob");
    await w.sync(a);
    const old = w.host.asDevice("bob", oldHash);
    const sub = [...w.host.streams.entries()].find(([, s]) => s.accountName === "alice");
    await expect(old.relay.readRecords(fromHex(sub?.[0] ?? ""), 0n, 10)).rejects.toThrow("SUPERSEDED_DEVICE");
    expect((await old.directory.listCircles(undefined)).circles).toEqual([]);
    expect((await old.directory.setSharingPreference(circleId, true, 0n)).status).toBe("UNAUTHORIZED");
    const fresh = w.host.asDevice("bob", r.pin.certificateHash);
    const page = await fresh.directory.listCircles(undefined);
    expect(page.cursor).toBeUndefined();
    expect(page.circles.map((c) => [toHex(c.circleId), toHex(c.ownerAccountId), c.role, c.enabled, c.preferenceRevision, c.snapshot !== undefined])).toEqual([[toHex(circleId), toHex(aliceId), "member", undefined, 0n, true]]);
    expect((await fresh.directory.setSharingPreference(circleId, true, 0n))).toEqual({ status: "COMMITTED", revision: 1n });
    // A delayed request against the old revision loses to the one that landed.
    expect((await fresh.directory.setSharingPreference(circleId, false, 0n))).toEqual({ status: "CONFLICT", revision: 1n, enabled: true });
    expect((await fresh.directory.setSharingPreference(circleId, false, 1n))).toEqual({ status: "COMMITTED", revision: 2n });
    expect((await fresh.directory.listCircles(undefined)).circles[0]).toMatchObject({ enabled: false, preferenceRevision: 2n });
    // The owner sees her own circle as owner; paging by one.
    w.host.circlePageSize = 1;
    const { circleId: second } = await a.client.circles.create();
    const owner = w.host.asDevice("alice", fromHex(w.host.accounts.get("alice")?.certificateHash ?? "")).directory;
    const p1 = await owner.listCircles(undefined);
    expect([p1.circles.length, p1.cursor !== undefined, p1.circles[0]?.role]).toEqual([1, true, "owner"]);
    const p2 = await owner.listCircles(p1.cursor);
    expect([p2.circles.length, p2.cursor]).toEqual([1, undefined]);
    expect([...p1.circles, ...p2.circles].map((c) => toHex(c.circleId)).sort()).toEqual([toHex(circleId), toHex(second)].sort());
    void bobId;
  });
});
