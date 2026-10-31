/**
 * Step 16: a malicious transport. Every case ends in the typed error the protocol names, with
 * nothing stored in plaintext that was not verified and no account silently replaced; after the
 * attack stops, delivery resumes. The lost-device scenario runs with the attacker holding the
 * complete old-device state.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { fromHex, toHex } from "../src/bytes.js";
import { open } from "../src/client.js";
import { buildResetKeyList } from "../src/codec.js";
import { C, H, openSealedBox, randomBytes, ready, signingKeypairFromSeed } from "../src/crypto.js";
import { certify, deviceFromSeed, newDevice, openAccount } from "../src/identity.js";
import { MemorySecretStore, MemoryStore, type TableName } from "../src/store.js";
import { testPolicy } from "../src/testing/clock.js";
import { MemoryPlatformProvider } from "../src/testing/providers.js";
import { DAY, codes, management, pair, resetTrust, rotate, thrown, world } from "./clientWorld.js";

beforeAll(() => ready());

describe("tampered documents", () => {
  it("a record with a flipped byte is BAD_SIGNATURE, stores nothing, and later records flow", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    const pinBefore = toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array());
    b.t.knobs.tamper.add("record");
    await a.client.enqueueLocation(w.loc(2));
    await w.sync(a);
    const n = b.events.length;
    const r = await w.sync(b);
    expect([...codes(r, b.events, n)]).toEqual(["BAD_SIGNATURE"]);
    expect(r.inbox.stored).toBe(0);
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(1);
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(pinBefore);
    b.t.knobs.tamper.delete("record");
    await a.client.enqueueLocation(w.loc(3));
    await w.sync(a);
    const r2 = await w.sync(b);
    expect(r2.inbox.stored).toBeGreaterThanOrEqual(1);
    const last = [...w.host.appendLog].reverse().find((x) => x.status === "ACCEPTED");
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(last?.recordId);
  });

  it("a tampered manifest or wrap never yields a key: the record waits as keyPending and opens once the bytes are honest", async () => {
    for (const kind of ["manifest", "wrap"] as const) {
      const w = world();
      const { a, b, aliceId, circleId } = await pair(w);
      const epoch = await rotate(w, a, circleId);
      expect(epoch).toBeGreaterThan(1);
      await a.client.enqueueLocation(w.loc(5));
      await w.sync(a);
      b.t.knobs.tamper.add(kind);
      const n = b.events.length;
      const r = await w.sync(b);
      const seen = codes(r, b.events, n);
      expect([...seen].every((c) => ["BAD_SIGNATURE", "DECRYPT_FAILED", "WRAP_HASH_MISMATCH", "KEY_PENDING"].includes(c))).toBe(true);
      expect(r.inbox.stored).toBe(0);
      expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(1);
      expect(await b.store.read((tx) => tx.list("readerEpochs").filter(([, e]) => e.epoch === epoch).length)).toBe(0);
      b.t.knobs.tamper.delete(kind);
      const r2 = await w.sync(b);
      expect(r2.inbox.stored).toBe(1);
      expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(2);
    }
  });

  it("a forged certificate for a member is ACCOUNT_KEY_CHANGED: quarantined, the pinned key kept, nothing closed", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    const forged = certify(openAccount("alice", randomBytes(32)), newDevice(), 2n);
    b.t.knobs.fork.certificates.set("alice", forged);
    const n = b.events.length;
    await w.sync(b);
    const ev = b.events.slice(n).find((e) => e.kind === "accountKeyChanged");
    expect(ev).toMatchObject({ kind: "accountKeyChanged", accountName: "alice", quarantined: true });
    expect((await b.client.getState()).status).toBe("quarantined");
    const pin = await b.store.read((tx) => tx.get("pins", toHex(aliceId)));
    expect(pin?.accountKey).toBe(toHex(w.host.accounts.get("alice")?.accountKey ?? new Uint8Array()));
    expect((await b.client.circles.list())[0]?.status).toBe("member");
    void a;
  });
});

describe("replayed documents", () => {
  it("an older snapshot is ROLLBACK and the circle keeps its revision", async () => {
    const w = world();
    const { b, circleId, snapshot1 } = await pair(w);
    b.t.knobs.replay.snapshots.set(toHex(circleId), snapshot1);
    const n = b.events.length;
    const r = await w.sync(b);
    expect(codes(r, b.events, n).has("ROLLBACK")).toBe(true);
    const c = (await b.client.circles.list())[0];
    expect([c?.revision, c?.status]).toEqual([2n, "member"]);
  });

  it("an older vault at restore cannot activate: ACCOUNT_RECOVERY_REQUIRED, no device allocated, and the honest vault restores", async () => {
    const w = world();
    const { b, circleId, bobVault1 } = await pair(w);
    const b2 = await w.device("bob", b.provider.twin());
    b2.t.knobs.replay.vault = bobVault1;
    expect(await thrown(() => b2.client.restoreAccount())).toBe("ACCOUNT_RECOVERY_REQUIRED");
    const acct = w.host.accounts.get("bob");
    expect([acct?.generation, acct?.deviceIds.size]).toEqual([1n, 1]);
    expect((await b2.client.getState()).status).toBe("activationPending");
    // A sync in this state changes nothing either.
    const r = await w.sync(b2);
    expect(r.errors).toEqual(["ACTIVATION_PENDING@sync"]);
    expect(w.host.accounts.get("bob")?.generation).toBe(1n);
    delete b2.t.knobs.replay.vault;
    const done = await b2.client.restoreAccount();
    expect(done.generation).toBe(2n);
    expect([w.host.accounts.get("bob")?.generation, w.host.accounts.get("bob")?.deviceIds.size]).toEqual([2n, 2]);
    expect((await b2.client.circles.list()).map((c) => toHex(c.circleId))).toEqual([toHex(circleId)]);
  });

  it("a replayed, unexpired older key list is not installed, and a receipt under a key the newer list removed is RESET_KEY_REVOKED", async () => {
    const w = world();
    const { a, b } = await pair(w);
    const v1 = w.host.resetKeyList ?? new Uint8Array();
    const other = signingKeypairFromSeed(H(C("other-op")));
    w.host.resetKeyList = buildResetKeyList({ version: 2n, issuedAt: w.clock.now(), expiresAt: w.clock.now() + 30n * DAY, keys: [{ keyId: new Uint8Array(16).fill(8), publicKey: other.publicKey }] }, management.secretKey);
    w.clock.advance(25n * 3_600_000n);
    await w.sync(b);
    expect(await b.store.read((tx) => tx.get("resetList", "list")?.version)).toBe("2");
    b.t.knobs.replay.keyList = v1;
    w.clock.advance(25n * 3_600_000n);
    const r = await w.sync(b);
    expect(codes(r, b.events).has("ROLLBACK")).toBe(true);
    expect(await b.store.read((tx) => tx.get("resetList", "list")?.version)).toBe("2");
    // The host still signs receipts with the removed key.
    await a.client.resetAccount({ confirmed: true });
    const n = b.events.length;
    const r2 = await w.sync(b);
    expect(codes(r2, b.events, n).has("RESET_KEY_REVOKED")).toBe(true);
    expect((await b.client.circles.list())[0]?.status).toBe("member");
  });

  it("a replayed current-epoch pointer changes nothing: records name their epoch", async () => {
    const w = world();
    const { a, b, aliceId, circleId } = await pair(w);
    expect(await rotate(w, a, circleId)).toBeGreaterThan(1);
    b.t.knobs.replay.currentEpoch = { epoch: 1, manifestHash: new Uint8Array(32) };
    await a.client.enqueueLocation(w.loc(9));
    await w.sync(a);
    const r = await w.sync(b);
    expect(r.inbox.stored).toBe(1);
    expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(2);
  });
});

describe("withholding, duplication and reordering", () => {
  it("withheld records move no cursor and arrive when served; withheld snapshots keep the last verified one with its age", async () => {
    const w = world();
    const { a, b, aliceId, circleId } = await pair(w);
    b.t.knobs.withhold.add("records");
    await a.client.enqueueLocation(w.loc(2));
    await w.sync(a);
    const stream = [...w.host.streams.values()].find((s) => s.accountName === "alice");
    const cursorBefore = [...(stream?.subscriptions.values() ?? [])][0]?.cursor;
    expect((await w.sync(b)).inbox.stored).toBe(0);
    expect([...(stream?.subscriptions.values() ?? [])][0]?.cursor).toBe(cursorBefore);
    b.t.knobs.withhold.delete("records");
    expect((await w.sync(b)).inbox.stored).toBe(1);
    // Removal withheld.
    b.t.knobs.withhold.add("snapshots");
    const bobId = (await b.client.inspect()).identityId ?? new Uint8Array();
    await a.client.circles.remove(circleId, bobId);
    await w.sync(a);
    w.clock.advance(3_600_000n);
    await w.sync(b);
    const c = (await b.client.circles.list())[0];
    expect(c?.status).toBe("member");
    expect(c?.snapshotAgeMs ?? 0n).toBeGreaterThanOrEqual(3_600_000n);
    // Alice's next epoch excludes Bob regardless.
    await a.client.enqueueLocation(w.loc(3));
    await w.sync(a);
    const pin = toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array());
    await w.sync(b);
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(pin);
    b.t.knobs.withhold.delete("snapshots");
    await w.sync(b);
    expect((await b.client.circles.list())[0]?.status).toBe("left");
  });

  it("duplicated pages and records served newest first: each record once, the pin at the newest, the cursor at the tail", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    for (const lat of [2, 3, 4]) await a.client.enqueueLocation(w.loc(lat));
    await w.sync(a);
    b.t.knobs.duplicate = true;
    b.t.knobs.reorder = true;
    await w.sync(b);
    await w.sync(b);
    const history = await b.client.history({ authorIdentityId: aliceId });
    expect(history.length).toBe(4);
    expect(new Set(history.map((h) => toHex(h.recordId))).size).toBe(4);
    const last = [...w.host.appendLog].reverse().find((x) => x.status === "ACCEPTED");
    expect(toHex((await b.client.latest(aliceId))?.recordId ?? new Uint8Array())).toBe(last?.recordId);
    const stream = [...w.host.streams.values()].find((s) => s.accountName === "alice");
    expect([...(stream?.subscriptions.values() ?? [])][0]?.cursor).toBe(stream?.tail);
  });
});

/** A byte-for-byte copy of a device's store, as an attacker who imaged the phone would hold. */
async function cloneStore(src: MemoryStore): Promise<MemoryStore> {
  const out = new MemoryStore();
  const image = src.snapshot();
  await out.transaction((tx) => {
    for (const [table, rows] of Object.entries(image)) for (const [k, v] of Object.entries(rows)) tx.put(table as TableName, k, v as never);
  });
  return out;
}

async function cloneSecrets(src: MemorySecretStore): Promise<MemorySecretStore> {
  const out = new MemorySecretStore();
  for (const n of ["accountSeed", "deviceSeed", "recoveryKey", "storageKey", "instanceId"] as const) {
    const v = await src.get(n);
    if (v) await out.set(n, v);
  }
  return out;
}

describe("lost device with the complete old-device state", () => {
  it("after activation and every author's rotation the attacker opens nothing new, cannot append, and cannot read the relay", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    // The attacker images Bob's phone now: store, device seed and host session.
    const image = { store: await cloneStore(b.store), secrets: await cloneSecrets(b.secrets) };
    const oldCert = w.host.accounts.get("bob")?.certificateHash ?? "";
    const openedBefore = (await b.client.history({ authorIdentityId: aliceId })).length;
    // Bob restores on a new phone; Alice rotates and keeps sharing.
    const b2 = await w.device("bob", b.provider.twin());
    await b2.client.restoreAccount();
    await w.sync(b2);
    await w.sync(a);
    await a.client.enqueueLocation(w.loc(2));
    await a.client.enqueueLocation(w.loc(3));
    await w.sync(a);
    expect((await w.sync(b2)).inbox.stored).toBe(2);
    // The attacker runs the SDK over the image with the old session.
    const session = w.host.asDevice("bob", fromHex(oldCert));
    const attacker = await open({ accountName: "bob", retentionPolicy: testPolicy, recoveryProvider: new MemoryPlatformProvider("attacker"), resetTrust, secretStore: image.secrets, store: image.store, transport: session, now: w.clock.now });
    await attacker.sync();
    expect((await attacker.getState()).status).toBe("retired");
    expect((await attacker.history({ authorIdentityId: aliceId })).length).toBe(openedBefore);
    expect(await thrown(() => attacker.enqueueLocation(w.loc(8)))).toBe("ACCOUNT_RECOVERY_REQUIRED");
    // Bypassing the SDK: the relay answers the old certificate with nothing, and the new epoch's
    // wrap for Bob's identity is sealed to the new phone's key.
    const aliceStream = [...w.host.streams.entries()].find(([, s]) => s.accountName === "alice");
    const page = await session.relay.readRecords(fromHex(aliceStream?.[0] ?? ""), 0n, 10);
    expect(page.records.length).toBe(0);
    const bundle = await session.relay.getEpoch(fromHex(aliceStream?.[0] ?? ""), aliceStream?.[1].currentEpoch ?? 0);
    const self = await image.store.read((tx) => tx.get("self", "self"));
    const oldBox = deviceFromSeed((await image.secrets.get("deviceSeed")) ?? new Uint8Array(32), fromHex(self?.deviceId ?? "")).box;
    expect(bundle?.wrap).toBeDefined();
    expect(await thrown(async () => openSealedBox(bundle?.wrap ?? new Uint8Array(), oldBox))).toBe("DECRYPT_FAILED");
    expect(w.host.appendLog.some((x) => x.streamId === self?.streamId && x.status === "ACCEPTED" && x.counter > 0)).toBe(false);
  });

  it("with the account seed as well, the attacker can only replace the device again, which every peer sees", async () => {
    const w = world();
    const { a, b, bobId } = await pair(w);
    const image = { secrets: await cloneSecrets(b.secrets) };
    const b2 = await w.device("bob", b.provider.twin());
    await b2.client.restoreAccount();
    await w.sync(b2);
    await w.sync(a);
    // The imaged secret store holds the account seed: a fresh store with those roots can activate.
    const attacker = await w.device("bob", new MemoryPlatformProvider("attacker"), new MemoryStore(), image.secrets);
    expect(await thrown(() => attacker.client.restoreAccount())).toBe("ACCOUNT_RECOVERY_REQUIRED"); // no provider, no code
    const stolenCode = await b.client.recoveryCode();
    const done = await attacker.client.restoreAccount(stolenCode);
    expect(done.generation).toBe(3n);
    // Never silent: Bob's real phone is retired and Alice is told the device changed.
    await w.sync(b2);
    expect((await b2.client.getState()).status).toBe("retired");
    const n = a.events.length;
    await w.sync(a);
    expect(a.events.slice(n).some((e) => e.kind === "deviceChanged" && toHex(e.identityId) === toHex(bobId) && e.generation === 3n)).toBe(true);
  });
});
