import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { resolveAudience } from "../src/audience.js";
import { DocumentType, expectType, verifyDocument, type AccountDevice } from "../src/codec.js";
import { randomBytes, ready } from "../src/crypto.js";
import { prepareEpoch } from "../src/epoch.js";
import { KavachError } from "../src/errors.js";
import { certify, deviceFromSeed, newDevice, openAccount, pinFromCertificate, type AccountPin } from "../src/identity.js";
import { validatePolicy } from "../src/policy.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { openStore, t1Activate, t1Header, t1Secrets, t2PrepareActivation, t3ApplyChange, t4PersistPrepared, t5Committed, t8OwnerSnapshot, t9Vault } from "../src/transactions.js";
import { circleToRow } from "../src/rows.js";
import { pinCircle } from "../src/circle.js";
import { fixture, hex, str } from "./fixture.js";

const alice = fixture.identities[0];
if (!alice) throw new Error("fixture");
const accountSeed = hex(str(fixture.inputs["alice_account_seed"] ?? ""));
const deviceSeed = hex(str(fixture.inputs["alice_device_seed"] ?? ""));

beforeAll(() => ready());

async function code(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "OK";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

async function initialised(options?: ConstructorParameters<typeof MemoryStore>[0]): Promise<{ store: MemoryStore; secrets: MemorySecretStore; pin: AccountPin; instanceId: Uint8Array }> {
  const store = new MemoryStore(options);
  const secrets = new MemorySecretStore();
  const account = openAccount("alice", accountSeed);
  const device = deviceFromSeed(deviceSeed, hex(alice.device_id));
  const certificate = certify(account, device, 1n);
  const instanceId = randomBytes(16);
  await t1Secrets(secrets, { accountSeed, deviceSeed, recoveryKey: randomBytes(32), instanceId });
  await store.transaction((tx) => t1Header(tx, { account, device, certificate, instanceId, generation: 1n }));
  await store.transaction((tx) => t1Activate(tx));
  const pin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice));
  return { store, secrets, pin, instanceId };
}

describe("the in-memory store", () => {
  it("is atomic: a throwing callback leaves nothing behind", async () => {
    const store = new MemoryStore();
    await expect(
      store.transaction((tx) => {
        tx.put("clock", "c", { highWater: "1" });
        throw new Error("boom");
      })
    ).rejects.toThrow("boom");
    expect(await store.read((tx) => tx.get("clock", "c"))).toBeUndefined();
    await store.transaction((tx) => tx.put("clock", "c", { highWater: "2" }));
    expect(await store.read((tx) => tx.get("clock", "c"))).toEqual({ highWater: "2" });
  });

  it("serialises writers across contexts and keeps a handoff inside the lock", async () => {
    const a = new MemoryStore();
    const b = a.fork();
    const order: string[] = [];
    let sent = false;
    const first = a.transaction((tx) => {
      order.push("A:check");
      tx.put("clock", "c", { highWater: "A" });
      order.push("A:send");
      void tx.handoff(async () => {
        sent = true;
        order.push("A:network");
      });
      return "a";
    });
    const second = b.transaction((tx) => {
      order.push("B:T3");
      tx.put("clock", "c", { highWater: "B" });
      return "b";
    });
    expect(await Promise.all([first, second])).toEqual(["a", "b"]);
    expect(order).toEqual(["A:check", "A:send", "A:network", "B:T3"]);
    expect(sent).toBe(true);
    expect(await a.read((tx) => tx.get("clock", "c"))).toEqual({ highWater: "B" });
  });

  it("refuses a callback that returns a promise, writes nothing, and releases the lock", async () => {
    const store = new MemoryStore();
    const refused = store.transaction((tx) => {
      tx.put("clock", "c", { highWater: "x" });
      return Promise.resolve("never committed") as unknown as string;
    });
    await expect(refused).rejects.toThrow(expect.objectContaining({ code: "STORAGE_FAILURE", message: expect.stringContaining("transaction callbacks are synchronous") }));
    expect(await store.read((r) => r.get("clock", "c"))).toBeUndefined();
    expect(store.isHeld).toBe(false);
    await store.transaction((tx) => tx.put("clock", "c", { highWater: "y" }));
    expect(await store.read((r) => r.get("clock", "c"))).toEqual({ highWater: "y" });
  });
});

describe("T1 and the marker protocol", () => {
  it("fresh, then initializing, then active", async () => {
    const store = new MemoryStore();
    const secrets = new MemorySecretStore();
    expect((await openStore(store, secrets, "alice")).kind).toBe("fresh");
    const instanceId = randomBytes(16);
    await t1Secrets(secrets, { accountSeed, deviceSeed, recoveryKey: randomBytes(32), instanceId });
    expect((await openStore(store, secrets, "alice")).kind).toBe("initializing");
    const account = openAccount("alice", accountSeed);
    const device = deviceFromSeed(deviceSeed, hex(alice.device_id));
    await store.transaction((tx) => t1Header(tx, { account, device, certificate: certify(account, device, 1n), instanceId, generation: 1n }));
    expect((await openStore(store, secrets, "alice")).kind).toBe("initializing");
    await store.transaction((tx) => t1Activate(tx));
    const opened = await openStore(store, secrets, "alice");
    expect(opened.kind).toBe("ACTIVE");
    if (opened.kind === "ACTIVE") expect(opened.meta.certificateHash).toBe(alice.certificate_hash);
  });

  it("a crash between the secret store and the store header resumes initialization, never a reset", async () => {
    let crashed = false;
    const store = new MemoryStore({
      beforeCommit: () => {
        if (!crashed) {
          crashed = true;
          throw new KavachError("STORAGE_FAILURE", "test", "crash before header commit");
        }
      }
    });
    const secrets = new MemorySecretStore();
    const instanceId = randomBytes(16);
    await t1Secrets(secrets, { accountSeed, deviceSeed, recoveryKey: randomBytes(32), instanceId });
    const account = openAccount("alice", accountSeed);
    const device = deviceFromSeed(deviceSeed, hex(alice.device_id));
    expect(await code(() => store.transaction((tx) => t1Header(tx, { account, device, certificate: certify(account, device, 1n), instanceId, generation: 1n })))).toBe("STORAGE_FAILURE");
    expect(await store.read((tx) => tx.get("meta", "meta"))).toBeUndefined();
    const opened = await openStore(store, secrets, "alice");
    expect(opened.kind).toBe("initializing");
    // Retrying with the same roots succeeds on the next attempt.
    await store.transaction((tx) => t1Header(tx, { account, device, certificate: certify(account, device, 1n), instanceId, generation: 1n }));
    expect((await openStore(store, secrets, "alice")).kind).toBe("initializing");
  });

  it("a crash in the secret store leaves nothing at all", async () => {
    const secrets = new MemorySecretStore();
    secrets.failNextWrite = true;
    await expect(t1Secrets(secrets, { accountSeed, deviceSeed, recoveryKey: randomBytes(32), instanceId: randomBytes(16) })).rejects.toThrow();
    expect(await secrets.get("accountSeed")).toBeUndefined();
    expect((await openStore(new MemoryStore(), secrets, "alice")).kind).toBe("fresh");
  });

  it("a mismatched header is RECOVERY_REQUIRED and counters stay untouched", async () => {
    const { store, secrets } = await initialised();
    const before = await store.read((tx) => tx.get("stream", "stream"));
    await secrets.set("instanceId", randomBytes(16));
    expect(await code(() => openStore(store, secrets, "alice"))).toBe("RECOVERY_REQUIRED");
    // Secrets for another account against this store.
    const other = new MemorySecretStore();
    await t1Secrets(other, { accountSeed: hex(str(fixture.inputs["bob_account_seed"] ?? "")), deviceSeed, recoveryKey: randomBytes(32), instanceId: randomBytes(16) });
    expect(await code(() => openStore(store, other, "alice"))).toBe("RECOVERY_REQUIRED");
    // A store with no secrets at all.
    expect(await code(() => openStore(store, new MemorySecretStore(), "alice"))).toBe("RECOVERY_REQUIRED");
    expect(await store.read((tx) => tx.get("stream", "stream"))).toEqual(before);
  });
});

describe("T2 to T5, T8, T9", () => {
  it("T2 marks activation pending with the exact bytes", async () => {
    const { store, secrets } = await initialised();
    await store.transaction((tx) =>
      t2PrepareActivation(tx, { certificate: "aa", vault: "bb", vaultRevision: "2", expectedCertificateHash: alice.certificate_hash, expectedVaultRevision: "1", expectedVaultHash: "cc" })
    );
    expect((await openStore(store, secrets, "alice")).kind).toBe("ACTIVATION_PENDING");
    expect(await store.read((tx) => tx.get("activation", "pending")?.certificate)).toBe("aa");
  });

  it("T4 persists one prepared epoch, T5 promotes or marks it obsolete, T3 invalidates and cancels", async () => {
    const { store, pin } = await initialised();
    const audience = resolveAudience(pin, [], new Map());
    const author = { identityId: pin.identityId, certificateHash: pin.certificateHash, streamId: pin.streamId, signingSecretKey: deviceFromSeed(deviceSeed, hex(alice.device_id)).signing.secretKey };
    const e1 = prepareEpoch({ author, epoch: 1, createdAt: 1n, audience, desiredRevision: 1n });
    await store.transaction((tx) => t4PersistPrepared(tx, e1));
    expect(await code(() => store.transaction((tx) => t4PersistPrepared(tx, prepareEpoch({ author, epoch: 2, createdAt: 1n, audience, desiredRevision: 1n }))))).toBe("ROTATION_REQUIRED");
    expect(await store.transaction((tx) => t5Committed(tx, 1, audience.key))).toBe("PROMOTED");
    let stream = await store.read((tx) => tx.get("stream", "stream"));
    expect(stream).toEqual({ highestCommittedEpoch: 1, activeEpoch: 1, pendingEpoch: undefined });
    // Two queued rows, then a membership change: both are cancelled and the epoch goes obsolete.
    await store.transaction((tx) => {
      for (const c of [0, 1]) {
        tx.put("outbox", `r${c}`, { recordId: `r${c}`, wire: "00", epoch: 1, counter: c, kind: 0, sentAt: "1", desiredRevision: "1", status: c === 0 ? "queued" : "inflight", attempts: 0, reason: undefined });
      }
    });
    const change = await store.transaction((tx) => t3ApplyChange(tx, { kind: "join", circleId: new Uint8Array(16) }));
    expect(change.changed).toBe(true);
    expect(change.desiredRevision).toBe(2n);
    expect(change.cancelled).toEqual(["r0"]); // the in-flight row cannot be recalled
    stream = await store.read((tx) => tx.get("stream", "stream"));
    expect(stream?.activeEpoch).toBeUndefined();
    expect(await store.read((tx) => tx.get("epochs", "1")?.status)).toBe("obsolete");
    expect(await store.read((tx) => tx.get("revision", "revision")?.paused)).toBe("rotation");
    // The same event again changes nothing.
    expect((await store.transaction((tx) => t3ApplyChange(tx, { kind: "snapshot", circleId: new Uint8Array(16), revision: 1n }))).changed).toBe(true);
    expect((await store.transaction((tx) => t3ApplyChange(tx, { kind: "snapshot", circleId: new Uint8Array(16), revision: 1n }))).changed).toBe(false);
    // An epoch prepared under the old revision commits obsolete; one under the current revision promotes and clears the pause.
    const stale = prepareEpoch({ author, epoch: 2, createdAt: 1n, audience, desiredRevision: 1n });
    await store.transaction((tx) => t4PersistPrepared(tx, stale));
    expect(await store.transaction((tx) => t5Committed(tx, 2, audience.key))).toBe("OBSOLETE");
    const fresh = prepareEpoch({ author, epoch: 3, createdAt: 1n, audience, desiredRevision: 3n });
    await store.transaction((tx) => t4PersistPrepared(tx, fresh));
    expect(await store.transaction((tx) => t5Committed(tx, 3, audience.key))).toBe("PROMOTED");
    expect(await store.read((tx) => tx.get("revision", "revision")?.paused)).toBeUndefined();
    expect(await store.read((tx) => tx.get("epochs", "3")?.nextCounter)).toBe(0);
  });

  it("each transaction commits whole or not at all under a crash", async () => {
    let crashAt = Infinity;
    const { store, pin } = await initialised({
      beforeCommit: (n) => {
        if (n === crashAt) throw new KavachError("STORAGE_FAILURE", "test", "crash");
      }
    });
    const audience = resolveAudience(pin, [], new Map());
    const author = { identityId: pin.identityId, certificateHash: pin.certificateHash, streamId: pin.streamId, signingSecretKey: newDevice().signing.secretKey };
    const e1 = prepareEpoch({ author, epoch: 1, createdAt: 1n, audience, desiredRevision: 1n });
    crashAt = store.commitCount + 1;
    expect(await code(() => store.transaction((tx) => t4PersistPrepared(tx, e1)))).toBe("STORAGE_FAILURE");
    expect(await store.read((tx) => [tx.get("epochs", "1"), tx.get("stream", "stream")?.pendingEpoch])).toEqual([undefined, undefined]);
    crashAt = Infinity;
    await store.transaction((tx) => t4PersistPrepared(tx, e1));
    crashAt = store.commitCount + 1;
    expect(await code(() => store.transaction((tx) => t5Committed(tx, 1, audience.key)))).toBe("STORAGE_FAILURE");
    expect(await store.read((tx) => tx.get("epochs", "1")?.status)).toBe("prepared");
    crashAt = Infinity;
    await store.transaction((tx) => t5Committed(tx, 1, audience.key));
    crashAt = store.commitCount + 1;
    expect(await code(() => store.transaction((tx) => t3ApplyChange(tx, { kind: "hygiene" })))).toBe("STORAGE_FAILURE");
    expect(await store.read((tx) => tx.get("stream", "stream")?.activeEpoch)).toBe(1);
  });

  it("T8 keeps the owner's successor pending and T9 the vault checkpoint", async () => {
    const { store, pin } = await initialised();
    const circle = pinCircle(new Uint8Array(16).fill(1), pin.identityId, true, "member");
    await store.transaction((tx) => tx.put("circles", toHex(circle.circleId), circleToRow(circle)));
    await store.transaction((tx) => t8OwnerSnapshot(tx, circle.circleId, new Uint8Array([1, 2, 3]), 2n));
    expect(await store.read((tx) => tx.get("circles", toHex(circle.circleId))?.pending)).toEqual({ snapshot: "010203", revision: "2" });
    await store.transaction((tx) => t9Vault(tx, { revision: "1", hash: "ab", wire: "cd", pending: true, dirty: false }));
    expect(await store.read((tx) => tx.get("vault", "vault")?.pending)).toBe(true);
  });
});

describe("retention policy validation", () => {
  it("accepts a complete policy and rejects a missing or malformed one", () => {
    const good = { version: 1, replacement: "both" as const, deliveryWindowMs: 86_400_000n, appendRetryWindowMs: 604_800_000n, hygieneRotationMs: 2_592_000_000n, maxOutboxRecords: 2000, maxOutboxBytes: 4 << 20, kinds: [{ kind: 0, retentionMs: 86_400_000n, queue: "keepAll" as const, history: true, newest: true }] };
    expect(() => validatePolicy({ ...good, kinds: [] })).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    expect(() => validatePolicy({ ...good, replacement: "either" })).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    const { replacement: _r, ...noModel } = good;
    void _r;
    expect(() => validatePolicy(noModel)).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    expect(() => validatePolicy({ ...good, kinds: [{ ...good.kinds[0], kind: 256 }] })).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    // Revision 11: header classes 0 to 7; anything else, or a non-integer, is malformed.
    expect(validatePolicy({ ...good, kinds: [{ ...good.kinds[0], headerClass: 7 }] }).kinds[0]?.headerClass).toBe(7);
    for (const headerClass of [8, -1, 1.5, "2"]) expect(() => validatePolicy({ ...good, kinds: [{ ...good.kinds[0], headerClass }] })).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    expect(() => validatePolicy({ ...good, kinds: [{ ...good.kinds[0], history: false, newest: false }] })).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    expect(validatePolicy(good).maxOutboxRecords).toBe(2000);
    expect(() => validatePolicy(undefined)).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    const { deliveryWindowMs: _omit, ...missing } = good;
    void _omit;
    expect(() => validatePolicy(missing)).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    expect(() => validatePolicy({ ...good, deliveryWindowMs: 86_400_000 })).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    expect(() => validatePolicy({ ...good, maxOutboxRecords: 0 })).toThrow(expect.objectContaining({ code: "MALFORMED" }));
  });
});
