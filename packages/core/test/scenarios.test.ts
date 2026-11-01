/**
 * The scenario tests of the protocol appendix that run against the client with the fake host.
 * Relay-only and platform-recovery scenarios live with the host and the Expo package.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { open, type Client, type ClientEvent } from "../src/client.js";
import { buildResetKeyList } from "../src/codec.js";
import { randomBytes, ready, signingKeypairFromSeed, H, C } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { locationFromDegrees } from "../src/record.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import type { ProviderLoadResult, ProviderSaveResult, ProviderStatus, ProviderStatusResult, RecoveryProvider } from "../src/vault.js";
import { FakeHost } from "../src/testing/fakeHost.js";
import { Clock, policy } from "./harness.js";

beforeAll(() => ready());

/** A platform recovery provider shared by all devices signed into one "platform account". */
class Platform implements RecoveryProvider {
  status_: ProviderStatus = "available";
  readonly items = new Map<string, Uint8Array>();
  constructor(private readonly platformAccount: string) {}
  async load(accountName: string, identityId: Uint8Array): Promise<ProviderLoadResult> {
    if (this.status_ !== "available") return { status: this.status_ };
    const k = this.items.get(`${this.platformAccount}:${accountName}:${toHex(identityId)}`);
    return k ? { status: "available", recoveryKey: k } : { status: "unavailable", reason: "no item" };
  }
  async save(accountName: string, identityId: Uint8Array, recoveryKey: Uint8Array): Promise<ProviderSaveResult> {
    if (this.status_ !== "available") return { status: this.status_, backupState: "unavailable" };
    this.items.set(`${this.platformAccount}:${accountName}:${toHex(identityId)}`, recoveryKey);
    return { status: "available", backupState: "pending" };
  }
  async status(): Promise<ProviderStatusResult> {
    return { status: this.status_, backupState: this.status_ === "available" ? "pending" : "unavailable" };
  }
  async eraseLocalAccess(): Promise<void> {}
  /** Another phone on the same platform account sees the same items. */
  twin(): Platform {
    const p = new Platform(this.platformAccount);
    (p as { items: Map<string, Uint8Array> }).items = this.items;
    return p;
  }
}

const management = signingKeypairFromSeed(H(C("identity"))); // any fixed seed
const operational = signingKeypairFromSeed(H(C("stream")));
const operationalId = new Uint8Array(16).fill(7);
const resetTrust = { managementKey: management.publicKey, minimumVersion: 1n };

interface World {
  host: FakeHost;
  clock: Clock;
  device(name: string, provider?: RecoveryProvider): Promise<{ client: Client; store: MemoryStore; secrets: MemorySecretStore; events: ClientEvent[]; provider: RecoveryProvider }>;
}

function world(): World {
  const host = new FakeHost();
  const clock = new Clock();
  host.now = clock.now;
  host.resetSigner = { key: operational, keyId: operationalId };
  host.resetKeyList = buildResetKeyList({ version: 1n, issuedAt: clock.now(), expiresAt: clock.now() + 2_592_000_000n, keys: [{ keyId: operationalId, publicKey: operational.publicKey }] }, management.secretKey);
  return {
    host,
    clock,
    async device(name, provider = new Platform(name + "@platform")) {
      const store = new MemoryStore();
      const secrets = new MemorySecretStore();
      const events: ClientEvent[] = [];
      // The transport is bound to the device's certificate after enrollment; a lazy proxy resolves it.
      let bound: ReturnType<FakeHost["asDevice"]> | undefined;
      const transport: ReturnType<FakeHost["asDevice"]> = {
        get directory() {
          return (bound ?? host.asDevice(name, new Uint8Array(32))).directory;
        },
        get relay() {
          return (bound ?? host.asDevice(name, new Uint8Array(32))).relay;
        }
      };
      const client = await open({ accountName: name, retentionPolicy: policy, recoveryProvider: provider, resetTrust, secretStore: secrets, store, transport, now: clock.now });
      client.subscribe((e) => {
        events.push(e);
        if (e.kind === "stateChanged") {
          const acct = host.accounts.get(name);
          if (acct) bound = host.asDevice(name, Uint8Array.from(Buffer.from(acct.certificateHash, "hex")));
        }
      });
      const existing = host.accounts.get(name);
      if (existing) bound = host.asDevice(name, Uint8Array.from(Buffer.from(existing.certificateHash, "hex")));
      return { client, store, secrets, events, provider };
    }
  };
}

const loc = (clock: Clock, lat = 37.7749) => locationFromDegrees(lat, -122.4194, 5, clock.now());

async function code(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "OK";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

/** Alice creates a circle, Bob asks to join, Alice approves, both sync. */
async function circleOfTwo(w: World) {
  const a = await w.device("alice");
  const b = await w.device("bob");
  await a.client.initializeAccount();
  await b.client.initializeAccount();
  const { circleId } = await a.client.circles.create();
  const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
  await b.client.circles.requestJoin(circleId, aliceId);
  await a.client.sync();
  await a.client.circles.approve(circleId, "bob");
  await a.client.sync();
  await b.client.sync();
  await a.client.sync();
  return { a, b, circleId, aliceId, bobId: (await b.client.inspect()).identityId ?? new Uint8Array() };
}

describe("scenarios 1 and 2: create, request, approve", () => {
  it("the owner is notified once, the requester's first manifest names both devices, the owner's audience rotates once", async () => {
    const w = world();
    const { a, b, circleId } = await circleOfTwo(w);
    expect(w.host.notifications.filter((n) => n.kind === "joinRequest" && n.to === "alice").length).toBe(1);
    const joinEvents = a.events.filter((e) => e.kind === "joinRequests");
    expect(joinEvents.length).toBeGreaterThanOrEqual(1);
    const bobStream = [...w.host.streams.values()].find((s) => s.accountName === "bob");
    const bobManifest = bobStream?.epochs.get(bobStream.currentEpoch);
    expect(bobManifest?.rows.length).toBe(2);
    const aliceStream = [...w.host.streams.values()].find((s) => s.accountName === "alice");
    // Alice: epoch 1 (self), epoch 2 after approving Bob. Nothing further.
    expect(aliceStream?.currentEpoch).toBe(2);
    const circles = await a.client.circles.list();
    expect(circles[0]?.members.length).toBe(2);
    expect((await b.client.getState()).circles[0]?.status).toBe("member");
    void circleId;
  });

  it("approved while the requester is offline: on return the requester shares from its vault preference without a second approval", async () => {
    const w = world();
    const a = await w.device("alice");
    const b = await w.device("bob");
    await a.client.initializeAccount();
    await b.client.initializeAccount();
    const { circleId } = await a.client.circles.create();
    const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
    await b.client.circles.requestJoin(circleId, aliceId, { shareOnApproval: true });
    await a.client.sync();
    await a.client.circles.approve(circleId, "bob");
    // Bob was offline; he comes back and syncs once.
    const before = w.host.notifications.filter((n) => n.kind === "joinRequest").length;
    await b.client.sync();
    await b.client.enqueueLocation(loc(w.clock));
    await b.client.sync();
    await a.client.sync();
    expect(w.host.notifications.filter((n) => n.kind === "joinRequest").length).toBe(before);
    expect(await a.client.latest((await b.client.inspect()).identityId ?? new Uint8Array())).toBeDefined();
  });
});

describe("scenarios 3 to 7: device replacement", () => {
  it("3: the owner replaces the device with a member offline; the circle revision is unchanged; the member rotates on return", async () => {
    const w = world();
    const { a, b, circleId } = await circleOfTwo(w);
    const revision = (await a.client.circles.list())[0]?.revision;
    // Alice's new phone on the same platform account.
    const a2 = await w.device("alice", (a.provider as Platform).twin());
    const restored = await a2.client.restoreAccount();
    expect(restored.generation).toBe(2n);
    expect(toHex(restored.identityId)).toBe(toHex((await a.client.inspect()).identityId ?? new Uint8Array()));
    await a2.client.sync();
    expect((await a2.client.circles.list())[0]?.revision).toBe(revision);
    expect((await a2.client.circles.list())[0]?.owned).toBe(true);
    // The old phone learns it is retired.
    await a.client.sync();
    expect((await a.client.getState()).status).toBe("retired");
    // The owner signs revision plus one from the new phone (a removal and re-admission would do the same).
    const c = await w.device("carol");
    await c.client.initializeAccount();
    await c.client.circles.requestJoin(circleId, restored.identityId);
    await a2.client.sync();
    const approved = await a2.client.circles.approve(circleId, "carol");
    expect(approved.revision).toBe((revision ?? 0n) + 1n);
    // Bob returns: he rotates to Alice's new device and can read her.
    await b.client.sync();
    expect(b.events.some((e) => e.kind === "deviceChanged")).toBe(true);
    await a2.client.enqueueLocation(loc(w.clock, 1));
    await a2.client.sync();
    await b.client.sync();
    expect(await b.client.latest(restored.identityId)).toBeDefined();
  });

  it("4: a member replaces the device while the owner is offline; online authors rotate within one sync; the old device opens nothing new", async () => {
    const w = world();
    const { a, b, aliceId, bobId } = await circleOfTwo(w);
    const b2 = await w.device("bob", (b.provider as Platform).twin());
    await b2.client.restoreAccount();
    await b2.client.sync();
    // Alice syncs once (the owner is "offline": nothing of the owner is needed).
    await a.client.sync();
    expect(a.events.filter((e) => e.kind === "deviceChanged").length).toBe(1);
    await a.client.enqueueLocation(loc(w.clock, 2));
    await a.client.sync();
    await b2.client.sync();
    expect(await b2.client.latest(aliceId)).toBeDefined();
    // The old phone: retired, and it never received the new epoch's wrap.
    await b.client.sync();
    expect((await b.client.getState()).status).toBe("retired");
    const aliceStream = [...w.host.streams.values()].find((s) => s.accountName === "alice");
    const newEpoch = aliceStream?.epochs.get(aliceStream.currentEpoch);
    const oldBobCert = [...(aliceStream?.epochs.get(1)?.rows ?? [])].find((r) => r.identityId === toHex(bobId))?.certificateHash;
    expect(newEpoch?.rows.find((r) => r.identityId === toHex(bobId))?.certificateHash).not.toBe(oldBobCert);
  });

  it("5: lost device with full old-device state: after rotation the attacker opens nothing new", async () => {
    const w = world();
    const { a, b, aliceId } = await circleOfTwo(w);
    // The attacker keeps Bob's whole old phone: store, secrets, provider access. Bob restores elsewhere.
    const attacker = b;
    const b2 = await w.device("bob", (b.provider as Platform).twin());
    await b2.client.restoreAccount();
    await b2.client.sync();
    await a.client.sync(); // Alice rotates to the new device
    await a.client.enqueueLocation(loc(w.clock, 3));
    await a.client.sync();
    const before = (await attacker.client.history({ authorIdentityId: aliceId })).length;
    await attacker.client.sync(); // retired: nothing is read
    expect((await attacker.client.getState()).status).toBe("retired");
    expect((await attacker.client.history({ authorIdentityId: aliceId })).length).toBe(before);
    // Even reading the relay directly with the old certificate yields nothing addressed to it.
    const oldCert = [...w.host.accounts.get("bob")?.retiredCertificates ?? []][0] ?? "";
    const rogue = w.host.asDevice("bob", Uint8Array.from(Buffer.from(oldCert, "hex")));
    const aliceStream = [...w.host.streams.entries()].find(([, s]) => s.accountName === "alice");
    const page = await rogue.relay.readRecords(Uint8Array.from(Buffer.from(aliceStream?.[0] ?? "", "hex")), 0n, 10);
    expect(page.records.length).toBe(0);
  });

  it("6: two candidate devices activate concurrently: exactly one commits", async () => {
    const w = world();
    const { a } = await circleOfTwo(w);
    const x = await w.device("alice", (a.provider as Platform).twin());
    const y = await w.device("alice", (a.provider as Platform).twin());
    const results = await Promise.allSettled([x.client.restoreAccount(), y.client.restoreAccount()]);
    const ok = results.filter((r) => r.status === "fulfilled").length;
    expect(ok).toBe(1);
    const failed = results.find((r) => r.status === "rejected") as PromiseRejectedResult | undefined;
    expect((failed?.reason as KavachError).code).toBe("ACCOUNT_RECOVERY_REQUIRED");
    expect(w.host.accounts.get("alice")?.generation).toBe(2n);
  });

  it("7: lose the local store, keep recovery: membership survives; the new stream starts at epoch 1, counter 0", async () => {
    const w = world();
    const { a, circleId } = await circleOfTwo(w);
    await a.client.enqueueLocation(loc(w.clock));
    await a.client.sync();
    const again = await w.device("alice", (a.provider as Platform).twin());
    await again.client.restoreAccount();
    await again.client.sync();
    const circles = await again.client.circles.list();
    expect(circles.map((c) => toHex(c.circleId))).toEqual([toHex(circleId)]);
    expect(circles[0]?.status).toBe("member");
    const info = await again.client.inspect();
    expect(info.activeEpoch).toBe(1);
    const r = await again.client.enqueueLocation(loc(w.clock));
    const row = await again.store.read((tx) => tx.get("outbox", toHex(r.recordId)));
    expect([row?.epoch, row?.counter]).toEqual([1, 0]);
  });
});

describe("scenarios 8 to 10: enrollment and recovery", () => {
  it("8: enrollment with the provider unavailable: the account exists, sharing works, status says not backed up, the code is reachable", async () => {
    const w = world();
    const p = new Platform("alice@platform");
    p.status_ = "unavailable";
    const a = await w.device("alice", p);
    await a.client.initializeAccount();
    expect((await a.client.recoveryStatus()).backupState).toBe("unavailable");
    await a.client.enqueueLocation(loc(w.clock));
    expect((await a.client.sync()).outbox.accepted).toBe(1);
    expect((await a.client.recoveryCode()).startsWith("SS5R-")).toBe(true);
  });

  it("9 and 10: platform recovery to a second device; a wrong platform account yields unavailable; both paths failing preserves circles", async () => {
    const w = world();
    const { a, circleId } = await circleOfTwo(w);
    const wrong = await w.device("alice", new Platform("someone-else@platform"));
    expect(await code(() => wrong.client.restoreAccount())).toBe("ACCOUNT_RECOVERY_REQUIRED");
    expect(w.host.accounts.get("alice")?.generation).toBe(1n);
    expect(w.host.circles.get(toHex(circleId))?.closed).toBe(false);
    const wrongCode = "SS5R-" + "A".repeat(43);
    expect(await code(() => wrong.client.restoreAccount(wrongCode))).toBe("DECRYPT_FAILED");
    // The right code works even on the wrong platform account.
    const right = await w.device("alice", new Platform("someone-else@platform"));
    const codeText = await a.client.recoveryCode();
    const restored = await right.client.restoreAccount(codeText);
    expect(restored.generation).toBe(2n);
  });
});

describe("scenarios 11 to 15: reset, removal, limits", () => {
  it("11: a valid receipt closes owned circles at peers and requires re-admission; a bare key change closes nothing", async () => {
    const w = world();
    const { a, b, circleId } = await circleOfTwo(w);
    await a.client.resetAccount({ confirmed: true });
    const resetReport = await b.client.sync();
    expect(resetReport.errors).toEqual([]);
    expect(b.events.some((e) => e.kind === "accountKeyChanged" && !e.quarantined)).toBe(true);
    expect((await b.client.circles.list())[0]?.status).toBe("closed");
    // Bob's audience no longer includes the old Alice; his next epoch names only himself.
    await b.client.enqueueLocation(loc(w.clock));
    await b.client.sync();
    const bobStream = [...w.host.streams.values()].find((s) => s.accountName === "bob");
    expect(bobStream?.epochs.get(bobStream.currentEpoch)?.rows.length).toBe(1);
    // A bare directory key change (no receipt) on another account: quarantined, nothing closes.
    const c = await w.device("carol");
    await c.client.initializeAccount();
    const { circleId: c2 } = await c.client.circles.create();
    const carolId = (await c.client.inspect()).identityId ?? new Uint8Array();
    await b.client.circles.requestJoin(c2, carolId);
    await c.client.sync();
    await c.client.circles.approve(c2, "bob");
    await b.client.sync();
    const acct = w.host.accounts.get("carol");
    if (!acct) throw new Error("carol");
    const impostor = await w.device("carol-impostor");
    void impostor;
    const { openAccount, certify, newDevice } = await import("../src/identity.js");
    const fake = openAccount("carol", randomBytes(32));
    acct.previousIdentities.add(acct.identityId);
    acct.accountKey = fake.account.publicKey;
    acct.certificate = certify(fake, newDevice(), 5n);
    acct.certificateHash = toHex((await import("../src/crypto.js")).bodyHash(acct.certificate.subarray(0, acct.certificate.length - 64)));
    acct.identityId = toHex(fake.identityId);
    const report = await b.client.sync();
    expect(report.metadata.quarantined).toBe(1);
    expect((await b.client.circles.list()).find((x) => toHex(x.circleId) === toHex(c2))?.status).toBe("member");
    expect((await b.client.getState()).status).toBe("quarantined");
    void circleId;
  });

  it("11b: a receipt under a key a newer list removed is RESET_KEY_REVOKED and the account stays quarantined", async () => {
    const w = world();
    const { a, b } = await circleOfTwo(w);
    await a.client.resetAccount({ confirmed: true });
    // Before Bob syncs, the management key publishes a list without the operational key. Bob's cached
    // list is still fresh, so he learns of the removal at his next recheck (section 15, limit 6).
    w.clock.advance(25n * 3_600_000n);
    w.host.resetKeyList = buildResetKeyList({ version: 2n, issuedAt: w.clock.now(), expiresAt: w.clock.now() + 2_592_000_000n, keys: [] }, management.secretKey);
    const report = await b.client.sync();
    expect(report.errors.map((e) => `${e.operation}:${e.code}@${e.stage}`)).toContain("resetReceipt:RESET_KEY_REVOKED@resetReceipt");
    expect((await b.client.circles.list())[0]?.status).toBe("member");
    expect(report.metadata.quarantined).toBe(1);
  });

  it("12 and 13: removal with the owner online rotates and locks the removed member out; a withheld removal keeps sharing with the last snapshot", async () => {
    const w = world();
    const { a, b, bobId } = await circleOfTwo(w);
    const circleId = (await a.client.circles.list())[0]?.circleId ?? new Uint8Array();
    const before = [...w.host.streams.values()].find((s) => s.accountName === "alice")?.currentEpoch ?? 0;
    await a.client.circles.remove(circleId, bobId);
    await a.client.sync();
    const stream = [...w.host.streams.values()].find((s) => s.accountName === "alice");
    expect(stream?.currentEpoch).toBe(before + 1);
    expect(stream?.epochs.get(stream.currentEpoch)?.rows.length).toBe(1);
    await a.client.enqueueLocation(loc(w.clock, 9));
    await a.client.sync();
    await b.client.sync();
    expect((await b.client.circles.list())[0]?.status).toBe("left");
    // 13: a server that withholds the removal from Carol: Carol keeps sharing with the last snapshot and shows its age.
    const c = await w.device("carol");
    await c.client.initializeAccount();
    const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
    await c.client.circles.requestJoin(circleId, aliceId);
    await a.client.sync();
    await a.client.circles.approve(circleId, "carol");
    const carolReport = await c.client.sync();
    expect(carolReport.errors).toEqual([]);
    expect((await c.client.circles.list())[0]?.status).toBe("member");
    w.host.withholdSnapshots = true;
    w.clock.advance(3_600_000n);
    await c.client.sync();
    const view = (await c.client.circles.list())[0];
    expect(view?.status).toBe("member");
    expect(view?.snapshotAgeMs).toBe(3_600_000n);
    await c.client.enqueueLocation(loc(w.clock));
    expect((await c.client.sync()).outbox.accepted).toBe(1);
  });

  it("14: remove then re-admit between two syncs still rotates", async () => {
    const w = world();
    const { a, b, bobId } = await circleOfTwo(w);
    const circleId = (await a.client.circles.list())[0]?.circleId ?? new Uint8Array();
    const revBefore = (await b.client.inspect()).desiredRevision;
    await a.client.circles.remove(circleId, bobId);
    await a.client.circles.approve(circleId, "bob");
    await b.client.sync();
    expect((await b.client.inspect()).desiredRevision).toBeGreaterThan(revBefore);
    expect((await b.client.circles.list())[0]?.status).toBe("member");
  });

  it("15: over-limit union across circles pauses with RECIPIENT_LIMIT and truncates nothing", async () => {
    const w = world();
    const a = await w.device("alice");
    await a.client.initializeAccount();
    const { circleId } = await a.client.circles.create();
    // 100 members in one circle (the owner plus 99), then one more through a second circle.
    for (let i = 1; i <= 99; i++) {
      const m = await w.device(`m${i}`);
      await m.client.initializeAccount();
      const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
      await m.client.circles.requestJoin(circleId, aliceId);
      await a.client.circles.approve(circleId, `m${i}`);
    }
    await a.client.sync();
    expect((await a.client.getState()).status).toBe("ready");
    const extra = await w.device("extra");
    await extra.client.initializeAccount();
    const { circleId: second } = await extra.client.circles.create();
    const extraId = (await extra.client.inspect()).identityId ?? new Uint8Array();
    await a.client.circles.requestJoin(second, extraId);
    await extra.client.sync();
    await extra.client.circles.approve(second, "alice");
    const report = await a.client.sync();
    expect(report.epoch).toBe("paused");
    const state = await a.client.getState();
    expect(state.status).toBe("paused");
    expect(state.paused).toBe("limit");
    expect(await code(() => a.client.enqueueLocation(loc(w.clock)))).toBe("RECIPIENT_LIMIT");
  }, 60_000);
});

describe("scenarios 24 and 26 through the client", () => {
  it("24: a check-in then two locations: three records, the check-in survives, the pin is the last location, notifications match", async () => {
    const w = world();
    const { a, b, aliceId } = await circleOfTwo(w);
    const start = w.host.notifications.length;
    await a.client.enqueueCheckIn(loc(w.clock, 10));
    await a.client.enqueueLocation(loc(w.clock, 11));
    await a.client.enqueueLocation(loc(w.clock, 12));
    await a.client.sync();
    await b.client.sync();
    const h = await b.client.history({ authorIdentityId: aliceId });
    expect(h.map((x) => x.kind)).toEqual([1, 0, 0]);
    expect(b.events.filter((e) => e.kind === "checkIn").length).toBe(1);
    expect(w.host.notifications.slice(start).filter((n) => n.to === "bob").map((n) => n.kind)).toEqual(["checkIn", "wake", "wake"]);
    const pin = await b.client.latest(aliceId);
    expect(pin && toHex(pin.payload)).toBe(toHex((await import("../src/codec.js")).encodeLocation(loc(w.clock, 12))));
  });

  it("26: hygiene rotation at the configured interval produces a new epoch and needsLocation", async () => {
    const w = world();
    const { a } = await circleOfTwo(w);
    const before = (await a.client.inspect()).activeEpoch ?? 0;
    w.clock.advance(31n * 86_400_000n);
    a.events.length = 0;
    await a.client.enqueueLocation(loc(w.clock));
    expect((await a.client.inspect()).activeEpoch).toBe(before + 1);
    expect(a.events.some((e) => e.kind === "needsLocation")).toBe(true);
  });
});
