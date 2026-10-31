/** Remaining acceptance criteria of steps 5, 12 and 13 at the client level. */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { open, type Client, type ClientEvent } from "../src/client.js";
import { buildResetKeyList } from "../src/codec.js";
import { C, H, ready, signingKeypairFromSeed } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { locationFromDegrees } from "../src/record.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import type { ProviderLoadResult, ProviderSaveResult, ProviderStatusResult, RecoveryProvider } from "../src/vault.js";
import { FakeHost } from "./fakeHost.js";
import { Clock, policy } from "./harness.js";

beforeAll(() => ready());

class Platform implements RecoveryProvider {
  readonly items = new Map<string, Uint8Array>();
  async load(accountName: string, identityId: Uint8Array): Promise<ProviderLoadResult> {
    const k = this.items.get(`${accountName}:${toHex(identityId)}`);
    return k ? { status: "available", recoveryKey: k } : { status: "unavailable" };
  }
  async save(accountName: string, identityId: Uint8Array, recoveryKey: Uint8Array): Promise<ProviderSaveResult> {
    this.items.set(`${accountName}:${toHex(identityId)}`, recoveryKey);
    return { status: "available", backupState: "pending" };
  }
  async status(): Promise<ProviderStatusResult> {
    return { status: "available", backupState: "pending" };
  }
  async eraseLocalAccess(): Promise<void> {}
}

const management = signingKeypairFromSeed(H(C("identity")));
const operational = signingKeypairFromSeed(H(C("stream")));
const operationalId = new Uint8Array(16).fill(7);
const resetTrust = { managementKey: management.publicKey, minimumVersion: 1n };

interface Dev {
  client: Client;
  store: MemoryStore;
  events: ClientEvent[];
  provider: Platform;
}

function world(listLifetimeMs = 2_592_000_000n) {
  const host = new FakeHost();
  const clock = new Clock();
  host.now = clock.now;
  host.resetSigner = { key: operational, keyId: operationalId };
  host.resetKeyList = buildResetKeyList({ version: 1n, issuedAt: clock.now(), expiresAt: clock.now() + listLifetimeMs, keys: [{ keyId: operationalId, publicKey: operational.publicKey }] }, management.secretKey);
  const platforms = new Map<string, Platform>();
  async function device(name: string, store = new MemoryStore(), secrets = new MemorySecretStore()): Promise<Dev> {
    const provider = platforms.get(name) ?? new Platform();
    platforms.set(name, provider);
    const events: ClientEvent[] = [];
    let bound: ReturnType<FakeHost["asDevice"]> | undefined;
    const bind = (): ReturnType<FakeHost["asDevice"]> => {
      const acct = host.accounts.get(name);
      if (acct) bound = host.asDevice(name, Uint8Array.from(Buffer.from(acct.certificateHash, "hex")));
      return bound ?? host.asDevice(name, new Uint8Array(32));
    };
    const transport: ReturnType<FakeHost["asDevice"]> = {
      get directory() {
        return bind().directory;
      },
      get relay() {
        return bind().relay;
      },
      observe: (h) => bind().observe(h)
    };
    const client = await open({ accountName: name, retentionPolicy: policy, recoveryProvider: provider, resetTrust, secretStore: secrets, store, transport, now: clock.now });
    client.subscribe((e) => events.push(e));
    return { client, store, events, provider };
  }
  return { host, clock, device };
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

describe("step 5: join requests", () => {
  it("an expired or withdrawn request cannot block an unrelated approval", async () => {
    const w = world();
    const a = await w.device("alice");
    const b = await w.device("bob");
    const c = await w.device("carol");
    for (const d of [a, b, c]) await d.client.initializeAccount();
    const { circleId } = await a.client.circles.create();
    const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
    await b.client.circles.requestJoin(circleId, aliceId);
    await c.client.circles.requestJoin(circleId, aliceId);
    // Bob's request expires on the host (7 days); Carol's is fresh.
    w.clock.advance(8n * 86_400_000n);
    await c.client.circles.requestJoin(circleId, aliceId);
    await a.client.sync();
    const requests = a.events.filter((e) => e.kind === "joinRequests").at(-1);
    expect(requests?.kind === "joinRequests" && requests.accountNames).toEqual(["carol"]);
    const approved = await a.client.circles.approve(circleId, "carol");
    expect(approved.revision).toBe(2n);
    // Approving Bob later still works: approval needs no live request, only the owner's choice.
    expect((await a.client.circles.approve(circleId, "bob")).revision).toBe(3n);
  });

  it("a recovering device learns admitted or waiting from the current snapshot, not from the vault", async () => {
    const w = world();
    const a = await w.device("alice");
    const b = await w.device("bob");
    await a.client.initializeAccount();
    await b.client.initializeAccount();
    const { circleId } = await a.client.circles.create();
    const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
    await b.client.circles.requestJoin(circleId, aliceId);
    // Bob loses his phone before approval and restores on a new one: the vault pins the circle, still waiting.
    const b2 = await w.device("bob");
    await b2.client.restoreAccount();
    await b2.client.sync();
    expect((await b2.client.circles.list())[0]?.status).toBe("requested");
    await a.client.sync();
    await a.client.circles.approve(circleId, "bob");
    await b2.client.sync();
    expect((await b2.client.circles.list())[0]?.status).toBe("member");
    // The vault itself never recorded admission: the entry is the same before and after.
    const vault = await b2.store.read((tx) => tx.get("vault", "vault"));
    expect(vault?.pending).toBe(false);
  });
});

describe("step 12: an expired list defers a reset without pausing sharing", () => {
  it("RESET_KEYS_REQUIRED is reported, the peer keeps the pinned key, and location sharing continues", async () => {
    const w = world(3_600_000n); // a one-hour list, never renewed
    const a = await w.device("alice");
    const b = await w.device("bob");
    await a.client.initializeAccount();
    await b.client.initializeAccount();
    const { circleId } = await a.client.circles.create();
    const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
    await b.client.circles.requestJoin(circleId, aliceId);
    await a.client.sync();
    await a.client.circles.approve(circleId, "bob");
    await b.client.sync();
    w.clock.advance(2n * 3_600_000n);
    await a.client.resetAccount({ confirmed: true });
    const report = await b.client.sync();
    expect(report.errors.some((e) => e.startsWith("RESET_KEYS_REQUIRED"))).toBe(true);
    expect((await b.client.circles.list())[0]?.status).toBe("member");
    expect(report.metadata.resets).toBe(0);
    // Sharing is not paused: Bob's next location is sealed, sent and accepted.
    await b.client.enqueueLocation(loc(w.clock));
    const next = await b.client.sync();
    expect(next.outbox.accepted).toBe(1);
    expect((await b.client.getState()).status).not.toBe("paused");
  });
});

describe("step 13: remaining appendix scenarios through the client", () => {
  async function pair(w: ReturnType<typeof world>) {
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
    return { a, b, circleId, aliceId };
  }

  it("20: delivered out of counter order, both in history and the pin stays at the newer", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    for (let i = 0; i < 8; i++) await a.client.enqueueLocation(loc(w.clock, i));
    await a.client.sync();
    // Reorder the relay's retained records so 7 is read before 6.
    const stream = [...w.host.streams.values()].find((s) => s.accountName === "alice");
    if (!stream) throw new Error("stream");
    const r6 = stream.records.get(7n);
    const r7 = stream.records.get(8n);
    if (r6 && r7) {
      stream.records.set(7n, r7);
      stream.records.set(8n, r6);
    }
    await b.client.sync();
    const h = await b.client.history({ authorIdentityId: aliceId });
    expect(h.length).toBe(8);
    const pin = await b.client.latest(aliceId);
    expect(pin && toHex(pin.plaintext)).toBe(toHex((await import("../src/codec.js")).encodeLocation(loc(w.clock, 7))));
  });

  it("25: two execution contexts enqueue concurrently: counters are unique and the order is preserved", async () => {
    const w = world();
    const secrets = new MemorySecretStore();
    const store = new MemoryStore();
    const fg = await w.device("alice", store, secrets);
    await fg.client.initializeAccount();
    const { circleId } = await fg.client.circles.create();
    void circleId;
    await fg.client.sync();
    // The background location task: a second client over another handle on the same store and secrets.
    const bg = await w.device("alice", store.fork(), secrets);
    expect((await bg.client.getState()).status).toBe("ready");
    const ids = await Promise.all([
      ...Array.from({ length: 10 }, (_, i) => fg.client.enqueueLocation(loc(w.clock, i))),
      ...Array.from({ length: 10 }, (_, i) => bg.client.enqueueLocation(loc(w.clock, 50 + i)))
    ]);
    const rows = await store.read((tx) => tx.list("outbox").map(([, r]) => r.counter).sort((x, y) => x - y));
    expect(rows).toEqual(Array.from({ length: 20 }, (_, i) => i));
    expect(new Set(ids.map((r) => toHex(r.recordId))).size).toBe(20);
    const report = await fg.client.sync();
    expect(report.outbox.accepted).toBe(20);
    // Alice is alone in her circle, so the relay completes each record on append; its checkpoint
    // shows the twenty counters arrived in order.
    const stream = [...w.host.streams.values()].find((s) => s.accountName === "alice");
    expect(stream?.highWater).toEqual({ epoch: 1, counter: 19 });
    expect(stream?.tail).toBe(20n);
  });

  it("27: a superseded device sends after its replacement activated: the relay refuses; a reader keeps the pin", async () => {
    const w = world();
    const { a, b, aliceId } = await pair(w);
    await a.client.enqueueLocation(loc(w.clock, 1));
    await a.client.sync();
    await b.client.sync();
    const a2 = await w.device("alice");
    await a2.client.restoreAccount();
    await a2.client.sync();
    // The old phone, not yet aware, queues and tries to send.
    await a.client.enqueueLocation(loc(w.clock, 2));
    const report = await a.client.sync();
    expect((await a.client.getState()).status).toBe("retired");
    expect(report.outbox.accepted).toBe(0);
    await b.client.sync();
    const pin = await b.client.latest(aliceId);
    expect(pin && toHex(pin.plaintext)).toBe(toHex((await import("../src/codec.js")).encodeLocation(loc(w.clock, 1))));
  });

  it("every state transition is emitted only after its durable commit", async () => {
    const w = world();
    const a = await w.device("alice");
    const seen: { status: string; durable: string | undefined }[] = [];
    a.client.subscribe((e) => {
      if (e.kind === "stateChanged") {
        // Read the store synchronously through its snapshot: the header must already carry the state.
        const meta = a.store.snapshot()["meta"]?.["meta"] as { state?: string } | undefined;
        seen.push({ status: e.state.status, durable: meta?.state });
      }
    });
    await a.client.initializeAccount();
    const { circleId } = await a.client.circles.create();
    void circleId;
    await a.client.sync();
    expect(seen.length).toBeGreaterThan(0);
    for (const s of seen) expect(s.durable).toBe("ACTIVE");
    // Retirement: the RETIRED state is emitted after the header says so.
    const a2 = await w.device("alice");
    await a2.client.restoreAccount();
    seen.length = 0;
    await a.client.sync();
    expect(seen.at(-1)).toEqual({ status: "retired", durable: "RETIRED" });
  });
});
