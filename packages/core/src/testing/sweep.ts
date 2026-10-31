/**
 * The crash and lost-response sweeps of build step 16. One scenario (two accounts, a circle,
 * locations both ways, a check-in, concurrent contexts, a phone replacement) runs once with no
 * fault to count the victim's transaction boundaries, then once per boundary and phase with the
 * victim's process crashing there, restarting, and finishing the scenario. After every run the
 * durable-state outcomes of protocol section 11 are checked against the host's view.
 */
import { fromHex, toHex } from "../bytes.js";
import { open, type Client, type ClientEvent } from "../client.js";
import { buildResetKeyList } from "../codec.js";
import { C, H, signingKeypairFromSeed } from "../crypto.js";
import { KavachError } from "../errors.js";
import { locationFromDegrees } from "../record.js";
import { MemorySecretStore, type Store } from "../store.js";
import type { Transport } from "../transport.js";
import { TestClock, testPolicy } from "./clock.js";
import { FakeHost } from "./fakeHost.js";
import { FaultyStore, MaliciousTransport, type CrashPhase, type CrashPlan, type MutationName } from "./faults.js";
import { MemoryPlatformProvider } from "./providers.js";

export type DeviceName = "alice" | "bob" | "bob2";

export interface SweepStores {
  /** A durable store for the named device of this run, empty. */
  open(run: string, name: DeviceName): Promise<Store> | Store;
  /** The same durable state as a restarted process opens it: a new handle on the same file. */
  reopen(run: string, name: DeviceName): Promise<Store> | Store;
  /** Another in-process handle on the same durable state, when the engine can give one. */
  fork?(run: string, name: DeviceName): Store;
  dispose?(run: string): Promise<void> | void;
}

export interface SweepOptions {
  readonly stores: SweepStores;
  readonly victim: DeviceName;
  readonly phases?: readonly CrashPhase[];
  /** Run only these boundaries (for narrowing a failure). */
  readonly only?: readonly number[];
}

export interface SweepRun {
  readonly at: number;
  readonly phase: CrashPhase;
  /** The scenario step during which the process died. */
  readonly crashedDuring: string;
  /** What the re-invoked step answered after the restart. */
  readonly retry: string;
}

export interface SweepResult {
  readonly boundaries: number;
  readonly runs: readonly SweepRun[];
}

export interface LostResponseRun {
  readonly mutation: MutationName;
  /** Whether the victim actually issued that mutation in this scenario. */
  readonly exercised: boolean;
}

const management = signingKeypairFromSeed(H(C("identity")));
const operational = signingKeypairFromSeed(H(C("stream")));
const operationalId = new Uint8Array(16).fill(7);
const resetTrust = { managementKey: management.publicKey, minimumVersion: 1n };

interface Device {
  name: DeviceName;
  client: Client;
  store: FaultyStore;
  secrets: MemorySecretStore;
  events: ClientEvent[];
  provider: MemoryPlatformProvider;
  transport: MaliciousTransport;
}

interface Runtime {
  host: FakeHost;
  clock: TestClock;
  devices: Map<DeviceName, Device>;
}

function newHost(): { host: FakeHost; clock: TestClock } {
  const host = new FakeHost();
  const clock = new TestClock();
  host.now = clock.now;
  host.resetSigner = { key: operational, keyId: operationalId };
  host.resetKeyList = buildResetKeyList({ version: 1n, issuedAt: clock.now(), expiresAt: clock.now() + 2_592_000_000n, keys: [{ keyId: operationalId, publicKey: operational.publicKey }] }, management.secretKey);
  return { host, clock };
}

function accountOf(name: DeviceName): string {
  return name === "bob2" ? "bob" : name;
}

/** The transport of a device: bound to the account's current certificate at the host on every call. */
export function hostTransport(host: FakeHost, account: string): Transport {
  const bind = (): Transport => {
    const acct = host.accounts.get(account);
    return host.asDevice(account, acct ? fromHex(acct.certificateHash) : new Uint8Array(32));
  };
  return {
    get directory() {
      return bind().directory;
    },
    get relay() {
      return bind().relay;
    },
    observe: (h) => bind().observe(h)
  };
}

async function openDevice(rt: Runtime, name: DeviceName, store: FaultyStore, secrets: MemorySecretStore, provider: MemoryPlatformProvider, transport: MaliciousTransport): Promise<Device> {
  const events: ClientEvent[] = [];
  const client = await open({ accountName: accountOf(name), retentionPolicy: testPolicy, recoveryProvider: provider, resetTrust, secretStore: secrets, store, transport, now: rt.clock.now });
  client.subscribe((e) => events.push(e));
  const d: Device = { name, client, store, secrets, events, provider, transport };
  rt.devices.set(name, d);
  return d;
}

type Step = { name: string; run: () => Promise<unknown> };

interface Scenario {
  steps: Step[];
  rt: Runtime;
}

function scenario(rt: Runtime, stores: SweepStores, run: string): Scenario {
  const d = (n: DeviceName): Device => {
    const x = rt.devices.get(n);
    if (!x) throw new Error("no device " + n);
    return x;
  };
  let circleId: Uint8Array = new Uint8Array(16);
  let aliceId: Uint8Array = new Uint8Array(32);
  const loc = (lat: number): ReturnType<typeof locationFromDegrees> => locationFromDegrees(lat, -122.4194, 5, rt.clock.now());
  const sync = (n: DeviceName) => async (): Promise<unknown> => {
    rt.clock.advance(1_000n);
    return d(n).client.sync();
  };
  const steps: Step[] = [
    { name: "alice.init", run: () => d("alice").client.initializeAccount() },
    { name: "bob.init", run: () => d("bob").client.initializeAccount() },
    {
      name: "alice.create",
      run: async () => {
        circleId = (await d("alice").client.circles.create()).circleId;
        aliceId = (await d("alice").client.inspect()).identityId ?? aliceId;
      }
    },
    { name: "bob.requestJoin", run: () => d("bob").client.circles.requestJoin(circleId, aliceId) },
    { name: "alice.sync#1", run: sync("alice") },
    { name: "alice.approve", run: () => d("alice").client.circles.approve(circleId, "bob") },
    { name: "alice.sync#2", run: sync("alice") },
    { name: "bob.sync#1", run: sync("bob") },
    { name: "alice.sync#3", run: sync("alice") },
    { name: "alice.enqueue#1", run: () => d("alice").client.enqueueLocation(loc(1)) },
    { name: "alice.enqueue#2", run: () => d("alice").client.enqueueLocation(loc(2)) },
    { name: "alice.sync#4", run: sync("alice") },
    { name: "bob.sync#2", run: sync("bob") },
    { name: "bob.checkIn", run: () => d("bob").client.enqueueCheckIn(loc(3)) },
    { name: "bob.sync#3", run: sync("bob") },
    { name: "alice.sync#5", run: sync("alice") },
    {
      name: "alice.concurrent",
      run: async () => {
        if (!stores.fork) return;
        // The background location task: a second client over another handle on the same store.
        const a = d("alice");
        const bg = await open({ accountName: "alice", retentionPolicy: testPolicy, recoveryProvider: a.provider, resetTrust, secretStore: a.secrets, store: a.store.fork(), transport: a.transport, now: rt.clock.now });
        await Promise.all([a.client.sync(), bg.enqueueLocation(loc(4)), bg.enqueueLocation(loc(5))]);
        await a.client.sync();
      }
    },
    { name: "bob2.restore", run: () => d("bob2").client.restoreAccount() },
    { name: "bob2.sync#1", run: sync("bob2") },
    { name: "alice.sync#6", run: sync("alice") },
    { name: "alice.enqueue#3", run: () => d("alice").client.enqueueLocation(loc(6)) },
    { name: "alice.sync#7", run: sync("alice") },
    { name: "bob2.sync#2", run: sync("bob2") },
    { name: "bob.sync#4", run: sync("bob") },
    { name: "bob2.checkIn", run: () => d("bob2").client.enqueueCheckIn(loc(7)) },
    { name: "bob2.sync#3", run: sync("bob2") },
    { name: "alice.sync#8", run: sync("alice") }
  ];
  void run;
  return { steps, rt };
}

async function setup(stores: SweepStores, run: string, plan: { victim: DeviceName; crash?: CrashPlan; lose?: MutationName }): Promise<Runtime> {
  const { host, clock } = newHost();
  const rt: Runtime = { host, clock, devices: new Map() };
  const bobPlatform = new MemoryPlatformProvider("bob@platform");
  for (const name of ["alice", "bob", "bob2"] as const) {
    const inner = await stores.open(run, name);
    const isVictim = name === plan.victim;
    const forkInner = stores.fork ? (): Store => stores.fork?.(run, name) as Store : undefined;
    const store = new FaultyStore(inner, isVictim ? plan.crash : undefined, forkInner);
    const transport = new MaliciousTransport(hostTransport(host, accountOf(name)));
    if (isVictim && plan.lose) transport.knobs.loseResponseOf.add(plan.lose);
    const provider = name === "alice" ? new MemoryPlatformProvider("alice@platform") : bobPlatform.twin();
    await openDevice(rt, name, store, new MemorySecretStore(), provider, transport);
  }
  return rt;
}

/** The victim's process restarts: a new handle on the same durable state, the same secrets. */
async function restart(rt: Runtime, stores: SweepStores, run: string, victim: DeviceName): Promise<void> {
  const old = rt.devices.get(victim);
  if (!old) throw new Error("no victim");
  const forkInner = stores.fork ? (): Store => stores.fork?.(run, victim) as Store : undefined;
  const store = new FaultyStore(await stores.reopen(run, victim), undefined, forkInner);
  const transport = new MaliciousTransport(hostTransport(rt.host, accountOf(victim)));
  await openDevice(rt, victim, store, old.secrets, old.provider, transport);
}

function describeError(e: unknown): string {
  return e instanceof KavachError ? `${e.code}@${e.stage}` : e instanceof Error ? e.name : String(e);
}

/** Runs the steps; on the victim's crash restarts it and re-invokes the step, then continues. */
async function drive(sc: Scenario, stores: SweepStores, run: string, victim: DeviceName): Promise<{ crashedDuring: string; retry: string }> {
  let crashedDuring = "";
  let retry = "";
  for (const step of sc.steps) {
    const v = sc.rt.devices.get(victim);
    if (!v) throw new Error("no victim");
    const lossesBefore = v.transport.losses.length;
    let failed: unknown;
    try {
      await step.run();
    } catch (e) {
      failed = e;
    }
    if (!v.store.crashed && v.transport.losses.length > lossesBefore && failed !== undefined) {
      // The app sees a failed operation and retries it; the host already committed the write.
      try {
        await step.run();
        retry = "OK";
      } catch (e) {
        if (!(e instanceof KavachError)) throw e;
        retry = describeError(e);
      }
      continue;
    }
    if (v.store.crashed) {
      if (crashedDuring) throw new Error(`crashed twice (${crashedDuring}, ${step.name})`);
      crashedDuring = step.name;
      await restart(sc.rt, stores, run, victim);
      try {
        await step.run();
        retry = "OK";
      } catch (e) {
        if (!(e instanceof KavachError)) throw e;
        retry = describeError(e);
      }
      continue;
    }
    if (failed !== undefined) throw new Error(`step ${step.name} failed without a crash: ${describeError(failed)}`);
  }
  return { crashedDuring, retry };
}

/** The durable-state outcomes of section 11, checked against the host after quiescence. */
async function checkInvariants(rt: Runtime, label: string): Promise<void> {
  const fail = (what: string): never => {
    throw new Error(`[${label}] ${what}`);
  };
  const d = (n: DeviceName): Device => rt.devices.get(n) ?? fail("no device " + n);
  // Quiescence.
  for (let i = 0; i < 2; i++) {
    rt.clock.advance(1_000n);
    await d("alice").client.sync();
    await d("bob2").client.sync();
  }
  const host = rt.host;
  const alice = host.accounts.get("alice") ?? fail("alice unknown at host");
  const bob = host.accounts.get("bob") ?? fail("bob unknown at host");
  // Activation: exactly one replacement, never a third device, never a reset.
  if (alice.generation !== 1n || alice.deviceIds.size !== 1) fail(`alice generation ${alice.generation} devices ${alice.deviceIds.size}`);
  if (bob.generation !== 2n || bob.deviceIds.size !== 2) fail(`bob generation ${bob.generation} devices ${bob.deviceIds.size}`);
  if (alice.previousIdentities.size || bob.previousIdentities.size) fail("an identity was reset");
  const aliceState = await d("alice").client.getState();
  const bob2State = await d("bob2").client.getState();
  const bobState = await d("bob").client.getState();
  if (aliceState.status !== "ready") fail(`alice is ${aliceState.status}`);
  if (bob2State.status !== "ready") fail(`bob2 is ${bob2State.status}`);
  if (bobState.status !== "retired") fail(`old bob is ${bobState.status}`);
  if (toHex(aliceState.identityId ?? new Uint8Array()) !== alice.identityId) fail("alice identity differs from the host's");
  if (toHex(bob2State.identityId ?? new Uint8Array()) !== bob.identityId) fail("bob2 identity differs from the host's");
  if (toHex(bob2State.certificateHash ?? new Uint8Array()) !== bob.certificateHash) fail("bob2 certificate differs from the host's");
  // Streams: every epoch the host holds is the exact bytes the author saved, and the author's
  // active epoch is the host's current one.
  for (const name of ["alice", "bob2", "bob"] as const) {
    const dev = d(name);
    const inner = dev.store.inner;
    const pin = await inner.read((tx) => tx.get("self", "self")) ?? fail(`${name} has no self row`);
    const s = host.streams.get(pin.streamId) ?? fail(`${name} has no stream at the host`);
    const rows = await inner.read((tx) => tx.list("epochs"));
    const byEpoch = new Map(rows.map(([, r]) => [r.epoch, r]));
    for (const [epoch, e] of s.epochs) {
      const row = byEpoch.get(epoch) ?? fail(`${name}: host epoch ${epoch} has no local row`);
      if (row.manifest !== toHex(e.manifest)) fail(`${name}: epoch ${epoch} bytes differ between host and store`);
    }
    for (const [, r] of rows) {
      if (r.status === "prepared") continue;
      if (r.epoch > s.currentEpoch) fail(`${name}: local epoch ${r.epoch} (${r.status}) above the host's ${s.currentEpoch}`);
    }
    const stream = await inner.read((tx) => tx.get("stream", "stream"));
    if (name !== "bob") {
      if (stream?.activeEpoch !== s.currentEpoch) fail(`${name}: active epoch ${stream?.activeEpoch} but host current ${s.currentEpoch}`);
      const active = rows.filter(([, r]) => r.status === "active");
      if (active.length !== 1) fail(`${name}: ${active.length} active epochs`);
    }
    // Records: every append the host saw is in the author's own history, the same recordId was
    // never asked to accept two different wires, and no counter was reused.
    const own = new Set((await inner.read((tx) => tx.list("history"))).filter(([, h]) => h.own).map(([, h]) => h.recordId));
    const log = host.appendLog.filter((a) => a.streamId === pin.streamId);
    const hashes = new Map<string, string>();
    for (const a of log) {
      if (!own.has(a.recordId)) fail(`${name}: record ${a.recordId.slice(0, 8)} reached the host without a history row`);
      const h = hashes.get(a.recordId);
      if (h && h !== a.hash) fail(`${name}: record ${a.recordId.slice(0, 8)} was sent with two different wires`);
      hashes.set(a.recordId, a.hash);
      if (a.status === "EQUIVOCATION" || a.status === "STALE_APPEND") fail(`${name}: the host answered ${a.status}`);
    }
    const outbox = await inner.read((tx) => tx.list("outbox").map(([, r]) => r.status));
    if (name !== "bob" && outbox.some((st) => st !== "accepted" && st !== "cancelled")) fail(`${name}: outbox left ${outbox.join(",")}`);
    // Cursors: the client never records a cursor the host does not hold.
    const subs = await inner.read((tx) => tx.list("subscriptions"));
    for (const [, sub] of subs) {
      const hs = host.streams.get(sub.streamId);
      const hostSub = hs?.subscriptions.get(toHex(dev.client ? (await dev.client.getState()).certificateHash ?? new Uint8Array() : new Uint8Array()));
      if (hostSub && hostSub.cursor < BigInt(sub.committedCursor)) fail(`${name}: committed cursor ${sub.committedCursor} above the host's ${hostSub.cursor}`);
    }
  }
  // Delivery: bob2 holds alice's newest location; alice has bob's check-ins.
  const aliceId = fromHex(alice.identityId);
  const pin = await d("bob2").client.latest(aliceId);
  const aliceStream = host.streams.get((await d("alice").store.inner.read((tx) => tx.get("self", "self")))?.streamId ?? "");
  const accepted = host.appendLog.filter((a) => a.streamId === (aliceStream ? [...host.streams.entries()].find(([, s]) => s === aliceStream)?.[0] : "") && (a.status === "ACCEPTED" || a.status === "ALREADY_ACCEPTED"));
  const lastLocation = [...accepted].reverse().find((a) => a.epoch === aliceStream?.currentEpoch);
  if (lastLocation && (!pin || toHex(pin.recordId) !== lastLocation.recordId)) fail(`bob2's pin is ${pin ? toHex(pin.recordId).slice(0, 8) : "missing"}, alice's last is ${lastLocation.recordId.slice(0, 8)}`);
  const checkIns = await d("alice").client.history({ authorIdentityId: fromHex(bob.identityId), kind: 1 });
  if (checkIns.length < 2) fail(`alice has ${checkIns.length} check-ins from bob`);
}

async function withRun<R>(stores: SweepStores, run: string, fn: () => Promise<R>): Promise<R> {
  try {
    return await fn();
  } finally {
    await stores.dispose?.(run);
  }
}

/** Runs the scenario with no fault and returns the victim's transaction count. */
export async function countBoundaries(stores: SweepStores, victim: DeviceName): Promise<number> {
  const run = `reference-${victim}`;
  return withRun(stores, run, async () => {
    const rt = await setup(stores, run, { victim });
    const sc = scenario(rt, stores, run);
    const { crashedDuring } = await drive(sc, stores, run, victim);
    if (crashedDuring) throw new Error("the reference run crashed");
    // Counted before the invariant check, whose own syncs are not part of the scenario.
    const boundaries = rt.devices.get(victim)?.store.transactions ?? 0;
    await checkInvariants(rt, "reference");
    return boundaries;
  });
}

export async function crashSweep(options: SweepOptions): Promise<SweepResult> {
  const { stores, victim } = options;
  const phases = options.phases ?? ["beforeCommit", "afterCommit"];
  const boundaries = await countBoundaries(stores, victim);
  const runs: SweepRun[] = [];
  for (let at = 1; at <= boundaries; at++) {
    if (options.only && !options.only.includes(at)) continue;
    for (const phase of phases) {
      const run = `${victim}-${phase}-${at}`;
      await withRun(stores, run, async () => {
        const rt = await setup(stores, run, { victim, crash: { at, phase } });
        const sc = scenario(rt, stores, run);
        const { crashedDuring, retry } = await drive(sc, stores, run, victim);
        if (!crashedDuring) throw new Error(`[${run}] boundary ${at} was never reached`);
        await checkInvariants(rt, `${run} during ${crashedDuring}, retry ${retry}`);
        runs.push({ at, phase, crashedDuring, retry });
      });
    }
  }
  return { boundaries, runs };
}

const MUTATIONS: readonly MutationName[] = ["registerAccount", "activateDevice", "publishVault", "publishOwnedCircle", "requestJoin", "publishEpoch", "appendRecord", "ackThrough"];

/** For each mutation the victim issues, the host commits it and the response is lost once. */
export async function lostResponseSweep(stores: SweepStores, victim: DeviceName): Promise<LostResponseRun[]> {
  const out: LostResponseRun[] = [];
  for (const mutation of MUTATIONS) {
    const run = `${victim}-lost-${mutation}`;
    await withRun(stores, run, async () => {
      const rt = await setup(stores, run, { victim, lose: mutation });
      const sc = scenario(rt, stores, run);
      const { crashedDuring } = await drive(sc, stores, run, victim);
      if (crashedDuring) throw new Error("no crash was planned");
      const v = rt.devices.get(victim);
      await checkInvariants(rt, run);
      out.push({ mutation, exercised: v?.transport.losses.includes(mutation) ?? false });
    });
  }
  return out;
}
