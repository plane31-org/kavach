/** Two clients over the fake host behind a MaliciousTransport, for the attack and regression suites. */
import { expect } from "vitest";
import { toHex } from "../src/bytes.js";
import { open, type Client, type ClientEvent, type SyncReport } from "../src/client.js";
import { buildResetKeyList, type Location } from "../src/codec.js";
import { C, H, signingKeypairFromSeed } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { locationFromDegrees } from "../src/record.js";
import { MemorySecretStore, MemoryStore } from "../src/store.js";
import { TestClock, testPolicy } from "../src/testing/clock.js";
import { FakeHost } from "../src/testing/fakeHost.js";
import { MaliciousTransport } from "../src/testing/faults.js";
import { MemoryPlatformProvider } from "../src/testing/providers.js";
import { hostTransport } from "../src/testing/sweep.js";

export const management = signingKeypairFromSeed(H(C("identity")));
export const operational = signingKeypairFromSeed(H(C("stream")));
export const operationalId = new Uint8Array(16).fill(7);
export const resetTrust = { managementKey: management.publicKey, minimumVersion: 1n };
export const DAY = 86_400_000n;

export interface Dev {
  client: Client;
  store: MemoryStore;
  secrets: MemorySecretStore;
  events: ClientEvent[];
  t: MaliciousTransport;
  provider: MemoryPlatformProvider;
}

export interface World {
  host: FakeHost;
  clock: TestClock;
  device(name: string, provider?: MemoryPlatformProvider, store?: MemoryStore, secrets?: MemorySecretStore): Promise<Dev>;
  loc(lat: number): Location;
  sync(d: Dev): Promise<SyncReport>;
}

export function world(): World {
  const host = new FakeHost();
  const clock = new TestClock();
  host.now = clock.now;
  host.resetSigner = { key: operational, keyId: operationalId };
  host.resetKeyList = buildResetKeyList({ version: 1n, issuedAt: clock.now(), expiresAt: clock.now() + 30n * DAY, keys: [{ keyId: operationalId, publicKey: operational.publicKey }] }, management.secretKey);
  const device = async (name: string, provider = new MemoryPlatformProvider(name + "@platform"), store = new MemoryStore(), secrets = new MemorySecretStore()): Promise<Dev> => {
    const t = new MaliciousTransport(hostTransport(host, name));
    const events: ClientEvent[] = [];
    const client = await open({ accountName: name, retentionPolicy: testPolicy, recoveryProvider: provider, resetTrust, secretStore: secrets, store, transport: t, now: clock.now });
    client.subscribe((e) => events.push(e));
    return { client, store, secrets, events, t, provider };
  };
  const loc = (lat: number) => locationFromDegrees(lat, -122.4194, 5, clock.now());
  const sync = async (d: Dev): Promise<SyncReport> => {
    clock.advance(1_000n);
    return d.client.sync();
  };
  return { host, clock, device, loc, sync };
}

/** The error codes a sync surfaced, through the report and through securityError events. */
export function codes(report: SyncReport, events: ClientEvent[], since = 0): Set<string> {
  const out = new Set<string>(report.errors.map((e) => e.code));
  for (const e of events.slice(since)) if (e.kind === "securityError") out.add(e.code);
  return out;
}

export async function thrown(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "OK";
  } catch (e) {
    return e instanceof KavachError ? e.code : String(e);
  }
}

/** Alice owns a circle with Bob and has delivered one location to him. */
export interface Pair {
  a: Dev;
  b: Dev;
  circleId: Uint8Array;
  aliceId: Uint8Array;
  bobId: Uint8Array;
  bobVault1: Uint8Array;
  snapshot1: Uint8Array;
}

export async function pair(w: World): Promise<Pair> {
  const a = await w.device("alice");
  const b = await w.device("bob");
  await a.client.initializeAccount();
  await b.client.initializeAccount();
  const bobVault1 = w.host.accounts.get("bob")?.vault?.wire ?? new Uint8Array();
  const { circleId } = await a.client.circles.create();
  const snapshot1 = w.host.circles.get(toHex(circleId))?.snapshot ?? new Uint8Array();
  const aliceId = (await a.client.inspect()).identityId ?? new Uint8Array();
  const bobId = (await b.client.inspect()).identityId ?? new Uint8Array();
  await b.client.circles.requestJoin(circleId, aliceId);
  await w.sync(a);
  await a.client.circles.approve(circleId, "bob");
  await w.sync(a);
  await w.sync(b);
  await w.sync(a);
  await a.client.enqueueLocation(w.loc(1));
  await w.sync(a);
  await w.sync(b);
  expect((await b.client.history({ authorIdentityId: aliceId })).length).toBe(1);
  return { a, b, circleId, aliceId, bobId, bobVault1, snapshot1 };
}

/** Make Alice rotate without changing who can read: disable and re-enable the circle. */
export async function rotate(w: World, a: Dev, circleId: Uint8Array): Promise<number> {
  await a.client.circles.setEnabled(circleId, false);
  await a.client.circles.setEnabled(circleId, true);
  await w.sync(a);
  return (await a.client.inspect()).activeEpoch ?? 0;
}

