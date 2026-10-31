/** Devices as clients of the real Worker, through SELF.fetch. */
import { SELF, env } from "cloudflare:test";
import { MemorySecretStore, MemoryStore, open, toHex, type Client, type ClientEvent, type ProviderLoadResult, type ProviderSaveResult, type ProviderStatusResult, type RecoveryProvider } from "@kavach/core";
import { TestClock, testPolicy } from "@kavach/core/testing";
import { httpTransport } from "../client/httpTransport.js";

export class Platform implements RecoveryProvider {
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

export interface Device {
  client: Client;
  store: MemoryStore;
  events: ClientEvent[];
  provider: Platform;
  /** The device's own bearer for raw calls to the host. */
  bearer(): string;
}

export const clock = new TestClock();
export const fetchHost = (input: string, init?: RequestInit): Promise<Response> => SELF.fetch(input, init);

export async function device(name: string, provider = new Platform()): Promise<Device> {
  const store = new MemoryStore();
  const secrets = new MemorySecretStore();
  const events: ClientEvent[] = [];
  let certHash: Uint8Array | undefined;
  const transport = httpTransport({
    baseUrl: "https://host",
    fetch: fetchHost,
    caller: () => (certHash ? { accountName: name, certificateHash: certHash } : undefined),
    now: clock.now
  });
  const client = await open({
    accountName: name,
    retentionPolicy: testPolicy,
    recoveryProvider: provider,
    resetTrust: { managementKey: Uint8Array.from(Buffer.from(env.TEST_MANAGEMENT_PUBLIC, "hex")), minimumVersion: 1n },
    secretStore: secrets,
    store,
    transport,
    now: clock.now
  });
  client.subscribe((e) => {
    events.push(e);
    if (e.kind === "stateChanged") certHash = e.state.certificateHash;
  });
  certHash = (await client.getState()).certificateHash;
  return {
    client,
    store,
    events,
    provider,
    bearer: () => `Bearer ${name}:${toHex(certHash ?? new Uint8Array(32))}`
  };
}

export async function hostJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await SELF.fetch("https://host" + path, { ...init, headers: { "content-type": "application/json", "x-test-now": clock.now().toString(), ...(init?.headers ?? {}) } });
  return (await res.json()) as T;
}

export async function circleOfTwo(): Promise<{ a: Device; b: Device; circleId: Uint8Array; aliceId: Uint8Array; bobId: Uint8Array }> {
  const a = await device("alice");
  const b = await device("bob");
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
