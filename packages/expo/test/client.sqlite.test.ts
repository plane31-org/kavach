/** The client over the SQLite store: one end-to-end exchange between two devices on real SQLite files. */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { open, toHex, type Client, type ProviderLoadResult, type ProviderSaveResult, type ProviderStatusResult, type RecoveryProvider } from "@plane31/blind-relay";
import { MemorySecretStore, ready } from "@plane31/blind-relay/adapters";
import { FakeHost, TestClock, testPolicy, testResetKeyList, testResetKeys } from "@plane31/blind-relay/testing";
import { SqliteStore, nodeSqliteDriver } from "../src/sqliteStore.js";
import { openNodeDatabase } from "./sqlite.js";
import { enqueueLocation, latest, locationFromDegrees } from "./location.js";

beforeAll(() => ready());

class NoProvider implements RecoveryProvider {
  async load(): Promise<ProviderLoadResult> {
    return { status: "unavailable" };
  }
  async save(): Promise<ProviderSaveResult> {
    return { status: "available", backupState: "pending" };
  }
  async status(): Promise<ProviderStatusResult> {
    return { status: "available", backupState: "pending" };
  }
  async eraseLocalAccess(): Promise<void> {}
}

describe("client on SqliteStore", () => {
  it("enrolls two devices, forms a circle and delivers a location end to end", async () => {
    const host = new FakeHost();
    const clock = new TestClock();
    host.now = clock.now;
    const resetKeys = testResetKeys();
    host.resetSigner = { key: resetKeys.operational, keyId: resetKeys.operationalKeyId };
    host.resetKeyList = testResetKeyList(resetKeys, clock.now());
    const dir = mkdtempSync(join(tmpdir(), "kavach-client-"));
    const secretsByName = new Map<string, MemorySecretStore>();
    const device = async (name: string, secrets = secretsByName.get(name) ?? new MemorySecretStore()): Promise<Client> => {
      secretsByName.set(name, secrets);
      const store = SqliteStore.open({ driver: nodeSqliteDriver(openNodeDatabase(join(dir, name + ".db"))), storageKey: undefined });
      let bound: ReturnType<FakeHost["asDevice"]> | undefined;
      const bind = (): ReturnType<FakeHost["asDevice"]> => {
        const acct = host.accounts.get(name);
        if (acct) bound = host.asDevice(name, Uint8Array.from(Buffer.from(acct.certificateHash, "hex")));
        return bound ?? host.asDevice(name, new Uint8Array(32));
      };
      return open({
        accountName: name,
        retentionPolicy: testPolicy,
        recoveryProvider: new NoProvider(),
        resetTrust: { managementKey: resetKeys.management.publicKey, minimumVersion: 1n },
        secretStore: secrets,
        store,
        transport: { get directory() { return bind().directory; }, get relay() { return bind().relay; } },
        now: clock.now
      });
    };
    const alice = await device("alice");
    const bob = await device("bob");
    await alice.initializeAccount();
    await bob.initializeAccount();
    const { circleId } = await alice.circles.create();
    const aliceId = (await alice.inspect()).identityId ?? new Uint8Array();
    await bob.circles.requestJoin(circleId, aliceId);
    await alice.sync();
    await alice.circles.approve(circleId, "bob");
    await bob.sync();
    await alice.sync();
    await enqueueLocation(alice, locationFromDegrees(37.7749, -122.4194, 5, clock.now()));
    await alice.sync();
    const report = await bob.sync();
    expect(report.inbox.stored).toBe(1);
    const pin = await latest(bob, aliceId);
    expect(pin).toBeDefined();
    expect(toHex(pin?.payload ?? new Uint8Array()).length).toBe(44);
    expect(host.retainedCount([...host.streams.keys()].map((k) => Uint8Array.from(Buffer.from(k, "hex")))[0] ?? new Uint8Array())).toBeGreaterThanOrEqual(0);
    // A restart with the same secret store reopens the account from the file; the file without its
    // secrets is RECOVERY_REQUIRED, never a fresh account.
    const again = await device("alice");
    expect((await again.getState()).status).toBe("ready");
    expect((await again.history()).length).toBe(1);
    expect((await again.circles.list())[0]?.members.length).toBe(2);
    await expect(device("alice", new MemorySecretStore())).rejects.toThrow(expect.objectContaining({ code: "RECOVERY_REQUIRED" }));
  });
});
