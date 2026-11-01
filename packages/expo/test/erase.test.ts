/** `eraseKavach`: one account's secrets and database go, nothing else; idempotent, and finished by a second run after an interruption. */
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { MemorySecretStore, SECRET_NAMES, ready } from "@plane31/blind-relay/adapters";
import { FakeHost, TestClock, testPolicy, testResetKeyList, testResetKeys } from "@plane31/blind-relay/testing";
import { nodeSqliteDriver, type SqlDriver } from "../src/sqliteStore.js";
import { databaseFileName, eraseKavach, openKavach } from "../src/setup.js";
import { openNodeDatabase } from "./sqlite.js";

beforeAll(() => ready());

function world() {
  const host = new FakeHost();
  const clock = new TestClock();
  host.now = clock.now;
  const resetKeys = testResetKeys();
  host.resetSigner = { key: resetKeys.operational, keyId: resetKeys.operationalId };
  host.resetKeyList = testResetKeyList(resetKeys, clock.now());
  const transport = (name: string) => ({
    get directory() {
      const a = host.accounts.get(name);
      return host.asDevice(name, a ? Uint8Array.from(Buffer.from(a.certificateHash, "hex")) : new Uint8Array(32)).directory;
    },
    get relay() {
      const a = host.accounts.get(name);
      return host.asDevice(name, a ? Uint8Array.from(Buffer.from(a.certificateHash, "hex")) : new Uint8Array(32)).relay;
    }
  });
  return { host, clock, resetTrust: { managementKey: resetKeys.management.publicKey, minimumVersion: 1n }, transport };
}

const files = (dir: string) => (fileName: string) => nodeSqliteDriver(openNodeDatabase(join(dir, fileName)));
const deleteFiles = (dir: string) => (fileName: string) => {
  for (const suffix of ["", "-wal", "-shm"]) rmSync(join(dir, fileName + suffix), { force: true });
};

describe("eraseKavach", () => {
  it("erases one account's secrets and database, leaves the other account, and is idempotent", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-erase-"));
    const secretsAlice = new MemorySecretStore();
    const secretsBob = new MemorySecretStore();
    const open = (name: string, secrets: MemorySecretStore) => openKavach({ accountName: name, transport: w.transport(name), retentionPolicy: { ...testPolicy, replacement: "recovery" }, resetTrust: w.resetTrust, secrets, database: files(dir), context: "foreground", now: w.clock.now });
    const alice = await open("alice", secretsAlice);
    const bob = await open("bob", secretsBob);
    await alice.client.initializeAccount();
    await bob.client.initializeAccount();
    await alice.close();
    await alice.close(); // idempotent
    await expect(alice.store.read(() => 1)).rejects.toMatchObject({ code: "CLOSED" });
    await eraseKavach({ accountName: "alice", secrets: secretsAlice, database: files(dir), deleteDatabase: deleteFiles(dir) });
    for (const name of SECRET_NAMES) expect(await secretsAlice.get(name)).toBeUndefined();
    expect(existsSync(join(dir, databaseFileName("alice")))).toBe(false);
    expect(existsSync(join(dir, databaseFileName("bob")))).toBe(true);
    expect(await secretsBob.get("accountSeed")).toBeDefined();
    expect((await bob.client.getState()).status).toBe("ready");
    await eraseKavach({ accountName: "alice", secrets: secretsAlice, database: files(dir), deleteDatabase: deleteFiles(dir) }); // nothing left: fine
    const again = await open("alice", secretsAlice);
    expect((await again.client.getState()).status).toBe("fresh");
    await again.close();
    await bob.close();
  });

  it("an erasure interrupted after the secrets leaves a store that refuses to open; running it again finishes", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-erase-"));
    const secrets = new MemorySecretStore();
    const open = () => openKavach({ accountName: "alice", transport: w.transport("alice"), retentionPolicy: { ...testPolicy, replacement: "recovery" }, resetTrust: w.resetTrust, secrets, database: files(dir), context: "foreground", now: w.clock.now });
    const first = await open();
    await first.client.initializeAccount();
    await first.close();
    // The interruption: secrets gone, the database file still there.
    for (const name of SECRET_NAMES) await secrets.delete(name);
    expect(existsSync(join(dir, databaseFileName("alice")))).toBe(true);
    await expect(open()).rejects.toMatchObject({ code: "RECOVERY_REQUIRED" });
    await eraseKavach({ accountName: "alice", secrets, database: files(dir), deleteDatabase: deleteFiles(dir) });
    const fresh = await open();
    expect((await fresh.client.getState()).status).toBe("fresh");
    await fresh.close();
  });

  it("refuses to erase when it has no way to delete the database, before touching any secret", async () => {
    const secrets = new MemorySecretStore();
    await secrets.set("accountSeed", new Uint8Array(32));
    await expect(eraseKavach({ accountName: "alice", secrets, database: () => ({ exec() {}, run() {}, all: () => [] }) as SqlDriver })).rejects.toMatchObject({ code: "MALFORMED" });
    expect(await secrets.get("accountSeed")).toBeDefined();
  });

  it("reports a deletion that failed for any reason but a missing file, and a second run finishes", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-erase-"));
    const secrets = new MemorySecretStore();
    const open = () => openKavach({ accountName: "alice", transport: w.transport("alice"), retentionPolicy: { ...testPolicy, replacement: "recovery" }, resetTrust: w.resetTrust, secrets, database: files(dir), context: "foreground", now: w.clock.now });
    const s = await open();
    await s.client.initializeAccount();
    await s.close();
    const denied = () => {
      throw Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    };
    await expect(eraseKavach({ accountName: "alice", secrets, database: files(dir), deleteDatabase: denied })).rejects.toMatchObject({ code: "STORAGE_FAILURE" });
    expect(existsSync(join(dir, databaseFileName("alice")))).toBe(true);
    const gone = () => {
      throw Object.assign(new Error("ENOENT: no such file or directory"), { code: "ENOENT" });
    };
    await expect(eraseKavach({ accountName: "bob", secrets: new MemorySecretStore(), database: files(dir), deleteDatabase: gone })).resolves.toBeUndefined();
    await eraseKavach({ accountName: "alice", secrets, database: files(dir), deleteDatabase: deleteFiles(dir) });
    expect(existsSync(join(dir, databaseFileName("alice")))).toBe(false);
    const fresh = await open();
    expect((await fresh.client.getState()).status).toBe("fresh");
    await fresh.close();
  });
});
