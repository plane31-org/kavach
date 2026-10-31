/** The one-call setup: per-account databases and secrets, a created storage key, and the lost-key case. */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { toHex, type ProviderLoadResult, type ProviderSaveResult, type ProviderStatusResult, type RecoveryProvider } from "@kavach/core";
import { MemorySecretStore, ready } from "@kavach/core/adapters";
import { FakeHost, TestClock, testPolicy, testResetKeyList, testResetKeys } from "@kavach/core/testing";
import { nodeSqliteDriver, type SqlDriver, type SqlValue } from "../src/sqliteStore.js";
import { databaseFileName, openKavach } from "../src/setup.js";
import type { SecureStoreLike } from "../src/secretStore.js";
import { openNodeDatabase } from "./sqlite.js";

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

/** A SecureStore fake: one map per keychain service, keys as the adapter writes them. */
function fakeSecureStore(): SecureStoreLike & { items: Map<string, string> } {
  const items = new Map<string, string>();
  return {
    items,
    async getItemAsync(key) {
      return items.get(key) ?? null;
    },
    async setItemAsync(key, value) {
      items.set(key, value);
    },
    async deleteItemAsync(key) {
      items.delete(key);
    }
  };
}

/**
 * Node's SQLite ignores `PRAGMA key`; this wrapper behaves like SQLCipher for the one thing the
 * setup relies on: a file created under one key refuses to read under another.
 */
function cipherLike(dir: string, keysByFile: Map<string, string>): (fileName: string) => SqlDriver {
  return (fileName) => {
    const inner = nodeSqliteDriver(openNodeDatabase(join(dir, fileName)));
    let key: string | undefined;
    return {
      exec: (sql) => {
        const m = /^PRAGMA key = "x'([0-9a-f]+)'"$/.exec(sql);
        if (m) {
          key = m[1];
          if (!keysByFile.has(fileName)) keysByFile.set(fileName, key ?? "");
          return;
        }
        inner.exec(sql);
      },
      run: (sql, params) => inner.run(sql, params),
      all: <T>(sql: string, params?: readonly SqlValue[]) => {
        if (keysByFile.get(fileName) !== key) throw new Error("file is not a database");
        return inner.all<T>(sql, params);
      }
    };
  };
}

function world(): { host: FakeHost; clock: TestClock; resetTrust: { managementKey: Uint8Array; minimumVersion: bigint }; transport: (name: string) => ReturnType<FakeHost["asDevice"]> } {
  const host = new FakeHost();
  const clock = new TestClock();
  host.now = clock.now;
  const resetKeys = testResetKeys();
  host.resetSigner = { key: resetKeys.operational, keyId: resetKeys.operationalKeyId };
  host.resetKeyList = testResetKeyList(resetKeys, clock.now());
  const transport = (name: string): ReturnType<FakeHost["asDevice"]> => {
    let bound: ReturnType<FakeHost["asDevice"]> | undefined;
    const bind = (): ReturnType<FakeHost["asDevice"]> => {
      const acct = host.accounts.get(name);
      if (acct) bound = host.asDevice(name, Uint8Array.from(Buffer.from(acct.certificateHash, "hex")));
      return bound ?? host.asDevice(name, new Uint8Array(32));
    };
    return {
      get directory() {
        return bind().directory;
      },
      get relay() {
        return bind().relay;
      }
    };
  };
  return { host, clock, resetTrust: { managementKey: resetKeys.management.publicKey, minimumVersion: 1n }, transport };
}

describe("openKavach", () => {
  it("keeps two accounts on one device in separate databases with separate keys and secrets", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const keys = new Map<string, string>();
    const secure = fakeSecureStore();
    const openAccount = (name: string) =>
      openKavach({
        accountName: name,
        transport: w.transport(name),
        recoveryProvider: new NoProvider(),
        retentionPolicy: testPolicy,
        resetTrust: w.resetTrust,
        secrets: { secureStore: secure, thisDeviceOnly: "device-only" },
        database: cipherLike(dir, keys),
        now: w.clock.now
      });
    const alice = await openAccount("alice");
    const bob = await openAccount("bob");
    expect([alice.databaseFileName, bob.databaseFileName]).toEqual(["kavach-alice.db", "kavach-bob.db"]);
    expect(keys.get("kavach-alice.db")).not.toBe(keys.get("kavach-bob.db"));
    await alice.client.initializeAccount();
    await bob.client.initializeAccount();
    expect(secure.items.get("kavach.alice.storageKey")).toBe(keys.get("kavach-alice.db"));
    expect(secure.items.get("kavach.bob.storageKey")).toBe(keys.get("kavach-bob.db"));
    expect(secure.items.get("kavach.alice.accountSeed")).not.toBe(secure.items.get("kavach.bob.accountSeed"));
    expect((await alice.client.getState()).status).toBe("ready");
    expect((await bob.client.getState()).status).toBe("ready");
    // A second open of the same account finds the same key and the same database.
    const again = await openAccount("alice");
    expect(toHex((await again.secretStore.get("storageKey")) ?? new Uint8Array())).toBe(keys.get("kavach-alice.db"));
    expect((await again.client.getState()).status).toBe("ready");
    expect(toHex((await again.client.inspect()).identityId ?? new Uint8Array())).toBe(toHex((await alice.client.inspect()).identityId ?? new Uint8Array()));
  });

  it("a database whose key is gone is RECOVERY_REQUIRED, and the new key does not open it", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const keys = new Map<string, string>();
    const setup = (secrets: MemorySecretStore) =>
      openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets, database: cipherLike(dir, keys), now: w.clock.now });
    const first = await setup(new MemorySecretStore());
    await first.client.initializeAccount();
    const lost = new MemorySecretStore();
    await expect(setup(lost)).rejects.toThrow(expect.objectContaining({ code: "RECOVERY_REQUIRED" }));
    // The key created for the attempt is stored, so a fresh database after the app deletes the file opens under it.
    expect(await lost.get("storageKey")).toBeDefined();
  });

  it("names and validates", () => {
    expect(databaseFileName("alice")).toBe("kavach-alice.db");
    expect(databaseFileName("alice", "moyo")).toBe("moyo-alice.db");
    expect(() => databaseFileName("../etc")).toThrow(expect.objectContaining({ code: "MALFORMED" }));
  });
});
