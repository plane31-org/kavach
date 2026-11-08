/** The one-call setup: per-account databases and secrets, a created storage key, and the lost-key case. */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { toHex, type ProviderLoadResult, type ProviderSaveResult, type ProviderStatusResult, type RecoveryProvider } from "@plane31/blind-relay";
import { MemorySecretStore, backendName, nobleBackend, ready, type SodiumLike } from "@plane31/blind-relay/adapters";
import { setCryptoBackend } from "@plane31/blind-relay";
import { createRequire } from "node:module";
import { FakeHost, TestClock, testPolicy, testResetKeyList, testResetKeys } from "@plane31/blind-relay/testing";
import { nodeSqliteDriver, type SqlDriver, type SqlValue } from "../src/sqliteStore.js";
import { databaseFileName, installNativeCrypto, installWebCrypto, openKavach } from "../src/setup.js";
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
      close: () => inner.close?.(),
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
  it("runs the cipher suite on an injected libsodium when given one, and both backends read each other's bytes", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const keys = new Map<string, string>();
    // Through its CommonJS build, as the core's Node entry does (the ESM build has shipped broken).
    type Lib = typeof import("libsodium-wrappers-sumo");
    const mod = createRequire(import.meta.url)("libsodium-wrappers-sumo") as { default?: Lib } & Lib;
    const sodium: SodiumLike & { ready: Promise<void> } = mod.default ?? mod; // assignable without a cast
    // Installed by the app itself, as a hand-wired app does: the open without `crypto` still reports what the process runs on.
    await installNativeCrypto(sodium);
    const secrets = new MemorySecretStore(); // one secret store: the same account is reopened below
    const alice = await openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets, database: cipherLike(dir, keys), context: "foreground", now: w.clock.now });
    expect(backendName()).toBe("sodium");
    expect(alice.cryptoBackend.kind).toBe("native");
    if (alice.cryptoBackend.kind === "native") expect(alice.cryptoBackend.report?.native).toContain("signDetached");
    await alice.close();
    const alice2 = await openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets, database: cipherLike(dir, keys), context: "foreground", now: w.clock.now, crypto: sodium });
    expect(alice2.cryptoBackend.kind).toBe("native");
    await alice2.close();
    setCryptoBackend(nobleBackend);
    const alice3 = await openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets, database: cipherLike(dir, keys), context: "foreground", now: w.clock.now, crypto: sodium });
    expect(backendName()).toBe("sodium");
    await alice3.client.initializeAccount();
    const { circleId } = await alice3.client.circles.create();
    expect(circleId.length).toBe(16);
    expect((await alice3.client.sync()).errors).toEqual([]);
    await alice3.close();
    setCryptoBackend(nobleBackend); // the rest of the suite runs on the portable backend
    expect(backendName()).toBe("noble");
  });

  it("opens on the portable backend when the binding cannot be used, naming the reason, and refuses only when asked", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const keys = new Map<string, string>();
    type Lib = typeof import("libsodium-wrappers-sumo");
    const mod = createRequire(import.meta.url)("libsodium-wrappers-sumo") as { default?: Lib } & Lib;
    const lib = mod.default ?? mod;
    // A binding whose native side never installed: its JSI functions are absent.
    const uninstalled = { ...lib, crypto_sign_detached: undefined } as unknown as SodiumLike;
    const common = { transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, database: cipherLike(dir, keys), context: "foreground" as const, now: w.clock.now };
    const alice = await openKavach({ ...common, accountName: "alice", secrets: new MemorySecretStore(), crypto: uninstalled });
    expect(alice.cryptoBackend).toEqual({ kind: "portable", reason: expect.stringMatching(/signDetached is missing/) });
    expect(backendName()).toBe("noble");
    await alice.client.initializeAccount();
    expect((await alice.client.sync()).errors).toEqual([]);
    await alice.close();
    // A binding that disagrees is named as such; `refuse` makes it fatal.
    const wrong = { ...lib, crypto_sign_detached: (m: Uint8Array, sk: Uint8Array) => lib.crypto_sign_detached(m, sk).map((b) => b ^ 1) } as unknown as SodiumLike;
    const bob = await openKavach({ ...common, accountName: "bob", transport: w.transport("bob"), secrets: new MemorySecretStore(), crypto: wrong });
    expect(bob.cryptoBackend).toEqual({ kind: "portable", reason: expect.stringMatching(/signDetached disagrees/) });
    await bob.close();
    await expect(openKavach({ ...common, accountName: "carol", transport: w.transport("carol"), secrets: new MemorySecretStore(), crypto: wrong, cryptoFallback: "refuse" })).rejects.toMatchObject({ code: "INVALID_KEY" });
    // A rejected `ready` is a refused binding too.
    const broken = Object.assign({ ...lib }, { ready: Promise.reject(new Error("no native module")) }) as unknown as SodiumLike & { ready: Promise<void> };
    const dave = await openKavach({ ...common, accountName: "dave", transport: w.transport("dave"), secrets: new MemorySecretStore(), crypto: broken });
    expect(dave.cryptoBackend).toEqual({ kind: "portable", reason: "no native module" });
    await dave.close();
    // Without a binding, portable and no reason.
    const erin = await openKavach({ ...common, accountName: "erin", transport: w.transport("erin"), secrets: new MemorySecretStore() });
    expect(erin.cryptoBackend).toEqual({ kind: "portable" });
    await erin.close();
  });

  it("takes no recovery provider on a recovery-only profile, and requires one where identity continuity is enabled", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const keys = new Map<string, string>();
    const recoveryOnly = { ...testPolicy, replacement: "recovery" as const };
    const alice = await openKavach({ accountName: "alice", transport: w.transport("alice"), retentionPolicy: recoveryOnly, resetTrust: w.resetTrust, secrets: new MemorySecretStore(), database: cipherLike(dir, keys), context: "foreground", now: w.clock.now });
    await alice.client.initializeAccount();
    expect((await alice.client.recoveryStatus()).status).toBe("unsupported");
    expect(w.host.accounts.get("alice")?.vault).toBeUndefined();
    await alice.client.close();
    await expect(openKavach({ accountName: "bob", transport: w.transport("bob"), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets: new MemorySecretStore(), database: cipherLike(dir, keys), context: "foreground", now: w.clock.now })).rejects.toMatchObject({ code: "MALFORMED" });
  });

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
        context: "foreground",
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
    const setup = (secrets: MemorySecretStore, context: "foreground" | "background" = "foreground") =>
      openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets, database: cipherLike(dir, keys), context, now: w.clock.now });
    const first = await setup(new MemorySecretStore());
    await first.client.initializeAccount();
    const lost = new MemorySecretStore();
    await expect(setup(lost)).rejects.toThrow(expect.objectContaining({ code: "RECOVERY_REQUIRED" }));
    // The key created for the attempt is stored, so a fresh database after the app deletes the file opens under it.
    expect(await lost.get("storageKey")).toBeDefined();
  });

  it("two first-time opens of one account in one context share one key", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const keys = new Map<string, string>();
    const secrets = new MemorySecretStore();
    const setup = () =>
      openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets, database: cipherLike(dir, keys), context: "foreground", now: w.clock.now });
    const [a, b] = await Promise.all([setup(), setup()]);
    const stored = toHex((await secrets.get("storageKey")) ?? new Uint8Array());
    expect(stored).toBe(keys.get("kavach-alice.db"));
    expect((await a.client.getState()).status).toBe("fresh");
    expect((await b.client.getState()).status).toBe("fresh");
  });

  it("a background context never provisions: without a key it stops with LOCKED and creates nothing", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const keys = new Map<string, string>();
    const secrets = new MemorySecretStore();
    const setup = (context: "foreground" | "background") =>
      openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets, database: cipherLike(dir, keys), context, now: w.clock.now });
    await expect(setup("background")).rejects.toThrow(expect.objectContaining({ code: "LOCKED" }));
    expect(await secrets.get("storageKey")).toBeUndefined();
    expect(keys.size).toBe(0);
    // Once the foreground has provisioned, the background opens under the same key.
    await setup("foreground");
    const bg = await setup("background");
    expect(toHex((await bg.secretStore.get("storageKey")) ?? new Uint8Array())).toBe(keys.get("kavach-alice.db"));
  });

  it("a failed key write rejects the open once, with no stray unhandled rejection, and the next open provisions again", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const keys = new Map<string, string>();
    const secrets = new MemorySecretStore();
    const setup = () =>
      openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets, database: cipherLike(dir, keys), context: "foreground", now: w.clock.now });
    const stray: unknown[] = [];
    const onStray = (reason: unknown): void => {
      stray.push(reason);
    };
    process.on("unhandledRejection", onStray);
    try {
      secrets.failNextWrite = true;
      await expect(setup()).rejects.toThrow(expect.objectContaining({ code: "STORAGE_FAILURE" }));
      await new Promise((resolve) => setImmediate(resolve));
      expect(stray).toEqual([]);
      const second = await setup();
      expect((await second.client.getState()).status).toBe("fresh");
      expect(await secrets.get("storageKey")).toBeDefined();
    } finally {
      process.off("unhandledRejection", onStray);
    }
  });

  it("forwards onListenerError to the client", async () => {
    const w = world();
    const dir = mkdtempSync(join(tmpdir(), "kavach-setup-"));
    const seen: string[] = [];
    const s = await openKavach({ accountName: "alice", transport: w.transport("alice"), recoveryProvider: new NoProvider(), retentionPolicy: testPolicy, resetTrust: w.resetTrust, secrets: new MemorySecretStore(), database: cipherLike(dir, new Map()), context: "foreground", now: w.clock.now, onListenerError: (e, ev) => seen.push(`${ev.kind}:${e instanceof Error ? e.message : String(e)}`) });
    s.client.subscribe((e) => {
      if (e.kind === "stateChanged") throw new Error("boom");
    });
    await s.client.initializeAccount();
    expect(seen).toContain("stateChanged:boom");
  });

  it("names and validates", () => {
    expect(databaseFileName("alice")).toBe("kavach-alice.db");
    expect(databaseFileName("alice", "acme")).toBe("acme-alice.db");
    expect(() => databaseFileName("../etc")).toThrow(expect.objectContaining({ code: "MALFORMED" }));
  });

  it("installs a random source on a runtime without Web Crypto, keeps an existing one, and refuses to open with neither", () => {
    const mine = <T extends ArrayBufferView>(a: T): T => a;
    const bare: { crypto?: { getRandomValues?: unknown } } = {};
    installWebCrypto(mine, bare);
    expect(bare.crypto?.getRandomValues).toBe(mine);
    const theirs = <T extends ArrayBufferView>(a: T): T => a;
    const has = { crypto: { getRandomValues: theirs } };
    installWebCrypto(mine, has);
    expect(has.crypto.getRandomValues).toBe(theirs);
    const partial: { crypto?: { getRandomValues?: unknown } } = { crypto: {} };
    installWebCrypto(mine, partial);
    expect(partial.crypto?.getRandomValues).toBe(mine);
    expect(() => installWebCrypto(undefined, {})).toThrow(expect.objectContaining({ code: "INVALID_KEY" }));
  });
});
