import { beforeAll, describe, expect, it } from "vitest";
import { MemorySecretStore, randomBytes, ready, toHex } from "@plane31/blind-relay/adapters";
import { ExpoSecretStore, type SecureStoreLike, type SecureStoreOptions } from "../src/secretStore.js";
import { BlockStoreRecoveryProvider, blockStoreKey, decodeBlockStoreValue, encodeBlockStoreValue, type BlockStoreLike } from "../src/recovery/android.js";
import { AppleKeychainRecoveryProvider, keychainAccount, type SyncedKeychainLike } from "../src/recovery/apple.js";
import { TrustedClock, highWaterInSecretStore } from "../src/clock.js";

beforeAll(() => ready());

describe("ExpoSecretStore", () => {
  it("stores hex values device-only without an authentication prompt", async () => {
    const calls: { op: string; key: string; options?: SecureStoreOptions }[] = [];
    const items = new Map<string, string>();
    const fake: SecureStoreLike = {
      async getItemAsync(key, options) {
        calls.push({ op: "get", key, ...(options ? { options } : {}) });
        return items.get(key) ?? null;
      },
      async setItemAsync(key, value, options) {
        calls.push({ op: "set", key, ...(options ? { options } : {}) });
        items.set(key, value);
      },
      async deleteItemAsync(key, options) {
        calls.push({ op: "delete", key, ...(options ? { options } : {}) });
        items.delete(key);
      }
    };
    const THIS_DEVICE_ONLY = Symbol("WHEN_UNLOCKED_THIS_DEVICE_ONLY");
    const store = new ExpoSecretStore(fake, { thisDeviceOnly: THIS_DEVICE_ONLY, keychainService: "com.example.app" });
    const seed = randomBytes(32);
    await store.set("accountSeed", seed);
    expect(items.get("kavach.accountSeed")).toBe(toHex(seed));
    expect(toHex((await store.get("accountSeed")) ?? new Uint8Array())).toBe(toHex(seed));
    expect(await store.get("deviceSeed")).toBeUndefined();
    await store.delete("accountSeed");
    expect(await store.get("accountSeed")).toBeUndefined();
    for (const c of calls) {
      expect(c.options?.keychainAccessible).toBe(THIS_DEVICE_ONLY);
      expect(c.options?.requireAuthentication).toBe(false);
      expect(c.options?.keychainService).toBe("com.example.app");
    }
  });
});

describe("BlockStoreRecoveryProvider", () => {
  const iid = randomBytes(32);
  const key = randomBytes(32);
  function fake(e2e: boolean | Error): BlockStoreLike & { entries: Map<string, { bytes: Uint8Array; cloud: boolean }> } {
    const entries = new Map<string, { bytes: Uint8Array; cloud: boolean }>();
    return {
      entries,
      async isEndToEndEncryptionAvailable() {
        if (e2e instanceof Error) throw e2e;
        return e2e;
      },
      async store(k, bytes, cloud) {
        entries.set(k, { bytes, cloud });
      },
      async retrieve(k) {
        return entries.get(k)?.bytes ?? null;
      },
      async delete(k) {
        entries.delete(k);
      }
    };
  }

  it("encodes the entry as the profile says and binds it to the account on load", async () => {
    const value = encodeBlockStoreValue("alice", iid, key);
    expect(value.length).toBe(1 + 1 + 5 + 32 + 32);
    expect(value[0]).toBe(1);
    expect(decodeBlockStoreValue(value)?.accountName).toBe("alice");
    expect(blockStoreKey(iid)).toBe("kavach.recovery." + toHex(iid));
    const bs = fake(true);
    const p = new BlockStoreRecoveryProvider(bs);
    expect(await p.save("alice", iid, key)).toEqual({ status: "available", backupState: "pending" });
    expect(bs.entries.get(blockStoreKey(iid))?.cloud).toBe(true);
    const loaded = await p.load("alice", iid);
    expect(loaded.status).toBe("available");
    expect(toHex(loaded.recoveryKey ?? new Uint8Array())).toBe(toHex(key));
    // Wrong product account for the same entry: unavailable, never a key.
    expect((await p.load("bob", iid)).status).toBe("unavailable");
    expect((await p.status()).backupState).toBe("pending");
  });

  it("never stores without end-to-end encryption and never downgrades an existing cloud copy", async () => {
    const bs = fake(false);
    bs.entries.set(blockStoreKey(iid), { bytes: encodeBlockStoreValue("alice", iid, key), cloud: true });
    const p = new BlockStoreRecoveryProvider(bs);
    const r = await p.save("alice", iid, randomBytes(32));
    expect(r.status).toBe("unavailable");
    expect(r.backupState).toBe("unavailable");
    expect(r.reason).toContain("end-to-end");
    expect(bs.entries.get(blockStoreKey(iid))?.cloud).toBe(true);
    expect(toHex(decodeBlockStoreValue(bs.entries.get(blockStoreKey(iid))?.bytes ?? new Uint8Array())?.recoveryKey ?? new Uint8Array())).toBe(toHex(key));
  });

  it("reports the five statuses", async () => {
    expect((await new BlockStoreRecoveryProvider(undefined).save("alice", iid, key)).status).toBe("unsupported");
    expect((await new BlockStoreRecoveryProvider(undefined).load("alice", iid)).status).toBe("unsupported");
    const err = new Error("ApiException");
    err.name = "ApiException";
    const failing = new BlockStoreRecoveryProvider(fake(err));
    expect(await failing.save("alice", iid, key)).toEqual({ status: "error", reason: "ApiException", backupState: "unavailable" });
    expect((await new BlockStoreRecoveryProvider(fake(true)).load("alice", iid)).status).toBe("unavailable");
    const ok = new BlockStoreRecoveryProvider(fake(true));
    expect((await ok.save("alice", iid, key)).status).toBe("available");
    await ok.eraseLocalAccess();
    expect((await ok.load("alice", iid)).status).toBe("available"); // the shared entry survives
  });
});

describe("AppleKeychainRecoveryProvider", () => {
  const iid = randomBytes(32);
  const key = randomBytes(32);
  function fake(failWith?: number, sync?: boolean): SyncedKeychainLike & { items: Map<string, string> } {
    const items = new Map<string, string>();
    return {
      items,
      async get(service, account) {
        if (failWith) throw Object.assign(new Error("sec"), { code: failWith });
        return items.get(service + "/" + account) ?? null;
      },
      async set(service, account, value) {
        if (failWith) throw Object.assign(new Error("sec"), { code: failWith });
        items.set(service + "/" + account, value);
      },
      async isSyncEnabled() {
        return sync;
      }
    };
  }

  it("saves and loads under the service and account, and keeps the item on erase", async () => {
    const kc = fake(undefined, true);
    const p = new AppleKeychainRecoveryProvider(kc);
    expect(await p.save("alice", iid, key)).toEqual({ status: "available", backupState: "pending" });
    expect(kc.items.has("kavach.recovery/" + keychainAccount("alice", iid))).toBe(true);
    expect(toHex((await p.load("alice", iid)).recoveryKey ?? new Uint8Array())).toBe(toHex(key));
    await p.eraseLocalAccess();
    expect(kc.items.size).toBe(1);
    expect((await p.load("bob", iid)).status).toBe("unavailable");
  });

  it("reports locked, unsupported, error and iCloud Keychain off", async () => {
    expect((await new AppleKeychainRecoveryProvider(fake(-25308)).load("alice", iid)).status).toBe("locked");
    expect((await new AppleKeychainRecoveryProvider(fake(-34018)).save("alice", iid, key)).status).toBe("unsupported");
    expect((await new AppleKeychainRecoveryProvider(fake(1)).load("alice", iid)).status).toBe("error");
    expect((await new AppleKeychainRecoveryProvider(undefined).status()).status).toBe("unsupported");
    const off = new AppleKeychainRecoveryProvider(fake(undefined, false));
    expect((await off.save("alice", iid, key)).backupState).toBe("unavailable");
    expect((await off.status()).reason).toContain("iCloud Keychain");
  });
});

describe("TrustedClock", () => {
  it("advances the durable high-water mark and distrusts a rollback or a jump", async () => {
    const secrets = new MemorySecretStore();
    let wall = 1_700_000_000_000n;
    let mono = 0;
    const storage = highWaterInSecretStore(secrets as never);
    const clock = new TrustedClock(storage, () => wall, () => mono);
    await clock.load();
    expect(await clock.trustedNow()).toBe(wall);
    wall += 1000n;
    mono += 1000;
    expect(await clock.trustedNow()).toBe(wall);
    expect(await storage.get()).toBe(wall);
    // Rollback below the high-water mark.
    wall -= 5000n;
    mono += 10;
    expect(await clock.trustedNow()).toBeUndefined();
    // A forward jump the monotonic clock does not confirm.
    wall += 5000n + 3_600_000n;
    expect(await clock.trustedNow()).toBeUndefined();
    // A restart reloads the mark from the secret store.
    const later = new TrustedClock(storage, () => 1_700_000_000_500n, () => 0);
    await later.load();
    expect(await later.trustedNow()).toBeUndefined();
  });
});
