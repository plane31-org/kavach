import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { accountKeypair, ready } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import {
  buildVault,
  decodeRecoveryCode,
  encodeRecoveryCode,
  newRecoveryKey,
  openVault,
  recoverAccount,
  removeEntry,
  upsertEntry,
  type ProviderLoadResult,
  type ProviderSaveResult,
  type ProviderStatus,
  type ProviderStatusResult,
  type RecoveryProvider
} from "../src/vault.js";
import { fixture, hex, str } from "./fixture.js";

beforeAll(() => ready());

interface RV {
  recovery_vault: { recovery_code: string; empty_vault: string; sharing_disabled_vault: string; recovery_key: string; wire: string };
}
const rv = (fixture as unknown as RV).recovery_vault;
const alice = fixture.identities[0];
if (!alice) throw new Error("fixture");

/** An in-memory provider with a settable status, standing in for Keychain or Block Store. */
class MemoryProvider implements RecoveryProvider {
  status_: ProviderStatus = "available";
  backup: "unknown" | "pending" | "unavailable" = "pending";
  items = new Map<string, Uint8Array>();
  loads = 0;
  async load(accountName: string, identityId: Uint8Array): Promise<ProviderLoadResult> {
    this.loads++;
    if (this.status_ !== "available") return { status: this.status_, reason: "test" };
    const key = this.items.get(accountName + ":" + toHex(identityId));
    return key ? { status: "available", recoveryKey: key } : { status: "unavailable", reason: "no item" };
  }
  async save(accountName: string, identityId: Uint8Array, recoveryKey: Uint8Array): Promise<ProviderSaveResult> {
    if (this.status_ !== "available") return { status: this.status_, reason: "test", backupState: "unavailable" };
    this.items.set(accountName + ":" + toHex(identityId), recoveryKey);
    return { status: "available", backupState: this.backup };
  }
  async status(): Promise<ProviderStatusResult> {
    return { status: this.status_, backupState: this.backup };
  }
  async eraseLocalAccess(): Promise<void> {
    /* the shared item survives */
  }
}

async function outcome(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "OK";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

describe("vault", () => {
  const rk = hex(rv.recovery_key);
  const ak = accountKeypair(hex(str(fixture.inputs["alice_account_seed"] ?? ""))).publicKey;

  it("opens the fixture with the right key and fails with the wrong key", () => {
    const v = openVault(hex(rv.wire), rk, "alice", ak);
    expect(toHex(v.accountSeed)).toBe(str(fixture.inputs["alice_account_seed"] ?? ""));
    expect(Object.keys(v)).not.toContain("epochKey");
    expect(() => openVault(hex(rv.wire), newRecoveryKey(), "alice", ak)).toThrow(expect.objectContaining({ code: "DECRYPT_FAILED" }));
  });

  it("holds no encryption key: only the seed, the checkpoint and the entries", () => {
    const v = openVault(hex(rv.wire), rk, "alice", ak);
    expect(Object.keys(v).sort()).toEqual(["accountSeed", "entries", "header", "lastCertificateHash", "lastDeviceGeneration"]);
    expect(v.entries[0] && Object.keys(v.entries[0]).sort()).toEqual(["circleId", "ownerIdentityId", "sharingEnabled"]);
  });

  it("re-seals edited entries at the next revision, sorted and unique", () => {
    const v = openVault(hex(rv.wire), rk, "alice", ak);
    const other = { circleId: new Uint8Array(16).fill(0xaa), ownerIdentityId: hex(alice.identity_id), sharingEnabled: false };
    const first = v.entries[0];
    if (!first) throw new Error("entry");
    let entries = upsertEntry(v.entries, other);
    entries = upsertEntry(entries, { ...first, sharingEnabled: false });
    expect(entries.length).toBe(2);
    expect(entries[0]?.sharingEnabled).toBe(false);
    const built = buildVault({ ...v.header, vaultRevision: 2n }, { ...v, entries }, rk);
    const reopened = openVault(built.wire, rk, "alice", ak);
    expect(reopened.header.vaultRevision).toBe(2n);
    expect(reopened.entries.map((e) => toHex(e.circleId))).toEqual(entries.map((e) => toHex(e.circleId)));
    expect(removeEntry(entries, other.circleId).length).toBe(1);
    expect(() => buildVault({ ...v.header, vaultRevision: 0n }, v, rk)).toThrow(expect.objectContaining({ code: "MALFORMED" }));
  });

  it("the recovery code is 48 characters and strict", () => {
    expect(encodeRecoveryCode(rk)).toBe(rv.recovery_code);
    expect(rv.recovery_code.length).toBe(48);
    expect(toHex(decodeRecoveryCode(rv.recovery_code))).toBe(rv.recovery_key);
    expect(() => decodeRecoveryCode(rv.recovery_code.toLowerCase())).toThrow();
  });
});

describe("recovery order", () => {
  const rk = hex(rv.recovery_key);
  const ak = accountKeypair(hex(str(fixture.inputs["alice_account_seed"] ?? ""))).publicKey;
  const iid = hex(alice.identity_id);
  const base = { accountName: "alice", identityId: iid, accountKey: ak, vaultWire: hex(rv.wire) };

  it("uses the provider first", async () => {
    const p = new MemoryProvider();
    await p.save("alice", iid, rk);
    const r = await recoverAccount({ ...base, provider: p });
    expect(r.source).toBe("provider");
    expect(toHex(r.recoveryKey)).toBe(rv.recovery_key);
    expect(r.vault.header.vaultRevision).toBe(1n);
  });

  it("falls back to the code when the provider is unavailable, locked, unsupported or erroring", async () => {
    for (const status of ["unavailable", "locked", "unsupported", "error"] as const) {
      const p = new MemoryProvider();
      p.status_ = status;
      const r = await recoverAccount({ ...base, provider: p, recoveryCode: rv.recovery_code });
      expect(r.source).toBe("code");
      expect(r.providerStatus).toBe(status);
    }
  });

  it("ignores a provider key that does not open the vault and uses the code", async () => {
    const p = new MemoryProvider();
    await p.save("alice", iid, newRecoveryKey());
    const r = await recoverAccount({ ...base, provider: p, recoveryCode: rv.recovery_code });
    expect(r.source).toBe("code");
  });

  it("reports ACCOUNT_RECOVERY_REQUIRED when both fail, and never resets", async () => {
    const p = new MemoryProvider();
    p.status_ = "unavailable";
    expect(await outcome(() => recoverAccount({ ...base, provider: p }))).toBe("ACCOUNT_RECOVERY_REQUIRED");
    const wrongCode = encodeRecoveryCode(newRecoveryKey());
    expect(await outcome(() => recoverAccount({ ...base, provider: p, recoveryCode: wrongCode }))).toBe("DECRYPT_FAILED");
    expect(await outcome(() => recoverAccount({ ...base, provider: p, recoveryCode: "SS5R-not-a-code" }))).toBe("MALFORMED");
  });

  it("a wrong platform account yields unavailable, never a new account", async () => {
    const p = new MemoryProvider();
    await p.save("alice", new Uint8Array(32).fill(1), rk); // an item for another identity
    expect(await outcome(() => recoverAccount({ ...base, provider: p }))).toBe("ACCOUNT_RECOVERY_REQUIRED");
    expect(p.loads).toBe(1);
  });
});
