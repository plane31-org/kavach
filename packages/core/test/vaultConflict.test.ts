/**
 * The vault write path against a host whose answer to a conflict cannot be trusted as is, and a
 * write the host never confirmed followed by another one.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { parseVaultHeader } from "../src/codec.js";
import { ready } from "../src/crypto.js";
import { VAULT } from "../src/transactions.js";
import { pair, thrown, world, type World } from "./clientWorld.js";

beforeAll(() => ready());

function hostVault(w: World, name: string): { wire: Uint8Array; revision: bigint; hash: string } {
  const v = w.host.accounts.get(name)?.vault;
  if (!v) throw new Error(`no vault for ${name}`);
  return v;
}

describe("vault conflicts", () => {
  it("a conflict answered with an older vault is ROLLBACK: the local vault is kept and the write lands once the host is honest", async () => {
    const w = world();
    const { b, circleId, bobVault1 } = await pair(w);
    const acct = w.host.accounts.get("bob");
    if (!acct) throw new Error("no account");
    const honest = hostVault(w, "bob");
    expect(honest.revision).toBeGreaterThan(1n);
    acct.vault = { wire: bobVault1, revision: 1n, hash: toHex(parseVaultHeader(bobVault1).hash) };
    expect(await thrown(() => b.client.circles.setEnabled(circleId, false))).toBe("ROLLBACK");
    const row = await b.store.read((tx) => tx.get("vault", VAULT));
    expect(row?.wire).not.toBe(toHex(bobVault1));
    expect(row?.pending).toBe(true);
    acct.vault = honest;
    const r = await w.sync(b);
    expect(r.errors).toEqual([]);
    expect(hostVault(w, "bob").revision).toBe(honest.revision + 1n);
    expect((await b.store.read((tx) => tx.get("vault", VAULT)))?.pending).toBe(false);
  });

  it("a conflict answered with another account's vault is refused and the local vault is kept", async () => {
    const w = world();
    const { b, circleId } = await pair(w);
    const acct = w.host.accounts.get("bob");
    if (!acct) throw new Error("no account");
    const honest = hostVault(w, "bob");
    const alice = hostVault(w, "alice");
    acct.vault = { wire: alice.wire, revision: honest.revision + 5n, hash: alice.hash };
    const code = await thrown(() => b.client.circles.setEnabled(circleId, false));
    expect(["VAULT_BINDING", "DECRYPT_FAILED"]).toContain(code);
    const row = await b.store.read((tx) => tx.get("vault", VAULT));
    expect(row?.wire).not.toBe(toHex(alice.wire));
  });

  it("a vault write the host never confirmed is settled before the next one, so neither change is lost", async () => {
    const w = world();
    const { b, circleId } = await pair(w);
    const before = hostVault(w, "bob").revision;
    b.t.knobs.refuse.add("publishVault");
    expect(await thrown(() => b.client.circles.setEnabled(circleId, false))).toBe("NETWORK");
    expect(hostVault(w, "bob").revision).toBe(before);
    expect((await b.store.read((tx) => tx.get("vault", VAULT)))?.pending).toBe(true);
    b.t.knobs.refuse.delete("publishVault");
    await b.client.circles.setEnabled(circleId, true);
    expect(hostVault(w, "bob").revision).toBe(before + 2n);
    const row = await b.store.read((tx) => tx.get("vault", VAULT));
    expect([row?.pending, row?.revision]).toEqual([false, (before + 2n).toString()]);
  });
});
