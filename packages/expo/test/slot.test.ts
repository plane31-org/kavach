/** `kavachSlot`: one account's client per runtime, shared by leases, closed cleanly, and let go when another runtime erases the account. */
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "@plane31/blind-relay";
import { MemorySecretStore, ready, type SecretStore } from "@plane31/blind-relay/adapters";
import { FakeHost, TestClock, testPolicy, testResetKeyList, testResetKeys } from "@plane31/blind-relay/testing";
import { nodeSqliteDriver } from "../src/sqliteStore.js";
import { databaseFileName, markErased, openKavach } from "../src/setup.js";
import { kavachSlot } from "../src/slot.js";
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

const leased = async (slot: { readonly leases: number }): Promise<void> => {
  while (slot.leases === 0) await new Promise((r) => setTimeout(r, 1));
};

const deleteFiles = (dir: string) => (fileName: string) => {
  for (const suffix of ["", "-wal", "-shm"]) rmSync(join(dir, fileName + suffix), { force: true });
};

/** A secret store whose erase-marker reads can be held at a gate, to reach the window between a slot's checks. */
class GatedSecrets extends MemorySecretStore implements SecretStore {
  gate: Promise<void> | undefined;
  /** Holds every deletion: an erasure waits here after closing the slot and before deleting anything. */
  deleteGate: Promise<void> | undefined;
  override async get(name: Parameters<SecretStore["get"]>[0]): Promise<Uint8Array | undefined> {
    if (name === "eraseGeneration" && this.gate) await this.gate;
    return super.get(name);
  }
  override async delete(name: Parameters<SecretStore["delete"]>[0]): Promise<void> {
    if (this.deleteGate) await this.deleteGate;
    return super.delete(name);
  }
}

/** Two runtimes over one account: the same files and the same secret store, each with its own slot. */
function runtimes() {
  const w = world();
  const dir = mkdtempSync(join(tmpdir(), "kavach-slot-"));
  const secrets = new GatedSecrets();
  let opens = 0;
  const options = (context: "foreground" | "background") => ({
    accountName: "alice",
    transport: w.transport("alice"),
    retentionPolicy: { ...testPolicy, replacement: "recovery" as const },
    resetTrust: w.resetTrust,
    secrets,
    database: (fileName: string) => {
      opens++;
      return nodeSqliteDriver(openNodeDatabase(join(dir, fileName)));
    },
    context,
    now: w.clock.now
  });
  return { w, dir, secrets, options, opens: () => opens };
}

describe("kavachSlot", () => {
  it("opens once for concurrent uses, closes only when the leases end, and a use during the close opens afresh after it", async () => {
    const { options, opens } = runtimes();
    const slot = kavachSlot(options("foreground"));
    const [a, b] = await Promise.all([slot.use((s) => s.client), slot.use((s) => s.client)]);
    expect(a).toBe(b);
    expect(opens()).toBe(1);
    let release: () => void = () => undefined;
    const running = slot.use(async (s) => {
      await new Promise<void>((r) => (release = r));
      return (await s.client.getState()).status; // still open: the close waits for this lease
    });
    await leased(slot);
    expect(slot.leases).toBe(1);
    const closing = slot.close();
    const after = slot.use((s) => s.client);
    release();
    expect(await running).toBe("fresh");
    await closing;
    const reopened = await after;
    expect(reopened).not.toBe(a);
    expect(opens()).toBe(2);
    await slot.close();
  });

  it("releaseIdle closes an idle handle and leaves one in use alone", async () => {
    const { options, opens } = runtimes();
    const slot = kavachSlot(options("foreground"));
    let release: () => void = () => undefined;
    const running = slot.use(() => new Promise<void>((r) => (release = r)));
    await leased(slot);
    await slot.releaseIdle(); // in use: nothing happens
    expect(slot.leases).toBe(1);
    release();
    await running;
    await slot.releaseIdle();
    await slot.use(() => undefined);
    expect(opens()).toBe(2); // released, then opened again on the next use
    await slot.close();
  });

  it("a runtime that erases the account makes the other one let go of its handle and open afresh", async () => {
    const { options, dir } = runtimes();
    const foreground = kavachSlot(options("foreground"));
    const background = kavachSlot(options("background"));
    const before = await foreground.use(async (s) => {
      await s.client.initializeAccount();
      return toHex((await s.client.inspect()).identityId ?? new Uint8Array());
    });
    expect(await background.use(async (s) => (await s.client.getState()).status)).toBe("ready");
    // The foreground signs out and erases; the background still holds its handle on the old file.
    await foreground.erase(deleteFiles(dir));
    expect(existsSync(join(dir, databaseFileName("alice")))).toBe(false);
    // The background's next use sees the marker change, drops the old handle and opens afresh: it
    // finds no storage key, and a background runtime never mints one, so it waits for the foreground.
    await expect(background.use((s) => s.client.getState())).rejects.toMatchObject({ code: "LOCKED" });
    // The foreground opens the account afresh (the erasure was local; the app restores or enrolls
    // from here), and the background then opens the same fresh store, never the erased one.
    expect(await foreground.use(async (s) => (await s.client.getState()).status)).toBe("fresh");
    expect(await background.use(async (s) => [(await s.client.getState()).status, (await s.client.inspect()).identityId])).toEqual(["fresh", undefined]);
    expect(before).toHaveLength(64);
    await foreground.close();
    await background.close();
  });

  it("a use that arrives while this slot erases waits for the erasure and opens the fresh store, never the erased account", async () => {
    const { options, dir, secrets } = runtimes();
    const slot = kavachSlot(options("foreground"));
    await slot.use((s) => s.client.initializeAccount());
    // The erasure is held after it closed the slot and before it deletes anything: the window in
    // which a use could otherwise reopen the old database, secrets still in place.
    let release: () => void = () => undefined;
    secrets.deleteGate = new Promise<void>((r) => (release = r));
    const erasing = slot.erase(deleteFiles(dir));
    const during = slot.use(async (s) => (await s.client.getState()).status);
    await new Promise((r) => setTimeout(r, 10));
    secrets.deleteGate = undefined;
    release();
    await erasing;
    expect(await during).toBe("fresh");
    expect(await slot.use(async (s) => (await s.client.getState()).status)).toBe("fresh");
    await slot.close();
  });

  it("another runtime's erasure under way: a slot opens nothing and lets go of its handle until it has finished", async () => {
    const { options, secrets } = runtimes();
    const background = kavachSlot(options("background"));
    const foreground = kavachSlot(options("foreground"));
    await foreground.use((s) => s.client.initializeAccount());
    expect(await background.use(async (s) => (await s.client.getState()).status)).toBe("ready");
    await markErased(secrets, "erasing"); // the other runtime has begun
    await expect(background.use((s) => s.client.getState())).rejects.toMatchObject({ code: "LOCKED", retryable: true });
    expect(background.leases).toBe(0);
    await markErased(secrets, "erased"); // and finished (the files stay in this test: the point is the marker)
    expect(await background.use(async (s) => (await s.client.getState()).status)).toBe("ready");
    await foreground.close();
    await background.close();
  });

  it("a handle released while a use reads the marker is never handed to that use", async () => {
    const { options, secrets, opens } = runtimes();
    const slot = kavachSlot(options("foreground"));
    await slot.use(() => undefined);
    let open: () => void = () => undefined;
    secrets.gate = new Promise<void>((r) => (open = r));
    const pending = slot.use(async (s) => (await s.client.getState()).status);
    await new Promise((r) => setTimeout(r, 5)); // the use is now waiting on its marker read
    const released = slot.releaseIdle();
    secrets.gate = undefined;
    open();
    await released;
    expect(await pending).toBe("fresh"); // it reopened instead of failing with CLOSED
    expect(opens()).toBe(2);
    await slot.close();
  });

  it("two overlapping erasures are one: a use waiting on them opens a store that stays", async () => {
    const { options, dir, secrets } = runtimes();
    const slot = kavachSlot(options("foreground"));
    await slot.use((s) => s.client.initializeAccount());
    let deletions = 0;
    const counted = (fileName: string): void => {
      deletions++;
      deleteFiles(dir)(fileName);
    };
    let release: () => void = () => undefined;
    secrets.deleteGate = new Promise<void>((r) => (release = r));
    const first = slot.erase(counted);
    const second = slot.erase(counted);
    const during = slot.use(async (s) => (await s.client.getState()).status);
    await new Promise((r) => setTimeout(r, 10));
    secrets.deleteGate = undefined;
    release();
    await Promise.all([first, second]);
    expect(deletions).toBe(1); // one erasure ran
    expect(await during).toBe("fresh");
    expect(existsSync(join(dir, databaseFileName("alice")))).toBe(true); // the store the use opened was not deleted after it
    expect(await slot.use(async (s) => (await s.client.getState()).status)).toBe("fresh");
    await slot.close();
  });

  it("a second open of a database already open in this runtime is refused; after a close, or in another context, it is fine", async () => {
    const { options } = runtimes();
    const fg = options("foreground");
    const first = await openKavach(fg);
    await expect(openKavach(fg)).rejects.toMatchObject({ code: "MALFORMED" });
    const other = await openKavach({ ...fg, context: "background" }); // another runtime, as a test models it
    await other.close();
    await first.close();
    const again = await openKavach(fg);
    await again.close();
  });
});

