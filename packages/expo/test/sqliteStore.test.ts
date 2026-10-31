import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { KavachError, certify, deviceFromSeed, newDevice, openAccount, randomBytes, ready, t1Activate, t1Header, t1Secrets, t3ApplyChange, openStore, MemorySecretStore } from "@kavach/core";
import { SqliteStore, nodeSqliteDriver, type SqlDriver } from "../src/sqliteStore.js";
import { openNodeDatabase } from "./sqlite.js";

beforeAll(() => ready());

function fileStore(path: string, busyTimeoutMs = 5000): SqliteStore {
  return SqliteStore.open({ driver: nodeSqliteDriver(openNodeDatabase(path)), busyTimeoutMs });
}

function memoryStore(): SqliteStore {
  return SqliteStore.open({ driver: nodeSqliteDriver(openNodeDatabase(":memory:")) });
}

async function code(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return "OK";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

describe("SqliteStore over a real SQLite engine", () => {
  it("sets the pragmas, keys the database when given a key, and creates the schema", () => {
    const statements: string[] = [];
    const inner = nodeSqliteDriver(openNodeDatabase(":memory:"));
    const recording: SqlDriver = {
      exec: (sql) => {
        statements.push(sql);
        if (!sql.startsWith("PRAGMA key")) inner.exec(sql); // node:sqlite has no cipher; the statement is still recorded
      },
      run: inner.run,
      all: inner.all
    };
    SqliteStore.open({ driver: recording, storageKey: new Uint8Array(32).fill(0xab), busyTimeoutMs: 250 });
    expect(statements[0]).toBe(`PRAGMA key = "x'${"ab".repeat(32)}'"`);
    expect(statements.slice(1, 4)).toEqual(["PRAGMA busy_timeout = 250", "PRAGMA journal_mode = WAL", "PRAGMA synchronous = FULL"]);
    expect(statements.some((s) => s.startsWith("CREATE TABLE IF NOT EXISTS kv"))).toBe(true);
    expect(() => SqliteStore.open({ driver: recording, storageKey: new Uint8Array(16) })).toThrow(expect.objectContaining({ code: "INVALID_KEY" }));
  });

  it("refuses to open when the first read fails, as SQLCipher does with the wrong key", () => {
    const inner = nodeSqliteDriver(openNodeDatabase(":memory:"));
    const broken: SqlDriver = { ...inner, all: () => { throw new Error("file is not a database"); } };
    expect(() => SqliteStore.open({ driver: broken })).toThrow(expect.objectContaining({ code: "RECOVERY_REQUIRED" }));
  });

  it("is atomic and reads see committed state only", async () => {
    const store = memoryStore();
    await expect(
      store.transaction((tx) => {
        tx.put("clock", "c", { highWater: "1" });
        throw new Error("boom");
      })
    ).rejects.toThrow("boom");
    expect(await store.read((tx) => tx.get("clock", "c"))).toBeUndefined();
    await store.transaction((tx) => {
      tx.put("clock", "c", { highWater: "2" });
      tx.put("clock", "d", { highWater: "3" });
      tx.delete("clock", "d");
      expect(tx.count("clock")).toBe(1);
    });
    expect(await store.read((tx) => tx.list("clock"))).toEqual([["c", { highWater: "2" }]]);
    expect(await store.read((tx) => tx.list("clock", "zz"))).toEqual([]);
    await expect(store.read((tx) => (tx as unknown as { put: (a: string, b: string, c: unknown) => void }).put("clock", "x", {}))).rejects.toThrow(expect.objectContaining({ code: "STORAGE_FAILURE" }));
  });

  it("refuses a callback that returns a promise, rolls back, and leaves the connection usable", async () => {
    const store = memoryStore();
    const refused = store.transaction((tx) => {
      tx.put("clock", "c", { highWater: "1" });
      return Promise.resolve("never committed") as unknown as string;
    });
    await expect(refused).rejects.toThrow(expect.objectContaining({ code: "STORAGE_FAILURE", message: expect.stringContaining("transaction callbacks are synchronous") }));
    expect(await store.read((tx) => tx.get("clock", "c"))).toBeUndefined();
    // The transaction was rolled back, so the next one can BEGIN and commit.
    await store.transaction((tx) => tx.put("clock", "c", { highWater: "2" }));
    expect(await store.read((tx) => tx.get("clock", "c"))).toEqual({ highWater: "2" });
  });

  it("serialises another process with BEGIN IMMEDIATE: a worker's write lands only after the handoff and commit", async () => {
    // Two JavaScript contexts, as the foreground app and the background task are on a phone. A second
    // connection in the same thread cannot be used for this: SQLite's busy wait blocks the thread.
    // The callback is synchronous, so the hold on the lock is stretched with a blocking wait, not an
    // await; the worker is told to begin while the lock is held and must wait for the commit.
    const dir = mkdtempSync(join(tmpdir(), "kavach-"));
    const path = join(dir, "store.db");
    const a = fileStore(path, 5000);
    await a.transaction((tx) => tx.put("clock", "c", { highWater: "init" }));
    const { Worker } = await import("node:worker_threads");
    const flags = new Int32Array(new SharedArrayBuffer(8)); // [0]: go, [1]: unused
    const workerCode = `
      const { parentPort, workerData } = require("node:worker_threads");
      const { DatabaseSync } = require("node:sqlite");
      const db = new DatabaseSync(workerData.path);
      db.exec("PRAGMA busy_timeout = 5000");
      Atomics.wait(workerData.flags, 0, 0); // until the main thread holds the lock
      const t0 = Date.now();
      db.exec("BEGIN IMMEDIATE");
      const waited = Date.now() - t0;
      db.prepare("INSERT INTO kv (tbl, key, value) VALUES ('clock', 'c', ?) ON CONFLICT (tbl, key) DO UPDATE SET value = excluded.value").run(JSON.stringify({ highWater: "B" }));
      db.exec("COMMIT");
      parentPort.postMessage({ waited, committedAt: Date.now() });
    `;
    const worker = new Worker(workerCode, { eval: true, workerData: { path, flags } });
    const result = new Promise<{ waited: number; committedAt: number }>((resolve, reject) => {
      worker.once("message", resolve);
      worker.once("error", reject);
    });
    await new Promise((r) => setTimeout(r, 100)); // the worker has opened its connection and is parked on the flag
    const order: string[] = [];
    let commitAt = 0;
    const outcome = await a.transaction((tx) => {
      order.push("A:check");
      Atomics.store(flags, 0, 1);
      Atomics.notify(flags, 0); // the worker now runs into our BEGIN IMMEDIATE and waits
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150); // hold the lock, synchronously
      tx.put("clock", "c", { highWater: "A" });
      const sent = tx.handoff(async () => {
        order.push("A:send");
        return result; // the awaited part: resolved by the worker, which needs our lock to finish
      });
      order.push("A:commit");
      commitAt = Date.now();
      return { sent }; // carried out inside a value: a bare promise return is refused by the contract
    });
    const b = await outcome.sent;
    expect(order).toEqual(["A:check", "A:send", "A:commit"]);
    // The worker's BEGIN IMMEDIATE blocked until A committed: it cannot have committed earlier, and
    // its wait covers most of the 150 ms hold.
    expect(b.waited).toBeGreaterThanOrEqual(50);
    expect(b.committedAt).toBeGreaterThanOrEqual(commitAt);
    expect(await a.read((tx) => tx.get("clock", "c"))).toEqual({ highWater: "B" });
  }, 20_000);

  it("a writer that cannot take the lock within the busy timeout gets LOCKED, with nothing written", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kavach-"));
    const path = join(dir, "store.db");
    // Another context holds the file lock: a raw connection with an open BEGIN IMMEDIATE.
    const holder = openNodeDatabase(path);
    const b = fileStore(path, 100);
    holder.exec("BEGIN IMMEDIATE");
    holder.prepare("INSERT INTO kv (tbl, key, value) VALUES ('clock', 'c', ?)").run(JSON.stringify({ highWater: "A" }));
    expect(await code(() => b.transaction((tx) => tx.put("clock", "c", { highWater: "B" })))).toBe("LOCKED");
    holder.exec("COMMIT");
    expect(await b.read((tx) => tx.get("clock", "c"))).toEqual({ highWater: "A" });
  });

  it("runs the core transactions: T1 header and activation, openStore binding, T3", async () => {
    const store = memoryStore();
    const secrets = new MemorySecretStore();
    const accountSeed = randomBytes(32);
    const account = openAccount("alice", accountSeed);
    const device = newDevice();
    const instanceId = randomBytes(16);
    await t1Secrets(secrets, { accountSeed, deviceSeed: device.deviceSeed, recoveryKey: randomBytes(32), instanceId });
    await store.transaction((tx) => t1Header(tx, { account, device: deviceFromSeed(device.deviceSeed, device.deviceId), certificate: certify(account, device, 1n), instanceId, generation: 1n }));
    expect((await openStore(store, secrets, "alice")).kind).toBe("initializing");
    await store.transaction((tx) => t1Activate(tx));
    expect((await openStore(store, secrets, "alice")).kind).toBe("ACTIVE");
    const change = await store.transaction((tx) => t3ApplyChange(tx, { kind: "join", circleId: new Uint8Array(16) }));
    expect(change.desiredRevision).toBe(2n);
    await secrets.set("instanceId", randomBytes(16));
    expect(await code(() => openStore(store, secrets, "alice"))).toBe("RECOVERY_REQUIRED");
  });
});
