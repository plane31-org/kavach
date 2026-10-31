/**
 * Step 16 on the real store: the crash sweep and the lost-response sweep over SQLite files with
 * `BEGIN IMMEDIATE`, WAL and `synchronous = FULL`, as the phone runs them (without SQLCipher's
 * key, which does not change transaction semantics). A restart is a new connection to the same
 * file while the dead process's connection stays open. The concurrent-contexts step needs a
 * second in-process handle and is skipped here; the worker-thread test in sqliteStore.test.ts
 * covers two connections contending for the lock.
 */
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { ready } from "@kavach/core";
import { crashSweep, lostResponseSweep, type DeviceName, type SweepStores } from "@kavach/core/testing";
import { SqliteStore, nodeSqliteDriver } from "../src/sqliteStore.js";
import { openNodeDatabase } from "./sqlite.js";

beforeAll(() => ready());

function sqliteStores(): SweepStores {
  const base = mkdtempSync(join(tmpdir(), "kavach-faults-"));
  const path = (run: string, name: DeviceName): string => join(base, run, name + ".db");
  const connect = (run: string, name: DeviceName): SqliteStore => SqliteStore.open({ driver: nodeSqliteDriver(openNodeDatabase(path(run, name))), storageKey: undefined, busyTimeoutMs: 50 });
  return {
    open(run, name) {
      mkdirSync(join(base, run), { recursive: true });
      return connect(run, name);
    },
    reopen: (run, name) => connect(run, name),
    dispose(run) {
      rmSync(join(base, run), { recursive: true, force: true });
    }
  };
}

const victims: DeviceName[] = ["alice", "bob2"];

describe("crash sweep on SQLite files", () => {
  for (const victim of victims) {
    it(`${victim}: a crash before or after every transaction boundary is recovered by a restart`, async () => {
      const result = await crashSweep({ stores: sqliteStores(), victim });
      expect(result.runs.length).toBe(result.boundaries * 2);
    }, 900_000);
  }
});

describe("lost responses on SQLite files", () => {
  it("bob2: each mutation's response lost once after the host committed it", async () => {
    const runs = await lostResponseSweep(sqliteStores(), "bob2");
    expect(runs.filter((r) => r.exercised).length).toBeGreaterThan(0);
  }, 300_000);
});
