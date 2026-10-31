/** In-memory durable "files" for the sweeps: reopen and fork are new handles on the same tables. */
import { MemoryStore } from "../src/store.js";
import type { SweepStores } from "../src/testing/sweep.js";

export function memoryStores(): SweepStores {
  const files = new Map<string, MemoryStore>();
  const key = (run: string, name: string): string => `${run}/${name}`;
  const existing = (run: string, name: string): MemoryStore => {
    const s = files.get(key(run, name));
    if (!s) throw new Error("no such store");
    return s;
  };
  return {
    open(run, name) {
      const s = new MemoryStore();
      files.set(key(run, name), s);
      return s;
    },
    reopen: (run, name) => existing(run, name).fork(),
    fork: (run, name) => existing(run, name).fork(),
    dispose(run) {
      for (const k of [...files.keys()]) if (k.startsWith(run + "/")) files.delete(k);
    }
  };
}

/** The sweeps exercise durable state, not the cipher suite: they run once, on the default backend. */
export const sweepsEnabled = process.env["KAVACH_CRYPTO"] !== "sodium";
