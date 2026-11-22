/**
 * One account's client for every caller in a JS runtime (0.9.0): opened when first used, shared
 * while in use, closed cleanly, and let go when another runtime erases the account. An Android app
 * with a headless background task runs two runtimes over one database; each keeps a slot.
 *
 * `use(fn)` opens the account if needed and holds a lease while `fn` runs. `close()` stops new
 * leases, waits for the ones running to end, then closes the client and its database; a `use` that
 * comes meanwhile waits for the close and opens afresh, so two handles never overlap in a runtime.
 * `releaseIdle()` closes only when nothing is in use: a background task calls it when its run ends,
 * so no idle handle is held across wakes. `erase()` replaces the erase marker, closes this slot and
 * erases the account. Before each use the slot reads the marker: when it changed since the slot
 * opened (the other runtime erased), the slot drops its handle and opens afresh, so it never keeps
 * writing to a database that was deleted under it. An operation already running in the other
 * runtime while the erasure deletes the file may finish against the deleted file; what it wrote
 * goes with the account.
 */
import { toHex } from "@plane31/blind-relay";
import { accountSecretStore, eraseKavach, markErased, openKavach, type KavachEraseOptions, type KavachSetup, type KavachSetupOptions } from "./setup.js";

export interface KavachSlot {
  use<T>(fn: (setup: KavachSetup) => Promise<T> | T): Promise<T>;
  close(): Promise<void>;
  releaseIdle(): Promise<void>;
  /** Mark, close and erase the account; with a driver factory, pass how to delete its database file. */
  erase(deleteDatabase?: KavachEraseOptions["deleteDatabase"]): Promise<void>;
  /** Leases running now, for diagnostics. */
  readonly leases: number;
}

export function kavachSlot(options: KavachSetupOptions): KavachSlot {
  const namespace = options.namespace ?? "kavach";
  const secrets = accountSecretStore(options.secrets, options.accountName, namespace);
  const marker = async (): Promise<string> => toHex((await secrets.get("eraseGeneration")) ?? new Uint8Array());
  let opening: Promise<{ setup: KavachSetup; marker: string }> | undefined;
  let closing: Promise<void> | undefined;
  let leases = 0;
  let waiters: (() => void)[] = [];
  const settled = (): void => {
    if (leases > 0) return;
    const ready = waiters;
    waiters = [];
    for (const r of ready) r();
  };
  const shut = (): Promise<void> => {
    const current = opening;
    opening = undefined; // new callers open afresh, after this close
    if (!current) return closing ?? Promise.resolve();
    const previous = closing;
    const done = (async () => {
      await previous;
      while (leases > 0) await new Promise<void>((r) => waiters.push(r));
      const s = await current.catch(() => undefined);
      if (s) await s.setup.close();
    })();
    const tracked: Promise<void> = done.finally(() => {
      if (closing === tracked) closing = undefined;
    });
    closing = tracked;
    return tracked;
  };
  const slot: KavachSlot = {
    get leases() {
      return leases;
    },
    async use<T>(fn: (setup: KavachSetup) => Promise<T> | T): Promise<T> {
      for (;;) {
        while (closing) await closing; // an open never overlaps a close in this runtime
        // The marker is read before the open: an erasure after the read is seen at the next use.
        opening ??= (async () => {
          const m = await marker();
          return { setup: await openKavach(options), marker: m };
        })();
        const mine = opening;
        let s: { setup: KavachSetup; marker: string };
        try {
          s = await mine;
        } catch (e) {
          if (opening === mine) opening = undefined;
          throw e;
        }
        if (opening !== mine) continue; // closed while it opened
        if ((await marker()) !== s.marker) {
          // Erased by another runtime since this handle opened: let it go, and open afresh.
          await shut();
          continue;
        }
        leases++;
        try {
          return await fn(s.setup);
        } finally {
          leases--;
          settled();
        }
      }
    },
    close: () => shut(),
    releaseIdle: () => (leases === 0 && opening && !closing ? shut() : Promise.resolve()),
    async erase(deleteDatabase) {
      await markErased(secrets); // first: the other runtime lets go before anything is deleted
      await shut();
      await eraseKavach({ accountName: options.accountName, secrets: options.secrets, namespace, database: options.database, ...(deleteDatabase ? { deleteDatabase } : {}) });
    }
  };
  return slot;
}
