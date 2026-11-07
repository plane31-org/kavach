/**
 * The fault harness of build step 16: a store wrapper that crashes the process at a chosen
 * transaction boundary, a transport wrapper that loses responses after the host committed,
 * duplicates and reorders deliveries, withholds, replays, forks and tampers with documents,
 * and a sweep that runs one scenario once per boundary and checks the durable-state outcomes
 * of protocol section 11 after a restart. Exported under `@plane31/blind-relay/testing` only.
 */
import { equalBytes, toHex } from "../bytes.js";
import { KavachError } from "../errors.js";
import { invokeSync, type Store, type Tx } from "../store.js";
import type {
  ResolvedAccount, AppendOutcome, Directory, EpochBundle, MutationOutcome, ReadRecordsResult, Relay, Transport } from "../transport.js";

// Crashes ------------------------------------------------------------------------------------------

export type CrashPhase = "beforeCommit" | "afterCommit";

export interface CrashPlan {
  /** The 1-based index of the transaction (counted across every handle of the process) to crash at. */
  readonly at: number;
  /** Before commit: the transaction rolls back. After commit: it is durable but no caller sees the result. */
  readonly phase: CrashPhase;
}

/** The process died here. Every later store call from the same process fails. */
export class SimulatedCrash extends Error {
  constructor(
    readonly at: number,
    readonly phase: CrashPhase
  ) {
    super(`simulated crash ${phase} transaction ${at}`);
    this.name = "SimulatedCrash";
  }
}

interface ProcessState {
  transactions: number;
  crashed: SimulatedCrash | undefined;
  readonly plan: CrashPlan | undefined;
}

/**
 * A store handle that belongs to one simulated process. All handles made with `fork()` share
 * the transaction counter and die together. A read-only probe that must survive the crash reads
 * the inner store directly.
 */
export class FaultyStore implements Store {
  private readonly process: ProcessState;

  constructor(
    readonly inner: Store,
    plan?: CrashPlan,
    private readonly forkInner?: () => Store,
    process?: ProcessState
  ) {
    this.process = process ?? { transactions: 0, crashed: undefined, plan };
  }

  get crashed(): SimulatedCrash | undefined {
    return this.process.crashed;
  }

  get transactions(): number {
    return this.process.transactions;
  }

  async transaction<R>(fn: (tx: Tx) => R): Promise<R> {
    this.alive();
    const n = ++this.process.transactions;
    const plan = this.process.plan;
    const result = await this.inner.transaction((tx) => {
      const r = invokeSync(fn, tx);
      if (plan && plan.phase === "beforeCommit" && plan.at === n) throw this.die(n, "beforeCommit");
      return r;
    });
    if (plan && plan.phase === "afterCommit" && plan.at === n) throw this.die(n, "afterCommit");
    return result;
  }

  async read<R>(fn: (tx: Omit<Tx, "put" | "delete" | "handoff">) => R): Promise<R> {
    this.alive();
    return this.inner.read(fn);
  }

  /** Another execution context of the same process. */
  fork(): FaultyStore {
    if (!this.forkInner) throw new Error("this store cannot fork");
    return new FaultyStore(this.forkInner(), undefined, this.forkInner, this.process);
  }

  private die(at: number, phase: CrashPhase): SimulatedCrash {
    this.process.crashed = new SimulatedCrash(at, phase);
    return this.process.crashed;
  }

  private alive(): void {
    if (this.process.crashed) throw new KavachError("STORAGE_FAILURE", "faultyStore", "the process has crashed");
  }
}

// The malicious transport ----------------------------------------------------------------------------

export type MutationName = "registerAccount" | "activateDevice" | "publishVault" | "publishOwnedCircle" | "requestJoin" | "requestLeave" | "resetAccount" | "succeedAccount" | "setSharingPreference" | "publishEpoch" | "appendRecord" | "ackThrough";

export type ServedKind = "certificate" | "snapshot" | "vault" | "manifest" | "wrap" | "record" | "keyList" | "receipt" | "succession";

export interface MaliciousKnobs {
  /** Mutations whose next response is lost after the host committed it (each name is consumed once). */
  readonly loseResponseOf: Set<MutationName>;
  /** Mutations whose next call fails before reaching the host (each name is consumed once). */
  readonly refuse: Set<MutationName>;
  /** Mutations whose next response waits for the given promise after the host committed (consumed once). */
  readonly hold: Map<MutationName, Promise<void>>;
  /** Called when a held mutation has reached its gate (the host has answered; the response is being held), so a test can act at exactly that point. */
  onHeld?: (name: MutationName) => void;
  /** Mutations whose next call fails with exactly this error before reaching the host (consumed once). */
  readonly failWith: Map<MutationName, KavachError>;
  /** Record reads fail once with NETWORK after this many pages have been served. */
  failReadsAfter?: number | undefined;
  /** Reads that answer "nothing" while present. */
  readonly withhold: Set<"snapshots" | "epochs" | "records" | "requests" | "currentEpoch" | "keyList" | "certificates" | "successions" | "circleList" | "subscriptions">;
  /** Older documents served instead of the current ones. */
  readonly replay: {
    vault?: Uint8Array;
    snapshots: Map<string, Uint8Array>;
    keyList?: Uint8Array;
    currentEpoch?: { epoch: number; manifestHash: Uint8Array };
  };
  /** Served documents to substitute: forks of the host's log. Keys are hex (circle id, stream id, record id). */
  readonly fork: {
    snapshots: Map<string, Uint8Array>;
    manifests: Map<string, Uint8Array>;
    records: Map<string, Uint8Array>;
    certificates: Map<string, Uint8Array>;
  };
  /** Every record page is served twice over, and each record appears twice inside a page. */
  duplicate: boolean;
  /** Records inside a page are served newest first. */
  reorder: boolean;
  /** Flip a byte in every served document of these kinds. */
  readonly tamper: Set<ServedKind>;
}

export function emptyKnobs(): MaliciousKnobs {
  return {
    loseResponseOf: new Set(),
    refuse: new Set(),
    hold: new Map(),
    failWith: new Map(),
    withhold: new Set(),
    replay: { snapshots: new Map() },
    fork: { snapshots: new Map(), manifests: new Map(), records: new Map(), certificates: new Map() },
    duplicate: false,
    reorder: false,
    tamper: new Set()
  };
}

function flipByte(bytes: Uint8Array): Uint8Array {
  const out = Uint8Array.from(bytes);
  const i = out.length - 1; // inside the signature for every signed type; inside the tag for a wrap
  out[i] = (out[i] ?? 0) ^ 0x01;
  return out;
}

/**
 * Wraps a transport. Everything not switched on passes through unchanged, so a scenario can be
 * driven to a point and then attacked. `calls` records every method name in order.
 */
export class MaliciousTransport implements Transport {
  readonly knobs: MaliciousKnobs = emptyKnobs();
  readonly calls: string[] = [];
  /** The mutations whose response this transport has lost so far. */
  readonly losses: MutationName[] = [];
  readonly directory: Directory;
  readonly relay: Relay;

  constructor(private readonly inner: Transport) {
    this.directory = this.wrapDirectory();
    this.relay = this.wrapRelay();
  }

  private serve(kind: ServedKind, bytes: Uint8Array | undefined): Uint8Array | undefined {
    if (!bytes) return bytes;
    return this.knobs.tamper.has(kind) ? flipByte(bytes) : bytes;
  }

  private async mutate<O extends MutationOutcome | AppendOutcome | { status: string }>(name: MutationName, call: () => Promise<O>): Promise<O> {
    this.calls.push(name);
    if (this.knobs.refuse.has(name)) {
      this.knobs.refuse.delete(name);
      throw new KavachError("NETWORK", "transport", "network unreachable");
    }
    const result = await call();
    const gate = this.knobs.hold.get(name);
    if (gate) {
      this.knobs.hold.delete(name);
      this.knobs.onHeld?.(name);
      await gate;
    }
    if (this.knobs.loseResponseOf.has(name)) {
      this.knobs.loseResponseOf.delete(name);
      this.losses.push(name);
      throw new KavachError("NETWORK", "transport", "response lost");
    }
    return result;
  }

  /** A resolved account as served: a forked or tampered certificate, and a tampered chain, where the knobs say so. */
  private servedAccount(r: ResolvedAccount): ResolvedAccount {
    const certificate = this.knobs.fork.certificates.get(r.accountName) ?? this.serve("certificate", r.certificate) ?? r.certificate;
    const successions = r.successions?.map((l) => ({ ...l, wire: this.serve("succession", l.wire) ?? l.wire }));
    return { ...r, certificate, ...(successions ? { successions } : {}) };
  }

  private wrapDirectory(): Directory {
    // The inner transport may rebind itself per call (a device's certificate changes at
    // activation), so it is read on every call, never captured.
    const d = (): Directory => this.inner.directory;
    const k = this.knobs;
    return {
      resolveAccounts: async (names) => {
        this.calls.push("resolveAccounts");
        if (k.withhold.has("certificates")) return [];
        const rs = await d().resolveAccounts(names);
        return rs.map((r) => this.servedAccount(r));
      },
      resolveIdentities: async (ids) => {
        this.calls.push("resolveIdentities");
        if (k.withhold.has("certificates")) return [];
        const rs = await d().resolveIdentities(ids);
        return rs.map((r) => this.servedAccount(r));
      },
      getCertificate: async (hash) => {
        this.calls.push("getCertificate");
        return this.serve("certificate", await d().getCertificate(hash));
      },
      activateDevice: (input) => this.mutate("activateDevice", () => d().activateDevice(input)),
      registerAccount: (input) => this.mutate("registerAccount", () => d().registerAccount(input)),
      getVault: async (name) => {
        this.calls.push("getVault");
        return this.serve("vault", k.replay.vault ?? (await d().getVault(name)));
      },
      publishVault: (input) => this.mutate("publishVault", () => d().publishVault(input)),
      getCircle: async (circleId) => {
        this.calls.push("getCircle");
        if (k.withhold.has("snapshots")) return undefined;
        const key = toHex(circleId);
        return this.serve("snapshot", k.fork.snapshots.get(key) ?? k.replay.snapshots.get(key) ?? (await d().getCircle(circleId)));
      },
      publishOwnedCircle: (input) => this.mutate("publishOwnedCircle", () => d().publishOwnedCircle(input)),
      requestJoin: (circleId) => this.mutate("requestJoin", () => d().requestJoin(circleId)),
      requestLeave: (circleId) => this.mutate("requestLeave", () => d().requestLeave(circleId)),
      readRequests: async (circleId) => {
        this.calls.push("readRequests");
        return k.withhold.has("requests") ? [] : d().readRequests(circleId);
      },
      getResetKeyList: async () => {
        this.calls.push("getResetKeyList");
        if (k.withhold.has("keyList")) return undefined;
        return this.serve("keyList", k.replay.keyList ?? (await d().getResetKeyList()));
      },
      getResetReceipt: async (id) => {
        this.calls.push("getResetReceipt");
        return this.serve("receipt", await d().getResetReceipt(id));
      },
      resetAccount: (input) => this.mutate("resetAccount", () => d().resetAccount(input)),
      succeedAccount: (input) => this.mutate("succeedAccount", () => d().succeedAccount(input)),
      getSuccessions: async (accountId, after, limit) => {
        this.calls.push("getSuccessions");
        if (k.withhold.has("successions")) return { successions: [] };
        const page = await d().getSuccessions(accountId, after, limit);
        return { ...page, successions: page.successions.map((l) => ({ ...l, wire: this.serve("succession", l.wire) ?? l.wire })) };
      },
      listCircles: async (cursor) => {
        this.calls.push("listCircles");
        if (k.withhold.has("circleList")) throw new KavachError("NETWORK", "transport", "network unreachable");
        return d().listCircles(cursor);
      },
      setSharingPreference: (circleId, enabled, expected) => this.mutate("setSharingPreference", () => d().setSharingPreference(circleId, enabled, expected))
    };
  }

  private wrapRelay(): Relay {
    const r = (): Relay => this.inner.relay;
    const k = this.knobs;
    const pagesServed = new Map<string, number>();
    return {
      getCurrentEpoch: async (streamId) => {
        this.calls.push("getCurrentEpoch");
        if (k.withhold.has("currentEpoch")) return undefined;
        return k.replay.currentEpoch ?? r().getCurrentEpoch(streamId);
      },
      getEpoch: async (streamId, epoch): Promise<EpochBundle | undefined> => {
        this.calls.push("getEpoch");
        if (k.withhold.has("epochs")) return undefined;
        const b = await r().getEpoch(streamId, epoch);
        if (!b) return b;
        const manifest = k.fork.manifests.get(`${toHex(streamId)}:${epoch}`) ?? this.serve("manifest", b.manifest) ?? b.manifest;
        return { manifest, wrap: this.serve("wrap", b.wrap) };
      },
      publishEpoch: (input) => this.mutate("publishEpoch", () => r().publishEpoch(input)),
      appendRecord: (recordId, wire) => {
        // Must stay synchronous up to the inner call (T6h).
        this.calls.push("appendRecord");
        const fail = k.failWith.get("appendRecord");
        if (fail) {
          k.failWith.delete("appendRecord");
          return Promise.reject(fail);
        }
        const p = r().appendRecord(recordId, wire);
        if (!k.loseResponseOf.has("appendRecord")) return p;
        k.loseResponseOf.delete("appendRecord");
        this.losses.push("appendRecord");
        return p.then(() => {
          throw new KavachError("NETWORK", "transport", "response lost");
        });
      },
      readRecords: async (streamId, afterSeq, limit): Promise<ReadRecordsResult> => {
        this.calls.push("readRecords");
        if (k.failReadsAfter !== undefined) {
          if (k.failReadsAfter <= 0) {
            k.failReadsAfter = undefined;
            throw Object.freeze(new KavachError("NETWORK", "transport", "network unreachable")); // frozen, as a transport may hand it over
          }
          k.failReadsAfter--;
        }
        if (k.withhold.has("records")) {
          const probe = await r().readRecords(streamId, afterSeq, limit);
          return { ...probe, records: [], nextSeq: afterSeq };
        }
        const page = await r().readRecords(streamId, afterSeq, limit);
        let records = page.records.map((x) => {
          const forked = k.fork.records.get(`${toHex(streamId)}:${x.deliverySeq}`);
          return { deliverySeq: x.deliverySeq, wire: forked ?? this.serve("record", x.wire) ?? x.wire };
        });
        if (k.reorder) records = [...records].reverse();
        if (k.duplicate) {
          records = records.flatMap((x) => [x, x]);
          const key = `${toHex(streamId)}:${afterSeq}`;
          const n = (pagesServed.get(key) ?? 0) + 1;
          pagesServed.set(key, n);
          // The first time a page is asked for, claim no progress so the reader asks again.
          if (n === 1 && records.length > 0) return { ...page, records, nextSeq: afterSeq };
        }
        return { ...page, records };
      },
      ackThrough: (streamId, cursor) => this.mutate("ackThrough", () => r().ackThrough(streamId, cursor)),
      listSubscriptions: async () => {
        this.calls.push("listSubscriptions");
        if (k.withhold.has("subscriptions")) throw new KavachError("NETWORK", "transport", "network unreachable");
        return r().listSubscriptions();
      }
    };
  }
}

// Helpers shared by the sweeps ----------------------------------------------------------------------

/** Whether two byte strings are equal, for assertions on exact-bytes outcomes. */
export function sameBytes(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  return a !== undefined && b !== undefined && equalBytes(a, b);
}
