/**
 * Durable state (protocol section 11): the store interface the profile implements, the secret
 * store, the logical tables, and an in-memory implementation with the same transaction semantics
 * for Node tests.
 *
 * Rules the interface carries: one writer across every execution context; a transaction is
 * atomic; the callback finishes synchronously, so the lock is never held across a suspension
 * of the caller; the callback may initiate a transport send before commit through `tx.handoff`,
 * and must not await it inside; a writer that cannot acquire the lock gets `LOCKED`.
 */
import type { RecordKind } from "./codec.js";
import { KavachError } from "./errors.js";

export interface SecretStore {
  get(name: SecretName): Promise<Uint8Array | undefined>;
  set(name: SecretName, value: Uint8Array): Promise<void>;
  delete(name: SecretName): Promise<void>;
}

export type SecretName = "accountSeed" | "deviceSeed" | "recoveryKey" | "storageKey" | "instanceId" | "pendingReset";

// Logical tables. Rows are JSON-safe: bytes as hex strings, u64 as decimal strings.

export type StoreState = "INITIALIZING" | "ACTIVE" | "ACTIVATION_PENDING" | "RETIRED";

export interface MetaRow {
  schema: 1;
  instanceId: string;
  accountName: string;
  identityId: string;
  certificateHash: string;
  state: StoreState;
}

export interface SelfRow {
  generation: string;
  deviceId: string;
  certificate: string;
  certificateHash: string;
  streamId: string;
}

export interface PinRow {
  accountName: string;
  accountKey: string;
  identityId: string;
  generation: string;
  certificateHash: string;
  certificate: string;
  deviceId: string;
  signingKey: string;
  boxKey: string;
  streamId: string;
  deviceIds: string[];
}

export interface CertificateRow {
  identityId: string;
  certificateHash: string;
  signingKey: string;
  boxKey: string;
  streamId: string;
  generation: string;
  wire: string;
  current: boolean;
}

export interface QuarantineRow {
  accountName: string;
  certificate: string;
  reason: string;
  at: string;
}

export interface CircleRow {
  circleId: string;
  ownerIdentityId: string;
  revision: string;
  bodyHash: string | undefined;
  snapshot: string | undefined;
  members: string[];
  enabled: boolean;
  status: "requested" | "member" | "left" | "quarantined" | "closed";
  verifiedAt: string;
  /** An owner's successor snapshot awaiting host confirmation (T8). */
  pending?: { snapshot: string; revision: string; close?: boolean } | undefined;
}

export interface RevisionRow {
  desiredRevision: string;
  seenSnapshots: Record<string, string>;
  seenCertificates: Record<string, string>;
  paused: "rotation" | "metadata" | "limit" | "sync" | undefined;
}

export interface VaultRow {
  revision: string;
  hash: string;
  wire: string;
  /** Prepared but not yet confirmed by the host. */
  pending: boolean;
  /** The circle rows changed since this vault was derived from them; set in the same transaction. */
  dirty: boolean;
}

export type EpochStatus = "prepared" | "committed" | "active" | "obsolete" | "retired";

export interface EpochRow {
  epoch: number;
  status: EpochStatus;
  manifest: string;
  manifestHash: string;
  wraps: Record<string, string>;
  epochKey: string;
  capturedRevision: string;
  audienceKey: string;
  createdAt: string;
  nextCounter: number;
  lastSentAt: string | undefined;
}

export interface StreamRow {
  highestCommittedEpoch: number;
  activeEpoch: number | undefined;
  pendingEpoch: number | undefined;
}

export type OutboxStatus = "queued" | "inflight" | "accepted" | "cancelled" | "unknown";

export interface OutboxRow {
  recordId: string;
  wire: string;
  epoch: number;
  counter: number;
  kind: RecordKind;
  sentAt: string;
  desiredRevision: string;
  status: OutboxStatus;
  attempts: number;
  reason: string | undefined;
}

export interface HistoryRow {
  recordId: string;
  authorIdentityId: string;
  streamId: string;
  generation: string;
  epoch: number;
  counter: number;
  kind: RecordKind;
  sentAt: string;
  receivedAt: string;
  plaintext: string;
  superseded: boolean;
  own: boolean;
  /** Body hash of the wire, for duplicate and equivocation detection. */
  bodyHash?: string;
}

export interface LivePinRow {
  recordId: string;
  generation: string;
  epoch: number;
  counter: number;
  sentAt: string;
}

/** The newest status (kind 2) per author: one row, never history. Keyed by author identity id. */
export interface StatusRow {
  recordId: string;
  bodyHash: string;
  generation: string;
  epoch: number;
  counter: number;
  sentAt: string;
  receivedAt: string;
  /** Hex, possibly empty; `null` once expired, the slot staying so an older status cannot become current. */
  payload: string | null;
}

export interface ReaderEpochRow {
  streamId: string;
  epoch: number;
  epochKey: string;
  manifestHash: string;
  authorCertificateHash: string;
  superseded: boolean;
}

export interface SubscriptionRow {
  streamId: string;
  authorIdentityId: string;
  /** Local scan position: the last sequence examined. */
  scanPos: string;
  /** The eligible acknowledged prefix. */
  ackPrefix: string;
  /** The last cursor the relay confirmed. */
  committedCursor: string;
  /** A send in flight for this stream. */
  ackInFlight: boolean;
}

export interface UnresolvedRow {
  streamId: string;
  deliverySeq: string;
  reason: "KEY_PENDING";
  epoch: number;
  recordedAt: string;
}

export interface ActivationRow {
  certificate: string;
  vault: string;
  vaultRevision: string;
  expectedCertificateHash: string;
  expectedVaultRevision: string;
  expectedVaultHash: string;
}

export interface ResetListRow {
  wire: string;
  version: string;
  hash: string;
  checkedAt: string;
}

export interface ResetReceiptRow {
  accountName: string;
  oldIdentityId: string;
  newIdentityId: string;
  receiptHash: string;
}

export interface ClockRow {
  highWater: string;
}

/** A last-resort reset prepared and persisted before it is sent, so a lost response can be resumed. */
export interface PendingResetRow {
  resetId: string;
  oldIdentityId: string;
  certificate: string;
  vault: string;
  vaultHash: string;
}

export interface Tables {
  meta: MetaRow;
  self: SelfRow;
  pins: PinRow;
  certificates: CertificateRow;
  quarantine: QuarantineRow;
  circles: CircleRow;
  revision: RevisionRow;
  vault: VaultRow;
  epochs: EpochRow;
  stream: StreamRow;
  outbox: OutboxRow;
  history: HistoryRow;
  livePins: LivePinRow;
  statuses: StatusRow;
  readerEpochs: ReaderEpochRow;
  subscriptions: SubscriptionRow;
  unresolved: UnresolvedRow;
  activation: ActivationRow;
  resetList: ResetListRow;
  resetReceipts: ResetReceiptRow;
  retiredIdentities: { identityId: string };
  clock: ClockRow;
  pendingReset: PendingResetRow;
}

export type TableName = keyof Tables;

export interface Tx {
  get<T extends TableName>(table: T, key: string): Tables[T] | undefined;
  put<T extends TableName>(table: T, key: string, row: Tables[T]): void;
  delete<T extends TableName>(table: T, key: string): void;
  list<T extends TableName>(table: T, prefix?: string): readonly [string, Tables[T]][];
  count(table: TableName): number;
  /**
   * Initiate a network operation inside this transaction (T6h). The call starts now, before
   * commit; the returned promise is awaited by the caller after the transaction returns.
   */
  handoff<R>(start: () => Promise<R>): Promise<R>;
}

export interface Store {
  /**
   * BEGIN IMMEDIATE semantics: exclusive, atomic, serialised across every context. The callback
   * runs to completion synchronously between begin and commit; a callback that returns a promise
   * is refused with `STORAGE_FAILURE` and nothing is written. The one asynchronous thing a
   * callback may do is start a network operation through `tx.handoff`.
   */
  transaction<R>(fn: (tx: Tx) => R): Promise<R>;
  /** A consistent read without taking the writer lock. */
  read<R>(fn: (tx: Omit<Tx, "put" | "delete" | "handoff">) => R): Promise<R>;
}

// In-memory implementation -----------------------------------------------------------------------

/**
 * Run a transaction callback and refuse one that returns a promise. Shared by every `Store`
 * implementation so the refusal is the same error everywhere.
 */
export function invokeSync<R>(fn: (tx: Tx) => R, tx: Tx): R {
  const result = fn(tx);
  if (isThenable(result)) throw new KavachError("STORAGE_FAILURE", "store", "transaction callbacks are synchronous");
  return result;
}

function isThenable(value: unknown): boolean {
  return (typeof value === "object" || typeof value === "function") && value !== null && typeof (value as { then?: unknown }).then === "function";
}

type TableMap = Map<TableName, Map<string, unknown>>;

function cloneRow<T>(row: T): T {
  return JSON.parse(JSON.stringify(row)) as T;
}

class MemoryTx implements Tx {
  readonly journal: Map<TableName, Map<string, unknown | null>> = new Map();
  readonly handoffs: Promise<unknown>[] = [];

  constructor(
    private readonly base: TableMap,
    private readonly readOnly: boolean
  ) {}

  private tableJournal(table: TableName): Map<string, unknown | null> {
    let j = this.journal.get(table);
    if (!j) {
      j = new Map();
      this.journal.set(table, j);
    }
    return j;
  }

  get<T extends TableName>(table: T, key: string): Tables[T] | undefined {
    const j = this.journal.get(table);
    if (j && j.has(key)) {
      const v = j.get(key);
      return v === null ? undefined : cloneRow(v as Tables[T]);
    }
    const v = this.base.get(table)?.get(key);
    return v === undefined ? undefined : cloneRow(v as Tables[T]);
  }

  put<T extends TableName>(table: T, key: string, row: Tables[T]): void {
    if (this.readOnly) throw new KavachError("STORAGE_FAILURE", "store", "write in a read transaction");
    this.tableJournal(table).set(key, cloneRow(row));
  }

  delete<T extends TableName>(table: T, key: string): void {
    if (this.readOnly) throw new KavachError("STORAGE_FAILURE", "store", "write in a read transaction");
    this.tableJournal(table).set(key, null);
  }

  list<T extends TableName>(table: T, prefix = ""): readonly [string, Tables[T]][] {
    const merged = new Map<string, unknown>(this.base.get(table) ?? []);
    for (const [k, v] of this.journal.get(table) ?? []) {
      if (v === null) merged.delete(k);
      else merged.set(k, v);
    }
    return [...merged.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => [k, cloneRow(v as Tables[T])]);
  }

  count(table: TableName): number {
    return this.list(table).length;
  }

  handoff<R>(start: () => Promise<R>): Promise<R> {
    if (this.readOnly) throw new KavachError("STORAGE_FAILURE", "store", "handoff in a read transaction");
    const p = start();
    this.handoffs.push(p.catch(() => undefined));
    return p;
  }

  commitInto(base: TableMap): void {
    for (const [table, j] of this.journal) {
      let t = base.get(table);
      if (!t) {
        t = new Map();
        base.set(table, t);
      }
      for (const [k, v] of j) {
        if (v === null) t.delete(k);
        else t.set(k, v);
      }
    }
  }
}

/** Crash injection for tests: throw at a chosen point. */
export interface MemoryStoreOptions {
  /** Called just before a transaction commits; throwing simulates a crash before durability. */
  beforeCommit?: (count: number) => void;
}

interface Shared {
  tables: TableMap;
  chain: Promise<void>;
  held: boolean;
  commits: number;
}

export class MemoryStore implements Store {
  private readonly shared: Shared;
  /** Every handoff started inside a committed transaction, for tests that wait for the network. */
  readonly handoffs: Promise<unknown>[] = [];

  constructor(
    private readonly options: MemoryStoreOptions = {},
    shared?: Shared
  ) {
    this.shared = shared ?? { tables: new Map(), chain: Promise.resolve(), held: false, commits: 0 };
  }

  async transaction<R>(fn: (tx: Tx) => R): Promise<R> {
    const release = await this.acquire();
    try {
      const tx = new MemoryTx(this.shared.tables, false);
      const result = invokeSync(fn, tx);
      this.options.beforeCommit?.(this.shared.commits + 1);
      tx.commitInto(this.shared.tables);
      this.shared.commits++;
      this.handoffs.push(...tx.handoffs);
      return result;
    } finally {
      release();
    }
  }

  async read<R>(fn: (tx: Omit<Tx, "put" | "delete" | "handoff">) => R): Promise<R> {
    return fn(new MemoryTx(this.shared.tables, true));
  }

  /** One writer at a time across every handle on the same tables, like SQLite's file lock. */
  private acquire(): Promise<() => void> {
    const previous = this.shared.chain;
    let release: () => void = () => undefined;
    this.shared.chain = new Promise<void>((resolve) => {
      release = () => {
        this.shared.held = false;
        resolve();
      };
    });
    return previous.then(() => {
      this.shared.held = true;
      return release;
    });
  }

  /** A second handle on the same tables and lock, as another execution context would have. */
  fork(): MemoryStore {
    return new MemoryStore(this.options, this.shared);
  }

  get isHeld(): boolean {
    return this.shared.held;
  }

  get commitCount(): number {
    return this.shared.commits;
  }

  snapshot(): Record<string, Record<string, unknown>> {
    const out: Record<string, Record<string, unknown>> = {};
    for (const [t, m] of this.shared.tables) out[t] = Object.fromEntries([...m.entries()].map(([k, v]) => [k, cloneRow(v)]));
    return out;
  }
}

export class MemorySecretStore implements SecretStore {
  private readonly items = new Map<SecretName, Uint8Array>();
  /** Test hook: throw on the next write to simulate a crash between the two stores. */
  failNextWrite = false;

  async get(name: SecretName): Promise<Uint8Array | undefined> {
    const v = this.items.get(name);
    return v ? Uint8Array.from(v) : undefined;
  }
  async set(name: SecretName, value: Uint8Array): Promise<void> {
    if (this.failNextWrite) {
      this.failNextWrite = false;
      throw new KavachError("STORAGE_FAILURE", "secretStore", "simulated crash");
    }
    this.items.set(name, Uint8Array.from(value));
  }
  async delete(name: SecretName): Promise<void> {
    this.items.delete(name);
  }
}
