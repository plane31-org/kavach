/**
 * The client (protocol sections 13 and 14): one asynchronous object over the store, the
 * transport, the recovery provider and the reset trust. States are emitted only after the
 * corresponding durable transition.
 */
import { concat, equalBytes, fromHex, toHex } from "./bytes.js";
import { resolveAudience, type ResolvedAudience } from "./audience.js";
import { acceptSnapshot, checkMemberResolution, createCircleSnapshot, newCircleId, pinCircle, successorSnapshot, type CircleState } from "./circle.js";
import { DocumentType, buildCircleSnapshot, expectType, parseDocument, parseVaultHeader, verifyDocument, type AccountDevice, type AccountSuccession, type RecordKind } from "./codec.js";
import { randomBytes, ready, type BoxKeypair } from "./crypto.js";
import { prepareEpoch, resolvePublish, type PreparedEpoch } from "./epoch.js";
import { KavachError, isKavachError, type ErrorCode } from "./errors.js";
import { acceptCertificate, certify, deviceFromSeed, newAccountSeed, newDevice, openAccount, pinFromCertificate, type AccountPin, type DeviceKeys, type OwnAccount } from "./identity.js";
import { ensureHistoryIndex } from "./historyIndex.js";
import { ensureSlots, forgetAuthor, forgetAuthorIn, history, historyPage, newest, newestSlot, purgeHistory, receive as receiveRecord, syncStream, type HistoryEntry, type HistoryPage, type HistoryQuery, type Newest, type ReadBudget, type ReceiveResult } from "./inbox.js";
import { drain, enqueue, outboxCount, outboxCounts, purgeOutbox, type EnqueueOptions, type OutboxCounts } from "./outbox.js";
export type { EnqueueOptions } from "./outbox.js";

/** The durable record a hand-over produced; `duplicate` when an idempotency key matched an earlier one. */
export interface EnqueueResult {
  readonly recordId: Uint8Array;
  readonly duplicate: boolean;
}
import { acceptsSuccession, allowsContinuity, kindOf, validatePolicy, type ReplacementModel, type RetentionPolicy } from "./policy.js";
import { ResetTrust, type ResetTrustConfig } from "./reset.js";
import { big, circleToRow, pinToRow, rowToCircle, rowToPin, rowToPrepared, unbig } from "./rows.js";
import type { BootstrapRetryRow, CircleRow, MetaRow, PendingResetRow, ReplacementRow, SecretStore, Store, Tx, VaultRow } from "./store.js";
import { META, REVISION, STREAM, VAULT, openStore, t1Activate, t1Header, t1Secrets, t2PrepareActivation, t3ApplyChange, t3Circle, t4PersistPrepared, t5Committed, t8OwnerSnapshot, t9MarkVault, t9Vault } from "./transactions.js";
import { applySuccession, authenticateSuccession, pinnedState, recordChainIn, rootIdentityIn, rootState, sameTransition, transitionOf, validateTransition, verifyChain, type SuccessionEffect, type VerifiedLink } from "./succession.js";
import type { CircleListing, Directory, Relay, ResolvedAccount, SuccessionLink, Transport } from "./transport.js";
import { buildVault, encodeRecoveryCode, newRecoveryKey, openVault, recoverAccount, removeEntry, upsertEntry, type ProviderStatusResult, type RecoveryProvider, type VaultEntry } from "./vault.js";

/** The types of the client's queries and of `receive`, defined with the inbox. */
export type { HistoryEntry, HistoryPage, HistoryQuery, Newest, ReceiveResult } from "./inbox.js";

/** accountSeed, deviceSeed, recoveryKey, instanceId and deviceId of a pending reset, in the secret store. */
const RESET_ROOTS_BYTES = 32 * 3 + 16 + 16;

/** The vault's entries as the circle rows say they should be. Entries of circles without a row are kept. */
function reconcileEntries(entries: readonly VaultEntry[], rows: readonly CircleRow[]): VaultEntry[] {
  let out: VaultEntry[] = [...entries];
  for (const r of rows) {
    const circleId = fromHex(r.circleId);
    if (r.status === "left" || r.status === "closed") out = removeEntry(out, circleId);
    else if (r.status === "member" || r.status === "requested") out = upsertEntry(out, { circleId, ownerIdentityId: fromHex(r.ownerIdentityId), sharingEnabled: r.enabled });
  }
  return out;
}

function sameEntries(a: readonly VaultEntry[], b: readonly VaultEntry[]): boolean {
  const key = (es: readonly VaultEntry[]) => es.map((e) => `${toHex(e.circleId)}:${toHex(e.ownerIdentityId)}:${e.sharingEnabled ? 1 : 0}`).sort().join(",");
  return key(a) === key(b);
}

export type ClientStatus = "fresh" | "replacementPrepared" | "ready" | "locked" | "accountRecoveryRequired" | "activationPending" | "retired" | "paused" | "quarantined";
export type PauseReason = "sync" | "rotation" | "metadata" | "limit";

function proposalOf(row: ReplacementRow): ReplacementProposal {
  return { successionId: fromHex(row.successionId), accountName: row.accountName, accountId: fromHex(row.accountId), expectedCertificateHash: fromHex(row.expectedCertificateHash), expectedGeneration: unbig(row.expectedGeneration), certificate: fromHex(row.certificate) };
}

/** The account id a directory answer names: the root of its succession chain, else the identity of its key. */
export function resolvedAccountId(r: ResolvedAccount): Uint8Array {
  const first = r.successions?.[0];
  if (first) return expectType<AccountSuccession>(parseDocument(first.wire), DocumentType.AccountSuccession, "resolve").accountId;
  const doc = expectType<AccountDevice>(verifyDocument(r.certificate), DocumentType.AccountDevice, "resolve");
  return pinFromCertificate(doc).identityId;
}

export interface ClientState {
  readonly status: ClientStatus;
  readonly paused: PauseReason | undefined;
  /** The account id: what circles, manifests and records name. Constant across successions. */
  readonly identityId: Uint8Array | undefined;
  /** The identity of the current account key; equal to `identityId` until a succession. */
  readonly keyIdentityId: Uint8Array | undefined;
  readonly certificateHash: Uint8Array | undefined;
  readonly generation: bigint | undefined;
  readonly outbox: number;
  /** Authors whose current epoch has not yet reached this device. */
  readonly waitingFor: readonly Uint8Array[];
  readonly circles: readonly CircleSummary[];
}

/** Diagnostics: where the protocol stands on this device. Never a secret or a plaintext. */
export interface Inspection {
  readonly identityId: Uint8Array | undefined;
  readonly keyIdentityId: Uint8Array | undefined;
  /** The replacement models the profile enables; never a runtime choice. */
  readonly replacementModel: ReplacementModel;
  /** A prepared account-recovery proposal on this device, until it commits or is definitively conflicted. */
  readonly replacement: { readonly successionId: Uint8Array; readonly expectedGeneration: bigint; readonly stale: boolean; readonly conflictGeneration: bigint | undefined } | undefined;
  /** Discovery after account recovery: where it stands. */
  readonly bootstrap: { readonly cursor: string | undefined; readonly complete: boolean } | undefined;
  readonly certificateHash: Uint8Array | undefined;
  readonly generation: bigint | undefined;
  readonly desiredRevision: bigint;
  readonly paused: PauseReason | undefined;
  readonly activeEpoch: number | undefined;
  /** An epoch prepared or committed that is not active yet. */
  readonly pendingEpoch: number | undefined;
  readonly outbox: OutboxCounts;
  readonly vault: { readonly revision: bigint; readonly pending: boolean; readonly dirty: boolean } | undefined;
}

export interface CircleSummary {
  readonly circleId: Uint8Array;
  readonly ownerIdentityId: Uint8Array;
  readonly revision: bigint;
  readonly members: readonly Uint8Array[];
  readonly enabled: boolean;
  readonly status: CircleState["status"];
  readonly snapshotAgeMs: bigint;
  readonly owned: boolean;
}

export type ClientEvent =
  | { kind: "deviceChanged"; identityId: Uint8Array; generation: bigint }
  /** After a rotation, or when a sent record's acceptance is in doubt: the app may resend its current state of each kind with a slot. */
  | { kind: "refresh"; reason: string }
  | { kind: "cancelled"; recordId: Uint8Array; reason: string }
  | { kind: "queued"; recordId: Uint8Array; recordKind: RecordKind }
  | { kind: "accepted"; recordId: Uint8Array }
  /** A record was stored, received or the device's own; `tookSlot` when it became the author's newest of its kind. */
  | { kind: "recordStored"; recordKind: RecordKind; authorIdentityId: Uint8Array; recordId: Uint8Array; tookSlot: boolean }
  | { kind: "waiting"; identityId: Uint8Array }
  | { kind: "joinRequests"; circleId: Uint8Array; accountNames: readonly string[] }
  | { kind: "circleChanged"; circleId: Uint8Array; revision: bigint; status: CircleState["status"] }
  | { kind: "accountKeyChanged"; accountName: string; quarantined: boolean }
  | { kind: "securityError"; code: string; detail: string }
  | { kind: "stateChanged"; state: ClientState };

export interface OpenOptions {
  readonly accountName: string;
  readonly retentionPolicy: unknown;
  /** The platform's synced secret store for the recovery key. Required when the profile enables identity continuity; a recovery-only profile may omit it, and then has no vault backup and no recovery code. */
  readonly recoveryProvider?: RecoveryProvider;
  readonly resetTrust: ResetTrustConfig;
  readonly secretStore: SecretStore;
  readonly store: Store;
  readonly transport: Transport;
  readonly now?: () => bigint;
  /** Called when a subscriber throws. Listeners are isolated from the protocol and from each other either way. */
  readonly onListenerError?: (error: unknown, event: ClientEvent) => void;
}

export interface Client {
  readonly accountName: string;
  getState(): Promise<ClientState>;
  subscribe(listener: (event: ClientEvent) => void): () => void;
  initializeAccount(): Promise<{ identityId: Uint8Array }>;
  recoveryStatus(): Promise<ProviderStatusResult>;
  recoveryCode(): Promise<string>;
  restoreAccount(recoveryCode?: string): Promise<{ identityId: Uint8Array; generation: bigint }>;
  /**
   * Account recovery (amendment A1), on a fresh device with no secret from the old one: prepare
   * a replacement under fresh keys and return the proposal the product takes to the host's fresh
   * authentication. A second call returns the same pending proposal. The remote account is untouched.
   */
  prepareReplacement(): Promise<ReplacementProposal>;
  /**
   * Commit the prepared replacement with the host's authorization. `SUCCESSION_PENDING` means the
   * outcome is unknown and the same call is to be made again; `REPLACEMENT_CONFLICT` means the
   * account moved and the next `prepareReplacement()` starts over; `AUTHORIZATION_REQUIRED` means
   * the host refused the authorization.
   */
  completeReplacement(input: { successionId: Uint8Array; authorization: Uint8Array }): Promise<{ identityId: Uint8Array; generation: bigint }>;
  /** The key changes this device accepted for its contacts, newest first, bounded. */
  keyChanges(options?: { accountId?: Uint8Array; limit?: number }): Promise<KeyChangeEntry[]>;
  /** A durable outbound record of a declared kind; the payload is the product's bytes, never read by the SDK. */
  enqueue(kind: RecordKind, payload: Uint8Array, options?: EnqueueOptions): Promise<EnqueueResult>;
  /** One synchronisation; `options.catchUp` bounds how much of a backlog this call reads (`SyncReport.inbox.hasMore` says when to call again). */
  sync(options?: SyncOptions): Promise<SyncReport>;
  receive(wire: Uint8Array): Promise<ReceiveResult>;
  /** The first page of `historyPage`, as a list. */
  history(query?: HistoryQuery): Promise<HistoryEntry[]>;
  /** One page of history in time order with a cursor for the next; served from the index. */
  historyPage(query?: HistoryQuery): Promise<HistoryPage>;
  /** The newest history entry for an author or kind, own records and superseded ones included. */
  newestEntry(query?: Pick<HistoryQuery, "authorIdentityId" | "kind">): Promise<HistoryEntry | undefined>;
  /** The newest record of a kind from an author's current device, self included; `undefined` when none or expired. */
  newest(identityId: Uint8Array, kind: RecordKind): Promise<Newest | undefined>;
  inspect(): Promise<Inspection>;
  readonly circles: {
    create(): Promise<{ circleId: Uint8Array }>;
    requestJoin(circleId: Uint8Array, ownerIdentityId: Uint8Array, options?: { shareOnApproval?: boolean }): Promise<void>;
    approve(circleId: Uint8Array, accountName: string): Promise<{ revision: bigint }>;
    remove(circleId: Uint8Array, memberIdentityId: Uint8Array): Promise<{ revision: bigint }>;
    leave(circleId: Uint8Array): Promise<void>;
    setEnabled(circleId: Uint8Array, enabled: boolean): Promise<void>;
    closeCircle(circleId: Uint8Array): Promise<void>;
    list(): Promise<readonly CircleSummary[]>;
  };
  resetAccount(options: { confirmed: true; reauthProof?: Uint8Array }): Promise<{ identityId: Uint8Array }>;
  close(): Promise<void>;
}

export interface SyncOptions {
  /**
   * The inbox budget of this sync, shared by every stream: at most this many records
   * (default 500) and this many milliseconds of reading (default 5,000) before the sync stops
   * and reports `inbox.hasMore`, so a long backlog never holds a wake-up open. Each stream reads
   * at least one page.
   */
  readonly catchUp?: { readonly maxRecords?: number; readonly maxMs?: number };
}

export const DEFAULT_CATCH_UP = { maxRecords: 500, maxMs: 5_000 } as const;

export interface SyncReport {
  metadata: { certificates: number; snapshots: number; rotations: number; quarantined: number; resets: number; successions: number };
  epoch: "unchanged" | "prepared" | "paused" | "pending";
  outbox: { sent: number; accepted: number; cancelled: number; unknown: number; retry: number };
  /** `hasMore`: a stream still has records on the relay that this sync's budget did not reach; sync again soon. */
  inbox: { streams: number; stored: number; keyPending: number; invalid: number; acked: number; hasMore: boolean };
  purged: number;
  /** Present while account recovery discovers circles through the host: pinned, pending and failed on this sync. */
  bootstrap?: { circles: number; pending: number; failed: number };
  errors: SyncError[];
}

/** What `prepareReplacement()` returns: everything the product hands to the host for authorization. All public. */
export interface ReplacementProposal {
  readonly successionId: Uint8Array;
  readonly accountName: string;
  readonly accountId: Uint8Array;
  readonly expectedCertificateHash: Uint8Array;
  readonly expectedGeneration: bigint;
  readonly certificate: Uint8Array;
}

/** One accepted key change of a contact: a verified succession or a validated reset. */
export interface KeyChangeEntry {
  readonly accountId: Uint8Array;
  readonly accountName: string;
  readonly previousIdentityId: Uint8Array;
  readonly newIdentityId: Uint8Array;
  readonly generation: bigint;
  readonly reason: "succession" | "reset";
  readonly successionId: Uint8Array | undefined;
  readonly acceptedAt: bigint;
}

/** One failure a sync worked around: which step, the protocol code and stage, and whether the same step may succeed later unchanged. */
export interface SyncError {
  readonly operation: string;
  readonly code: ErrorCode | "ACTIVATION_PENDING" | "UNEXPECTED";
  readonly stage: string;
  readonly retryable: boolean;
  /**
   * On an `inbox` entry: the stream whose download or processing failed and its author, so the
   * host can tell which sender is affected. Identifying metadata (protocol section 14): keep it
   * local or pseudonymise it before logging.
   */
  readonly streamId?: Uint8Array;
  readonly authorIdentityId?: Uint8Array;
  /** On a `bootstrap` entry: the circle that could not be adopted on this sync; it is retried by the next. */
  readonly circleId?: Uint8Array;
}

function syncError(operation: string, e: unknown, extra: Partial<Pick<SyncError, "circleId" | "streamId" | "authorIdentityId">> = {}): SyncError {
  return e instanceof KavachError ? { operation, code: e.code, stage: e.stage, retryable: e.retryable, ...extra } : { operation, code: "UNEXPECTED", stage: operation, retryable: false, ...extra };
}

const RESET_LIST_RECHECK_MS = 86_400_000n;

export async function open(options: OpenOptions): Promise<Client> {
  await ready();
  const policy = validatePolicy(options.retentionPolicy);
  if (!options.recoveryProvider && allowsContinuity(policy)) throw new KavachError("MALFORMED", "open", "recoveryProvider is required when the profile enables identity continuity");
  const impl = new ClientImpl(options, policy);
  await impl.load();
  return impl;
}

class ClientImpl implements Client {
  readonly accountName: string;
  private readonly store: Store;
  private readonly secrets: SecretStore;
  private readonly transport: Transport;
  private readonly provider: RecoveryProvider | undefined;
  /** A vault exists only where a recovery provider does: a recovery-only profile without one has no path that reads it. */
  private get vaultEnabled(): boolean {
    return this.provider !== undefined;
  }
  private readonly now: () => bigint;
  private readonly listeners = new Set<(e: ClientEvent) => void>();
  private account: OwnAccount | undefined;
  /** Retired by a succession or a later device: nothing is written from here again. */
  private retired = false;
  private device: DeviceKeys | undefined;
  private selfPin: AccountPin | undefined;
  private trust: ResetTrust;
  private syncing: Promise<SyncReport> | undefined;
  /** The current sync's reading budget: records, and the links of a succession chain, count against it. */
  private syncBudget: ReadBudget | undefined;
  private backupChecked = false;
  readonly circles: Client["circles"];

  constructor(
    private readonly options: OpenOptions,
    private readonly policy: RetentionPolicy
  ) {
    this.accountName = options.accountName;
    this.store = options.store;
    this.secrets = options.secretStore;
    this.transport = options.transport;
    this.provider = options.recoveryProvider;
    this.now = options.now ?? ((): bigint => BigInt(Date.now()));
    this.trust = new ResetTrust(options.resetTrust);
    this.circles = {
      create: () => this.createCircle(),
      requestJoin: (c, o, opts) => this.requestJoin(c, o, opts?.shareOnApproval ?? true),
      approve: (c, n) => this.approve(c, n),
      remove: (c, m) => this.changeMembership(c, { remove: m }),
      leave: (c) => this.leave(c),
      setEnabled: (c, e) => this.setEnabled(c, e),
      closeCircle: (c) => this.closeCircle(c),
      list: () => this.listCircles()
    };
  }

  // Loading ---------------------------------------------------------------------------------------

  async load(): Promise<void> {
    await this.finishInterruptedReset();
    const opened = await openStore(this.store, this.secrets, this.accountName);
    if (opened.kind === "fresh") return;
    this.retired = opened.kind === "RETIRED";
    await ensureHistoryIndex(this.store);
    await ensureSlots(this.store, this.policy);
    this.account = opened.account;
    const deviceSeed = await this.secrets.get("deviceSeed");
    const self = await this.store.read((tx) => tx.get("self", "self"));
    if (deviceSeed && self && opened.account) {
      const accountId = opened.account.accountId;
      this.device = deviceFromSeed(deviceSeed, fromHex(self.deviceId));
      const pinRow = await this.store.read((tx) => tx.get("pins", toHex(accountId)));
      if (pinRow) this.selfPin = rowToPin(pinRow);
    }
    const rows = await this.store.read((tx) => ({
      list: tx.get("resetList", "list"),
      clock: tx.get("clock", "clock"),
      accepted: tx.list("resetReceipts").map(([k]) => k),
      events: tx.list("resetReceipts").map(([k, r]) => ({ resetId: k, accountName: r.accountName, oldIdentityId: r.oldIdentityId, newIdentityId: r.newIdentityId })),
      retired: tx.list("retiredIdentities").map(([k]) => k)
    }));
    this.trust = ResetTrust.fromRows(this.options.resetTrust, {
      list: rows.list,
      clock: rows.clock ?? { highWater: "0" },
      accepted: rows.events.map((e) => e.resetId).length ? (await this.store.read((tx) => tx.list("resetReceipts").map(([, r]) => r.receiptHash))) : [],
      events: rows.events,
      retired: rows.retired
    });
  }

  /** Each listener on its own: a throwing subscriber affects neither the other listeners nor the protocol. */
  private emit(event: ClientEvent): void {
    for (const l of this.listeners) {
      try {
        l(event);
      } catch (e) {
        try {
          this.options.onListenerError?.(e, event);
        } catch {
          /* the diagnostic hook is the application's too */
        }
      }
    }
  }

  subscribe(listener: (event: ClientEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private requireAccount(stage: string): { account: OwnAccount; device: DeviceKeys; pin: AccountPin } {
    if (this.retired) throw new KavachError("SUPERSEDED_DEVICE", stage, "this device is retired");
    if (!this.account || !this.device || !this.selfPin) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "no account on this device");
    return { account: this.account, device: this.device, pin: this.selfPin };
  }

  private selfView(): { identityId: Uint8Array; certificateHash: Uint8Array; box: BoxKeypair } {
    const { device, pin } = this.requireAccount("self");
    return { identityId: pin.accountId, certificateHash: pin.certificateHash, box: device.box };
  }

  private outboxDeps() {
    const { device, pin } = this.requireAccount("outbox");
    return {
      store: this.store,
      relay: this.transport.relay,
      policy: this.policy,
      now: this.now,
      author: () => ({ streamId: pin.streamId, signingSecretKey: device.signing.secretKey, generation: pin.generation, identityId: pin.accountId }),
      events: {
        queued: (recordId: Uint8Array, recordKind: RecordKind) => this.emit({ kind: "queued", recordId, recordKind }),
        accepted: (recordId: Uint8Array) => this.emit({ kind: "accepted", recordId }),
        cancelled: (recordId: Uint8Array, reason: string) => this.emit({ kind: "cancelled", recordId, reason }),
        refresh: (reason: string) => this.emit({ kind: "refresh", reason }),
        securityError: (code: string, detail: string) => this.emit({ kind: "securityError", code, detail })
      }
    };
  }

  private inboxDeps() {
    return {
      store: this.store,
      relay: this.transport.relay,
      policy: this.policy,
      now: this.now,
      self: () => this.selfView(),
      events: {
        received: (r: ReceiveResult) => {
          if (r.result === "updated" || r.result === "history") this.emit({ kind: "recordStored", recordKind: r.kind, authorIdentityId: r.authorIdentityId, recordId: r.recordId, tookSlot: r.result === "updated" && (kindOf(this.policy, r.kind)?.newest ?? false) });
        },
        waiting: (identityId: Uint8Array) => this.emit({ kind: "waiting", identityId }),
        securityError: (code: string, detail: string) => this.emit({ kind: "securityError", code, detail })
      }
    };
  }

  // State -----------------------------------------------------------------------------------------

  async getState(): Promise<ClientState> {
    const meta = await this.store.read((tx) => tx.get("meta", META));
    const base = { identityId: this.selfPin?.accountId, keyIdentityId: this.selfPin?.identityId, certificateHash: this.selfPin?.certificateHash, generation: this.selfPin?.generation, outbox: 0, waitingFor: [] as Uint8Array[], circles: [] as CircleSummary[] };
    if (!meta || (!this.account && meta.state !== "RETIRED")) {
      const proposal = await this.store.read((tx) => tx.get("replacement", "pending"));
      return { status: proposal && !proposal.stale ? "replacementPrepared" : "fresh", paused: undefined, ...base };
    }
    const circles = await this.listCircles();
    const outbox = await outboxCount(this.store);
    const waitingFor = await this.waitingFor();
    const revision = await this.store.read((tx) => tx.get("revision", REVISION));
    const quarantined = await this.store.read((tx) => tx.count("quarantine") > 0);
    let status: ClientStatus = "ready";
    if (meta.state === "INITIALIZING") status = "accountRecoveryRequired";
    else if (meta.state === "ACTIVATION_PENDING") status = "activationPending";
    else if (meta.state === "RETIRED") status = "retired";
    else if (revision?.paused) status = "paused";
    else if (quarantined) status = "quarantined";
    return { status, paused: revision?.paused, ...base, outbox, waitingFor, circles };
  }

  private async waitingFor(): Promise<Uint8Array[]> {
    if (!this.selfPin) return [];
    const selfHex = toHex(this.selfPin.accountId);
    return this.store.read((tx) => {
      const authors = new Set<string>();
      for (const [, c] of tx.list("circles")) if (c.status === "member") for (const m of c.members) if (m !== selfHex) authors.add(m);
      const out: Uint8Array[] = [];
      for (const a of authors) {
        const pin = tx.get("pins", a);
        if (!pin) continue;
        const hasKey = tx.list("readerEpochs", pin.streamId + ":").length > 0;
        if (!hasKey) out.push(fromHex(a));
      }
      return out;
    });
  }

  async inspect(): Promise<Inspection> {
    const now = this.now();
    return this.store.read((tx) => {
      const stream = tx.get("stream", STREAM);
      const revision = tx.get("revision", REVISION);
      const vault = tx.get("vault", VAULT);
      const meta = tx.get("meta", META);
      const proposal = tx.get("replacement", "pending");
      const pendingEpoch = tx.list("epochs").find(([, e]) => e.status === "prepared" || e.status === "committed")?.[1].epoch;
      return {
        identityId: this.selfPin?.accountId,
        keyIdentityId: this.selfPin?.identityId,
        replacementModel: this.policy.replacement,
        replacement: proposal ? { successionId: fromHex(proposal.successionId), expectedGeneration: unbig(proposal.expectedGeneration), stale: proposal.stale, conflictGeneration: proposal.conflictGeneration === undefined ? undefined : unbig(proposal.conflictGeneration) } : undefined,
        bootstrap: meta?.bootstrap ? { cursor: meta.bootstrap.cursor, complete: meta.bootstrap.complete } : undefined,
        certificateHash: this.selfPin?.certificateHash,
        generation: this.selfPin?.generation,
        desiredRevision: revision ? unbig(revision.desiredRevision) : 1n,
        paused: revision?.paused,
        activeEpoch: stream?.activeEpoch,
        pendingEpoch,
        outbox: outboxCounts(tx, now),
        vault: vault ? { revision: unbig(vault.revision), pending: vault.pending, dirty: vault.dirty } : undefined
      };
    });
  }

  // Enrollment ------------------------------------------------------------------------------------

  async initializeAccount(): Promise<{ identityId: Uint8Array }> {
    const stage = "initializeAccount";
    const opened = await openStore(this.store, this.secrets, this.accountName);
    if (opened.kind !== "fresh" && opened.kind !== "initializing") throw new KavachError("MALFORMED", stage, "an account already exists on this device");
    let accountSeed = await this.secrets.get("accountSeed");
    let deviceSeed = await this.secrets.get("deviceSeed");
    let recoveryKey = await this.secrets.get("recoveryKey");
    let instanceId = await this.secrets.get("instanceId");
    const device = deviceSeed ? deviceFromSeed(deviceSeed, (await this.store.read((tx) => tx.get("self", "self")))?.deviceId ? fromHex((await this.store.read((tx) => tx.get("self", "self")))?.deviceId ?? "") : newDevice().deviceId) : newDevice();
    if (!accountSeed || !deviceSeed || !recoveryKey || !instanceId) {
      accountSeed = newAccountSeed();
      deviceSeed = device.deviceSeed;
      recoveryKey = newRecoveryKey();
      instanceId = randomBytes(16);
      await t1Secrets(this.secrets, { accountSeed, deviceSeed, recoveryKey, instanceId });
    }
    const account = openAccount(this.accountName, accountSeed);
    const certificate = certify(account, device, 1n);
    const pin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice));
    const iid = instanceId;
    await this.store.transaction((tx) => t1Header(tx, { account, device, certificate, instanceId: iid, generation: 1n }));
    const vault = this.vaultEnabled ? buildVault({ accountName: this.accountName, accountKey: account.account.publicKey, vaultRevision: 1n }, { accountSeed, lastDeviceGeneration: 1n, lastCertificateHash: pin.certificateHash, entries: [] }, recoveryKey) : undefined;
    const outcome = await this.transport.directory.registerAccount({ certificate, vault: vault?.wire });
    if (outcome.status === "CONFLICT") {
      // A restart or a lost response after the host committed: the name is ours if the host holds
      // exactly the certificate this device saved; anything else is somebody else's account.
      const [me] = await this.transport.directory.resolveAccounts([this.accountName]);
      if (!me || !equalBytes(me.certificate, certificate)) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "an account with this name exists under another key");
    } else if (outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") {
      throw new KavachError("NOT_AUTHORIZED", stage, `host refused registration: ${outcome.status}`);
    }
    await this.store.transaction((tx) => {
      if (vault) t9Vault(tx, { revision: "1", hash: toHex(vault.hash), wire: toHex(vault.wire), pending: false, dirty: false });
      t1Activate(tx);
    });
    this.account = account;
    this.device = device;
    this.selfPin = pin;
    // The recovery key goes to the provider; enrollment never blocks on it or on the code.
    try {
      await this.provider?.save(this.accountName, pin.identityId, recoveryKey);
    } catch {
      /* status is reported by recoveryStatus() */
    }
    await this.emitState();
    return { identityId: pin.identityId };
  }

  async recoveryStatus(): Promise<ProviderStatusResult> {
    if (!this.provider) return { status: "unsupported", backupState: "unavailable", reason: "no recovery provider on a recovery-only profile" };
    return this.provider.status();
  }

  async recoveryCode(): Promise<string> {
    // A code opens a vault for identity continuity; where the profile disables that, or where no
    // vault exists, the code would open nothing and is not issued.
    if (!allowsContinuity(this.policy) || !this.vaultEnabled) throw new KavachError("NOT_AUTHORIZED", "recoveryCode", "this deployment does not restore accounts by recovery code");
    const key = await this.secrets.get("recoveryKey");
    if (!key) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", "recoveryCode");
    return encodeRecoveryCode(key);
  }

  async restoreAccount(recoveryCode?: string): Promise<{ identityId: Uint8Array; generation: bigint }> {
    const stage = "restoreAccount";
    const opened = await openStore(this.store, this.secrets, this.accountName);
    if (opened.kind === "ACTIVE" || opened.kind === "RETIRED") throw new KavachError("MALFORMED", stage, "an account already exists on this device");
    let pending: { device: DeviceKeys; instanceId: Uint8Array } | undefined;
    if (opened.kind === "ACTIVATION_PENDING") {
      const resumed = await this.resumeActivation(stage);
      if (resumed.outcome === "done") return resumed.result;
      // The host still shows the certificate we expected but refused our prepared bytes (the vault
      // moved under us): prepare again with the same device keys. Nothing was allocated remotely.
      pending = resumed;
    }
    if (!allowsContinuity(this.policy)) throw new KavachError("NOT_AUTHORIZED", stage, "this deployment replaces devices through successions, not the recovery key");
    const [resolved] = await this.transport.directory.resolveAccounts([this.accountName]);
    if (!resolved) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "unknown account");
    const current = expectType<AccountDevice>(verifyDocument(resolved.certificate), DocumentType.AccountDevice, stage);
    const vaultWire = await this.transport.directory.getVault(this.accountName);
    if (!vaultWire) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "no vault");
    const accountId = resolvedAccountId(resolved);
    const identity = pinFromCertificate(current).identityId;
    if (!this.provider) throw new KavachError("NOT_AUTHORIZED", stage, "identity continuity needs a recovery provider");
    // An account that succeeded: the served chain is verified link by link under the current list,
    // from the root to the key this device is about to hold, before anything is written.
    const verified = resolved.successions?.length ? (await this.followChain({ accountId, accountName: this.accountName, finalIdentityId: identity, firstPage: resolved.successions, next: resolved.successionsNext })).verified : [];
    const recovered = await recoverAccount({
      accountName: this.accountName,
      identityId: identity,
      accountKey: resolved.accountKey,
      vaultWire,
      provider: this.provider,
      ...(recoveryCode === undefined ? {} : { recoveryCode })
    });
    const account = openAccount(this.accountName, recovered.vault.accountSeed, accountId);
    // Fresh device keys and a fresh local store. Nothing from the old device is copied.
    const device = pending?.device ?? newDevice();
    const generation = current.generation + 1n;
    const certificate = certify(account, device, generation);
    const pin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice), undefined, accountId);
    const header = parseVaultHeader(vaultWire);
    const nextVault = buildVault(
      { accountName: this.accountName, accountKey: account.account.publicKey, vaultRevision: header.vaultRevision + 1n },
      { accountSeed: recovered.vault.accountSeed, lastDeviceGeneration: generation, lastCertificateHash: pin.certificateHash, entries: recovered.vault.entries },
      recovered.recoveryKey
    );
    const instanceId = pending?.instanceId ?? randomBytes(16);
    if (!pending) await t1Secrets(this.secrets, { accountSeed: recovered.vault.accountSeed, deviceSeed: device.deviceSeed, recoveryKey: recovered.recoveryKey, instanceId });
    await this.store.transaction((tx) => {
      t1Header(tx, { account, device, certificate, instanceId, generation });
      recordChainIn(tx, verified, this.now());
      rootIdentityIn(tx, accountId, this.accountName, resolved.rootCertificate);
      t2PrepareActivation(tx, {
        certificate: toHex(certificate),
        vault: toHex(nextVault.wire),
        vaultRevision: big(header.vaultRevision + 1n),
        expectedCertificateHash: toHex(current.bodyHash),
        expectedVaultRevision: big(header.vaultRevision),
        expectedVaultHash: toHex(header.hash)
      });
    });
    // Durable now: the device exists locally as activationPending even if the next call fails.
    this.account = account;
    this.device = device;
    this.selfPin = pin;
    const outcome = await this.transport.directory.activateDevice({
      accountName: this.accountName,
      expectedCertificateHash: current.bodyHash,
      expectedVaultRevision: header.vaultRevision,
      expectedVaultHash: header.hash,
      newCertificate: certificate,
      newVault: nextVault.wire
    });
    if (outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") {
      // Another candidate won, or the metadata moved: report it; the user may try again.
      throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, `activation ${outcome.status}`);
    }
    return this.finishActivation({ account, device, pin, vaultRevision: header.vaultRevision + 1n, vault: nextVault, entries: recovered.vault.entries, recoveryKey: recovered.recoveryKey });
  }

  /** The local half of activation, after the host committed it: no new randomness, ever. */
  private async finishActivation(input: { account: OwnAccount; device: DeviceKeys; pin: AccountPin; vaultRevision: bigint; vault: { wire: Uint8Array; hash: Uint8Array }; entries: readonly VaultEntry[]; recoveryKey: Uint8Array }): Promise<{ identityId: Uint8Array; generation: bigint }> {
    const { account, device, pin } = input;
    await this.store.transaction((tx) => {
      tx.delete("activation", "pending");
      t9Vault(tx, { revision: big(input.vaultRevision), hash: toHex(input.vault.hash), wire: toHex(input.vault.wire), pending: false, dirty: false });
      for (const e of input.entries) {
        const owned = equalBytes(e.ownerIdentityId, pin.accountId);
        const c = pinCircle(e.circleId, e.ownerIdentityId, e.sharingEnabled, owned ? "member" : "requested");
        tx.put("circles", toHex(e.circleId), circleToRow(c));
      }
      t3ApplyChange(tx, { kind: "ownActivation" });
      t1Activate(tx);
    });
    this.account = account;
    this.device = device;
    this.selfPin = pin;
    try {
      await this.provider?.save(this.accountName, pin.identityId, input.recoveryKey);
    } catch {
      /* reported by recoveryStatus() */
    }
    await this.emitState();
    return { identityId: pin.identityId, generation: pin.generation };
  }

  /**
   * A device that crashed, or lost the response, between T2 and the local acknowledgement: the
   * host is asked what it holds. Our prepared certificate there means the activation happened
   * and is finished locally; the expected old certificate means it did not, and the exact
   * prepared bytes are sent again; anything else means another candidate won. No key, device
   * id or vault is ever generated here.
   */
  private async resumeActivation(stage: string): Promise<{ outcome: "done"; result: { identityId: Uint8Array; generation: bigint } } | { outcome: "prepareAgain"; device: DeviceKeys; instanceId: Uint8Array }> {
    const row = await this.store.read((tx) => tx.get("activation", "pending"));
    if (!row) throw new KavachError("RECOVERY_REQUIRED", stage, "activation pending without its prepared bytes");
    const [accountSeed, deviceSeed, recoveryKey, instanceId] = await Promise.all([this.secrets.get("accountSeed"), this.secrets.get("deviceSeed"), this.secrets.get("recoveryKey"), this.secrets.get("instanceId")]);
    const [self, meta] = await this.store.read((tx) => [tx.get("self", "self"), tx.get("meta", META)] as const);
    if (!accountSeed || !deviceSeed || !recoveryKey || !instanceId || !self || !meta) throw new KavachError("RECOVERY_REQUIRED", stage, "activation pending without its roots");
    const accountId = fromHex(meta.accountId ?? meta.identityId);
    const account = openAccount(this.accountName, accountSeed, accountId);
    const device = deviceFromSeed(deviceSeed, fromHex(self.deviceId));
    const certificate = fromHex(row.certificate);
    const prepared = expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice, stage);
    const pin = pinFromCertificate(prepared, undefined, accountId);
    const [me] = await this.transport.directory.resolveAccounts([this.accountName]);
    if (!me) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "unknown account");
    const theirs = expectType<AccountDevice>(verifyDocument(me.certificate), DocumentType.AccountDevice, stage);
    const vaultWire = fromHex(row.vault);
    if (!equalBytes(theirs.bodyHash, prepared.bodyHash)) {
      if (toHex(theirs.bodyHash) !== row.expectedCertificateHash) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "another device activated first");
      const outcome = await this.transport.directory.activateDevice({
        accountName: this.accountName,
        expectedCertificateHash: fromHex(row.expectedCertificateHash),
        expectedVaultRevision: unbig(row.expectedVaultRevision),
        expectedVaultHash: fromHex(row.expectedVaultHash),
        newCertificate: certificate,
        newVault: vaultWire
      });
      if (outcome.status === "CONFLICT") return { outcome: "prepareAgain", device, instanceId };
      if (outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, `activation ${outcome.status}`);
    }
    const opened = openVault(vaultWire, recoveryKey, this.accountName, account.account.publicKey);
    const result = await this.finishActivation({ account, device, pin, vaultRevision: unbig(row.vaultRevision), vault: { wire: vaultWire, hash: parseVaultHeader(vaultWire).hash }, entries: opened.entries, recoveryKey });
    return { outcome: "done", result };
  }

  /**
   * Enrollment and activation hand the recovery key to the provider after their last transaction,
   * so a process that dies in between leaves the account unbacked. The first sync of each process
   * asks the provider and saves again when it has nothing for this identity.
   */
  private async ensureBackup(): Promise<void> {
    if (this.backupChecked || !this.selfPin || !this.provider) return;
    this.backupChecked = true;
    try {
      const key = await this.secrets.get("recoveryKey");
      if (!key) return;
      const have = await this.provider.load(this.accountName, this.selfPin.identityId);
      if (have.status === "unavailable") await this.provider.save(this.accountName, this.selfPin.identityId, key);
    } catch {
      /* reported by recoveryStatus() */
    }
  }

  private async emitState(): Promise<void> {
    this.emit({ kind: "stateChanged", state: await this.getState() });
  }

  // Sending ---------------------------------------------------------------------------------------

  async enqueue(kind: RecordKind, payload: Uint8Array, options: EnqueueOptions = {}): Promise<EnqueueResult> {
    const deps = this.outboxDeps();
    // A key answered before anything that may need the network: the record it names is already
    // durable, so a retry offline, or with a rotation due, returns it. The outbox checks the key
    // again inside its transaction for calls that race.
    if (options.idempotencyKey !== undefined) {
      const seen = await this.store.read((tx) => tx.get("enqueueKeys", options.idempotencyKey ?? ""));
      if (seen) return { recordId: fromHex(seen.recordId), duplicate: true };
    }
    await this.ensureEpoch();
    try {
      return this.enqueued(kind, await enqueue(deps, kind, payload, options));
    } catch (e) {
      if (isKavachError(e, "ROTATION_REQUIRED") || isKavachError(e, "COUNTER_EXHAUSTED")) {
        await this.ensureEpoch();
        const r = await enqueue(deps, kind, payload, options);
        this.emit({ kind: "refresh", reason: "rotation" });
        return this.enqueued(kind, r);
      }
      throw e;
    }
  }

  /** After commit: the device's own record is stored like any author's, so one subscription covers self and others. */
  private enqueued(kind: RecordKind, r: { recordId: Uint8Array; duplicate: boolean; own: boolean }): EnqueueResult {
    if (!r.duplicate && this.selfPin) this.emit({ kind: "recordStored", recordKind: kind, authorIdentityId: this.selfPin.accountId, recordId: r.recordId, tookSlot: r.own });
    return { recordId: r.recordId, duplicate: r.duplicate };
  }

  // Epochs ----------------------------------------------------------------------------------------

  private async currentAudience(): Promise<ResolvedAudience> {
    const { pin } = this.requireAccount("audience");
    const retired = new Set(this.trust.state.retired);
    return this.store.read((tx) => {
      // A reset retires the whole account, however many successions it went through.
      for (const [, r] of tx.list("identities")) if (r.resetAt !== undefined) retired.add(r.accountId);
      const pins = new Map(tx.list("pins").map(([k, p]) => [k, rowToPin(p)]));
      // An account whose chain this device has not finished verifying is out of every audience until it has.
      for (const [, p] of tx.list("chainProgress")) if (!p.complete) pins.delete(p.accountId);
      const circles = tx.list("circles").map(([, c]) => rowToCircle(c));
      return resolveAudience(pin, circles, pins, retired);
    });
  }

  /** Prepare, publish and promote epochs until one is active under the current revision. */
  private async ensureEpoch(): Promise<SyncReport["epoch"]> {
    const { device, pin } = this.requireAccount("epoch");
    for (let attempt = 0; attempt < 4; attempt++) {
      const stream = await this.store.read((tx) => tx.get("stream", STREAM));
      const revisionRow = await this.store.read((tx) => tx.get("revision", REVISION));
      if (!stream) throw new KavachError("RECOVERY_REQUIRED", "epoch");
      if (stream.activeEpoch !== undefined && revisionRow?.paused !== "rotation") return attempt === 0 ? "unchanged" : "prepared";
      let audience: ResolvedAudience;
      try {
        audience = await this.currentAudience();
      } catch (e) {
        if (isKavachError(e, "METADATA_REQUIRED") || isKavachError(e, "RECIPIENT_LIMIT")) {
          const reason = e.code === "METADATA_REQUIRED" ? "metadata" : "limit";
          await this.store.transaction((tx) => {
            const r = tx.get("revision", REVISION);
            if (r) tx.put("revision", REVISION, { ...r, paused: reason });
          });
          return "paused";
        }
        throw e;
      }
      let prepared: PreparedEpoch;
      if (stream.pendingEpoch !== undefined) {
        const row = await this.store.read((tx) => tx.get("epochs", String(stream.pendingEpoch)));
        if (!row) throw new KavachError("STORAGE_FAILURE", "epoch", "pending epoch row missing");
        prepared = rowToPrepared(row);
      } else {
        const revision = revisionRow ? unbig(revisionRow.desiredRevision) : 1n;
        const fresh = prepareEpoch({
          author: { identityId: pin.accountId, certificateHash: pin.certificateHash, streamId: pin.streamId, signingSecretKey: device.signing.secretKey },
          epoch: stream.highestCommittedEpoch + 1,
          createdAt: this.now(),
          audience,
          desiredRevision: revision
        });
        // Under the lock, another context may have prepared or even promoted first. One unresolved
        // epoch per stream: adopt theirs, or start over if the stream moved on.
        const adopted = await this.store.transaction((tx): PreparedEpoch | undefined => {
          const st = tx.get("stream", STREAM);
          if (!st) throw new KavachError("RECOVERY_REQUIRED", "epoch");
          if (st.pendingEpoch !== undefined) {
            const row = tx.get("epochs", String(st.pendingEpoch));
            if (!row) throw new KavachError("STORAGE_FAILURE", "epoch", "pending epoch row missing");
            return rowToPrepared(row);
          }
          if (st.highestCommittedEpoch !== stream.highestCommittedEpoch || st.activeEpoch !== undefined) return undefined;
          t4PersistPrepared(tx, fresh);
          return fresh;
        });
        if (!adopted) continue;
        prepared = adopted;
      }
      const outcome = await this.transport.relay.publishEpoch({ streamId: pin.streamId, expectedEpoch: prepared.epoch - 1, expectedHash: undefined, manifest: prepared.manifest, wraps: prepared.wraps });
      const resolution = resolvePublish(
        prepared,
        outcome.status === "CONFLICT"
          ? { status: "CONFLICT", currentEpoch: outcome.currentEpoch ?? 0, currentManifest: outcome.currentManifest }
          : { status: outcome.status === "IGNORED_OLDER" ? "RETRYABLE" : outcome.status }
      );
      if (resolution === "RETRY") return "pending";
      const promoted = await this.store.transaction((tx) => t5Committed(tx, prepared.epoch, audience.key));
      if (promoted === "PROMOTED") {
        if (attempt > 0 || stream.activeEpoch === undefined) this.emit({ kind: "refresh", reason: "rotation" });
        return "prepared";
      }
    }
    return "pending";
  }

  // Sync ------------------------------------------------------------------------------------------

  async sync(options: SyncOptions = {}): Promise<SyncReport> {
    if (this.syncing) return this.syncing;
    this.syncing = this.runSync(options).finally(() => {
      this.syncing = undefined;
    });
    return this.syncing;
  }

  private async runSync(options: SyncOptions): Promise<SyncReport> {
    const report: SyncReport = {
      metadata: { certificates: 0, snapshots: 0, rotations: 0, quarantined: 0, resets: 0, successions: 0 },
      epoch: "unchanged",
      outbox: { sent: 0, accepted: 0, cancelled: 0, unknown: 0, retry: 0 },
      inbox: { streams: 0, stored: 0, keyPending: 0, invalid: 0, acked: 0, hasMore: false },
      purged: 0,
      errors: []
    };
    this.syncBudget = {
      remainingRecords: Math.max(1, Math.floor(options.catchUp?.maxRecords ?? DEFAULT_CATCH_UP.maxRecords)),
      deadline: this.now() + BigInt(Math.max(0, Math.floor(options.catchUp?.maxMs ?? DEFAULT_CATCH_UP.maxMs)))
    };
    if (!this.selfPin) {
      // A prepared replacement whose commit this device never saw: the chain says whether it landed.
      const row = await this.store.read((tx) => tx.get("replacement", "pending"));
      if (row && !row.stale) {
        try {
          const link = await this.findOwnLink(row);
          const roots = await this.secrets.get("pendingReplacement");
          if (link && roots && roots.length === RESET_ROOTS_BYTES) await this.activateReplacement(row, roots, link.wire);
        } catch (e) {
          report.errors.push(syncError("resumeReplacement", e));
        }
      }
    }
    if (!this.account || !this.selfPin) return report;
    const meta = await this.store.read((tx) => tx.get("meta", META));
    if (!meta || meta.state === "RETIRED") return report;
    if (await this.store.read((tx) => tx.get("pendingReset", "pending"))) {
      // A reset the host may already hold: nothing else runs under the old identity.
      try {
        await this.resumeReset("sync");
      } catch (e) {
        report.errors.push(syncError("resumeReset", e));
        return report;
      }
    }
    if (meta.state === "ACTIVATION_PENDING") {
      try {
        const resumed = await this.resumeActivation("sync");
        if (resumed.outcome !== "done") {
          report.errors.push({ operation: "resumeActivation", code: "ACTIVATION_PENDING", stage: "sync", retryable: true }); // restoreAccount prepares again
          return report;
        }
      } catch (e) {
        report.errors.push(syncError("resumeActivation", e));
        return report;
      }
    } else if (meta.state !== "ACTIVE") return report;
    await this.ensureBackup();
    if (meta.bootstrap && !meta.bootstrap.complete) {
      try {
        report.bootstrap = await this.bootstrap(report, meta.bootstrap);
      } catch (e) {
        report.errors.push(syncError("bootstrap", e));
      }
    }
    try {
      await this.syncMetadata(report);
    } catch (e) {
      report.errors.push(syncError("metadata", e));
    }
    try {
      await this.pushPreferences(report);
    } catch (e) {
      report.errors.push(syncError("preference", e));
    }
    const after = await this.store.read((tx) => tx.get("meta", META));
    if (after?.state === "RETIRED") return report;
    try {
      report.epoch = await this.ensureEpoch();
    } catch (e) {
      report.errors.push(syncError("epoch", e));
    }
    try {
      report.outbox = await drain(this.outboxDeps());
    } catch (e) {
      report.errors.push(syncError("outbox", e));
    }
    let subs: Awaited<ReturnType<Relay["listSubscriptions"]>> = [];
    try {
      subs = await this.transport.relay.listSubscriptions();
    } catch (e) {
      report.errors.push(syncError("listSubscriptions", e));
    }
    // Each stream on its own: a failed download or a refused record names its stream in the report
    // and leaves the other streams to be read; a stream that failed is not counted as synced.
    // One budget spans the streams; a stream it stops early reports hasMore.
    const budget: ReadBudget = this.syncBudget;
    if (budget.remainingRecords < 1) budget.remainingRecords = 1; // every stream reads at least one page
    for (const s of subs) {
      try {
        const known = await this.store.read((tx) => tx.list("certificates").some(([, c]) => c.streamId === toHex(s.streamId)));
        if (!known) continue;
        const r = await syncStream(this.inboxDeps(), s.streamId, s.authorIdentityId, budget);
        report.inbox.streams++;
        report.inbox.stored += r.stored;
        report.inbox.keyPending += r.keyPending;
        report.inbox.invalid += r.invalid;
        if (r.acked !== undefined) report.inbox.acked++;
        if (r.hasMore) report.inbox.hasMore = true;
      } catch (e) {
        report.errors.push({ ...syncError("inbox", e), streamId: s.streamId, authorIdentityId: s.authorIdentityId });
      }
    }
    report.purged = (await purgeHistory(this.store, this.policy, this.now())) + (await purgeOutbox(this.store, this.policy, this.now()));
    await this.emitState();
    return report;
  }

  private async syncMetadata(report: SyncReport): Promise<void> {
    const { pin } = this.requireAccount("sync");
    // Own account: has this device been superseded?
    const [me] = await this.transport.directory.resolveAccounts([this.accountName]);
    if (me) {
      const theirs = expectType<AccountDevice>(verifyDocument(me.certificate), DocumentType.AccountDevice, "sync");
      if (!equalBytes(theirs.accountKey, pin.accountKey)) {
        // Our own key changed at the host. A succession from our identity, attested by an authority
        // we trust, retires this device (its key is no longer the account's); a bare key change or a
        // reset we did not make is ignored here, as before.
        if (await this.supersededBySuccession(pin, me, report)) {
          await this.retire();
          // The key itself is retired, not only the device: nothing of it stays here.
          await this.secrets.delete("accountSeed");
          this.account = undefined;
          return;
        }
      } else if (!equalBytes(theirs.bodyHash, pin.certificateHash) && theirs.generation > pin.generation) {
        await this.retire();
        return;
      }
    }
    // Reset-key list when due.
    const now = this.now();
    const due = !this.trust.fresh(now) || now - this.trust.state.timeHighWater >= RESET_LIST_RECHECK_MS;
    if (due) {
      const wire = await this.transport.directory.getResetKeyList();
      if (wire) {
        try {
          this.trust.install(wire, now);
          await this.persistTrust();
        } catch (e) {
          report.errors.push(syncError("resetKeyList", e));
        }
      }
    }
    // Unconfirmed writes of our own first: a successor snapshot the host never took, a vault update
    // it never saw. Until they land, peers read stale membership and a replacement phone a stale
    // preference.
    const pendingOwned = await this.store.read((tx) => tx.list("circles").filter(([, r]) => r.pending && r.ownerIdentityId === toHex(pin.accountId)).map(([, r]) => fromHex(r.circleId)));
    for (const circleId of pendingOwned) {
      try {
        if ((await this.publishPendingSnapshot(circleId)) === "COMMITTED") report.metadata.snapshots++;
      } catch (e) {
        report.errors.push(syncError("publishSnapshot", e));
      }
    }
    try {
      await this.syncVault();
    } catch (e) {
      report.errors.push(syncError("vault", e));
    }
    // Circles: owners we have not pinned yet, then snapshots, then members' certificates.
    const circles = await this.store.read((tx) => tx.list("circles").map(([, c]) => rowToCircle(c)));
    const unknownOwners: Uint8Array[] = [];
    for (const c of circles) {
      if (c.status === "closed" || c.status === "quarantined" || c.status === "left") continue;
      if (!equalBytes(c.ownerIdentityId, pin.accountId) && !(await this.pinFor(c.ownerIdentityId))) unknownOwners.push(c.ownerIdentityId);
    }
    if (unknownOwners.length > 0) {
      for (const r of await this.transport.directory.resolveIdentities(unknownOwners)) await this.acceptMemberCertificate(r, report);
    }
    const memberIds = new Map<string, Uint8Array>();
    for (const c of circles) {
      if (c.status === "closed" || c.status === "quarantined" || c.status === "left") continue;
      const ownerPin = equalBytes(c.ownerIdentityId, pin.accountId) ? pin : await this.pinFor(c.ownerIdentityId);
      if (!ownerPin) {
        memberIds.set(toHex(c.ownerIdentityId), c.ownerIdentityId);
        continue;
      }
      const wire = await this.transport.directory.getCircle(c.circleId);
      if (wire) {
        try {
          const r = await this.acceptSnapshotFrom(c, wire, ownerPin, now, report);
          if (r.outcome === "ACCEPTED") {
            // The row may have moved since it was read: a sharing preference, a leave or a close
            // made meanwhile wins over the fetched snapshot, and a newer snapshot already stored
            // makes this one stale.
            const committed = await this.store.transaction((tx) => {
              const row = tx.get("circles", toHex(c.circleId));
              const fresh = row ? rowToCircle(row) : c;
              if (fresh.revision >= r.state.revision) return undefined;
              const localFinal = fresh.status === "left" || fresh.status === "closed" || fresh.status === "quarantined";
              const state: CircleState = { ...r.state, enabled: fresh.enabled, status: localFinal ? fresh.status : r.state.status };
              const ch = t3Circle(tx, { ...circleToRow(state), pending: row?.pending && unbig(row.pending.revision) <= state.revision ? undefined : row?.pending }, { kind: "snapshot", circleId: c.circleId, revision: state.revision });
              return { state, rotated: ch.changed, leftNow: state.status === "left" && fresh.status !== "left" };
            });
            if (committed) {
              if (committed.rotated) report.metadata.rotations++;
              report.metadata.snapshots++;
              this.emit({ kind: "circleChanged", circleId: c.circleId, revision: committed.state.revision, status: committed.state.status });
              if (committed.leftNow) await this.onLeft(c);
              for (const m of committed.state.members) memberIds.set(toHex(m), m);
            } else for (const m of c.members) memberIds.set(toHex(m), m);
          } else for (const m of c.members) memberIds.set(toHex(m), m);
        } catch (e) {
          if (isKavachError(e, "EQUIVOCATION")) {
            await this.store.transaction((tx) => t3Circle(tx, circleToRow({ ...c, status: "quarantined" })));
            this.emit({ kind: "securityError", code: "EQUIVOCATION", detail: "two snapshots at one revision" });
          } else report.errors.push(syncError("circleSnapshot", e));
          for (const m of c.members) memberIds.set(toHex(m), m);
        }
      } else for (const m of c.members) memberIds.set(toHex(m), m);
      if (equalBytes(c.ownerIdentityId, pin.accountId) && c.status === "member") {
        const requests = await this.transport.directory.readRequests(c.circleId);
        const joins = requests.filter((r) => r.action === "join").map((r) => r.accountName);
        if (joins.length) this.emit({ kind: "joinRequests", circleId: c.circleId, accountNames: joins });
        for (const r of requests.filter((r) => r.action === "leave")) {
          const [acct] = await this.transport.directory.resolveAccounts([r.accountName]);
          if (!acct) continue;
          try {
            await this.changeMembership(c.circleId, { remove: resolvedAccountId(acct) });
          } catch (e) {
            report.errors.push(syncError("removeLeaver", e));
          }
        }
      }
    }
    memberIds.delete(toHex(pin.accountId));
    if (memberIds.size > 0) {
      const resolved = await this.transport.directory.resolveIdentities([...memberIds.values()]);
      const byIdentity = new Map<string, { accountName: string; accountKey: Uint8Array }>();
      for (const r of resolved) {
        expectType<AccountDevice>(verifyDocument(r.certificate), DocumentType.AccountDevice, "sync");
        byIdentity.set(toHex(resolvedAccountId(r)), { accountName: r.accountName, accountKey: r.accountKey });
        await this.acceptMemberCertificate(r, report);
      }
      checkMemberResolution(byIdentity);
    }
  }

  /**
   * Has the host's chain for our own account moved past our key? A valid succession from our
   * current identity means an authority replaced this account's key; the device holding the old
   * key has nothing left to say. Deferred (no fresh list, untrusted clock) and invalid
   * attestations leave the device as it is.
   */
  private async supersededBySuccession(pin: AccountPin, me: ResolvedAccount, report: SyncReport): Promise<boolean> {
    if (!me.successions?.length) return false;
    try {
      const r = await this.followChain({ accountId: pin.accountId, accountName: pin.accountName, current: pin, firstPage: me.successions, next: me.successionsNext, budget: this.syncBudget });
      return r.pin !== undefined && !equalBytes(r.pin.identityId, pin.identityId);
    } catch (e) {
      // A chain this device cannot follow for its own account is a diagnostic the product must
      // see: the host has already fenced the device, and only this report says why it still runs.
      report.errors.push(syncError("ownSuccession", e));
      return false;
    }
  }

  /**
   * Verify a snapshot under the owner's current key, or, when the owner's key changed through a
   * succession and the snapshot predates it, under the retired key it was signed with. The
   * successor republishes at the next revision; until then the older snapshot stays valid.
   */
  private async acceptSnapshotFrom(c: CircleState, wire: Uint8Array, ownerPin: AccountPin, now: bigint, report?: SyncReport, resolved = false): Promise<ReturnType<typeof acceptSnapshot>> {
    const { pin } = this.requireAccount("sync");
    // The very bytes this device already verified (a bootstrap snapshot under a key since retired)
    // are a duplicate whatever key signed them; only new bytes are verified.
    if (c.snapshot && equalBytes(c.snapshot, wire)) return { outcome: "DUPLICATE", state: c };
    try {
      return acceptSnapshot(c, wire, ownerPin.accountKey, pin.accountId, now);
    } catch (e) {
      if (!isKavachError(e, "BAD_SIGNATURE")) throw e;
      // A retired key may only vouch for a circle this device holds at revision 0 (bootstrap, first
      // contact): an established circle advances under the current owner key alone.
      const ownerHex = toHex(ownerPin.accountId);
      const retiredKeys = c.revision === 0n ? await this.store.read((tx) => tx.list("identities").flatMap(([, r]) => (r.accountId === ownerHex && r.retired && r.accountKey ? [fromHex(r.accountKey)] : []))) : [];
      for (const key of retiredKeys) {
        try {
          return acceptSnapshot(c, wire, key, pin.accountId, now);
        } catch (inner) {
          if (!isKavachError(inner, "BAD_SIGNATURE")) throw inner;
        }
      }
      // Signed by a key we do not know: the owner may have succeeded since we last resolved it.
      // The chain is verified first; only a key it produced may sign this circle.
      if (!resolved && report && !equalBytes(ownerPin.accountId, pin.accountId)) {
        const [r] = await this.transport.directory.resolveIdentities([ownerPin.accountId]);
        if (r && !equalBytes(r.accountKey, ownerPin.accountKey)) {
          await this.acceptMemberCertificate(r, report);
          const fresh = await this.pinFor(ownerPin.accountId);
          if (fresh && !equalBytes(fresh.accountKey, ownerPin.accountKey)) return this.acceptSnapshotFrom(c, wire, fresh, now, report, true);
        }
      }
      throw e;
    }
  }

  private async pinFor(accountId: Uint8Array): Promise<AccountPin | undefined> {
    const row = await this.store.read((tx) => tx.get("pins", toHex(accountId)));
    return row ? rowToPin(row) : undefined;
  }

  /**
   * The one path every succession takes (section 4, "Chains"): the policy gate first, then the
   * key list, then each link verified in order from the start identity (the pinned identity for
   * an established contact, the account id at first contact or for a restoring device), page by
   * page within the sync's budget, with the verified prefix persisted so that the next sync
   * resumes instead of starting over. Only when the chain is complete does anything move: for a
   * pinned contact every link is applied in one transaction, so no epoch is ever sealed to an
   * intermediate successor; for a first contact or a restore the verified links are returned and
   * the caller records them with the pin or the header. Any failure leaves the pin where it was.
   */
  private async followChain(input: { accountId: Uint8Array; accountName: string; current?: AccountPin; finalIdentityId?: Uint8Array; untilGeneration?: bigint; firstPage: readonly SuccessionLink[]; next: bigint | undefined; budget?: ReadBudget | undefined }): Promise<{ pin: AccountPin | undefined; verified: VerifiedLink[]; accepted: SuccessionEffect[] }> {
    const stage = "chain";
    if (!acceptsSuccession(this.policy)) throw new KavachError("UNSUPPORTED_TYPE", stage, "this deployment does not accept successions");
    const accountHex = toHex(input.accountId);
    const startIdentity = input.current?.identityId ?? input.accountId;
    await this.ensureResetList();
    // The state the chain is validated against: the pin with what this store retired, or the root.
    const current = input.current;
    let state = current ? await this.store.read((tx) => pinnedState(tx, current, this.trust)) : rootState(input.accountId, input.accountName, this.trust);
    // Reconcile first: the host serves the chain from the root, and a pinned contact already holds
    // a prefix of it. Links whose transition is on record are dropped (the same transition at a
    // recorded state; a different one is the authority signing two successors), so verification
    // starts at the pinned identity with only the transitions this device has not seen.
    const recorded = current ? await this.store.read((tx) => tx.list("successions", accountHex + ":").map(([, r]) => r)) : [];
    // The bound, applied to every page alike: links past `untilGeneration` are not this call's to
    // follow (a replacing device stops at the state its own succession left from).
    const within = (l: SuccessionLink): boolean => input.untilGeneration === undefined || expectType<AccountSuccession>(parseDocument(l.wire), DocumentType.AccountSuccession, stage).newGeneration <= input.untilGeneration;
    const unseen = (links: readonly SuccessionLink[]): SuccessionLink[] =>
      links.filter(within).filter((l) => {
        const doc = expectType<AccountSuccession>(parseDocument(l.wire), DocumentType.AccountSuccession, stage);
        const t = transitionOf(doc);
        const row = recorded.find((r) => unbig(r.previousGeneration) === t.previousGeneration && r.previousIdentityId === t.previousIdentityId);
        if (!row) return true;
        if (!sameTransition({ accountName: row.accountName, accountId: row.accountId, successionId: row.successionId, previousIdentityId: row.previousIdentityId, newIdentityId: row.newIdentityId, previousGeneration: unbig(row.previousGeneration), newGeneration: unbig(row.newGeneration), newCertificateHash: row.newCertificateHash }, t)) {
          // A different transition at a recorded state is evidence against the authority only if
          // the authority signed it: unauthenticated bytes are a bad signature, nothing more.
          authenticateSuccession(l.wire, this.trust, this.now());
          throw new KavachError("EQUIVOCATION", stage, "two successors for one account state");
        }
        return false;
      });
    const progress = await this.store.read((tx) => tx.get("chainProgress", accountHex));
    const verified: VerifiedLink[] = [];
    let cursor: bigint | undefined;
    let pending: readonly SuccessionLink[];
    // Only links this device has not recorded are verified, and only they count against the budget.
    const verifyMore = (links: readonly SuccessionLink[]): void => {
      const fresh = unseen(links);
      const r = verifyChain(fresh, { state, trust: this.trust, now: this.now() });
      verified.push(...r.links);
      state = r.state;
      if (input.budget) input.budget.remainingRecords -= fresh.length;
    };
    if (progress && progress.startIdentityId === toHex(startIdentity)) {
      // Resume at the saved cursor, however long the verified prefix is. The prefix's transitions
      // were verified when their attestations were allowed, so they are replayed through the
      // transition rules alone; their bytes are authenticated again below, and refreshed from the
      // host where a key rotation since made them stale.
      for (const l of progress.links) {
        const doc = expectType<AccountSuccession>(parseDocument(fromHex(l.wire)), DocumentType.AccountSuccession, stage);
        state = validateTransition(doc, fromHex(l.certificate), state).next;
        verified.push({ doc, wire: fromHex(l.wire), certificate: fromHex(l.certificate) });
      }
      cursor = unbig(progress.nextGeneration);
      pending = [];
    } else {
      pending = input.firstPage;
      cursor = input.next;
    }
    const persist = (): Promise<void> =>
      this.store.transaction((tx) => {
        if (cursor === undefined) tx.delete("chainProgress", accountHex);
        else tx.put("chainProgress", accountHex, { accountId: accountHex, startIdentityId: toHex(startIdentity), links: verified.map((v) => ({ wire: toHex(v.wire), certificate: toHex(v.certificate) })), nextGeneration: big(cursor), complete: false });
      });
    const reached = (): boolean => input.untilGeneration !== undefined && state.generation >= input.untilGeneration;
    verifyMore(pending);
    if (reached()) cursor = undefined;
    while (cursor !== undefined) {
      if (input.budget && (input.budget.remainingRecords <= 0 || this.now() >= input.budget.deadline)) {
        await persist();
        throw new KavachError("METADATA_REQUIRED", stage, "the chain continues past this sync's budget");
      }
      let page;
      try {
        page = await this.transport.directory.getSuccessions(input.accountId, cursor, 32);
      } catch (e) {
        await persist();
        throw e;
      }
      if (page.successions.length === 0) {
        await persist();
        throw new KavachError("METADATA_REQUIRED", stage, "the host did not finish serving the chain");
      }
      verifyMore(page.successions);
      cursor = reached() ? undefined : page.nextGeneration;
      if (cursor !== undefined) await persist();
    }
    if (input.finalIdentityId && state.identityId !== toHex(input.finalIdentityId)) throw new KavachError("SUCCESSION_BINDING", stage, "the chain does not end at the served key");
    // Every attestation under the current list before anything is recorded. A link whose signer
    // left the list since it was verified is fetched again: the host re-attests a legitimate
    // transition under a current key, and the transition must be the same one.
    for (let i = 0; i < verified.length; i++) {
      const link = verified[i];
      if (!link) continue;
      try {
        authenticateSuccession(link.wire, this.trust, this.now());
      } catch (e) {
        if (!isKavachError(e, "RESET_KEY_REVOKED")) throw e;
        const page = await this.transport.directory.getSuccessions(input.accountId, link.doc.newGeneration - 1n, 1);
        const again = page.successions[0];
        if (!again) throw e;
        const doc = authenticateSuccession(again.wire, this.trust, this.now());
        if (!sameTransition(transitionOf(doc), transitionOf(link.doc)) || !equalBytes(again.certificate, link.certificate)) throw new KavachError("EQUIVOCATION", stage, "the re-attested link is a different transition");
        verified[i] = { doc, wire: again.wire, certificate: link.certificate };
      }
    }
    if (!current) {
      if (progress) await this.store.transaction((tx) => tx.delete("chainProgress", accountHex));
      return { pin: undefined, verified, accepted: [] };
    }
    const applied = await this.store.transaction((tx) => {
      const effects: SuccessionEffect[] = [];
      let pin = current;
      for (const link of verified) {
        // A link behind the pinned key that is already on record: the pin moved past it earlier.
        if (link.doc.previousGeneration < pin.generation && tx.list("successions").some(([, s]) => s.accountId === accountHex && unbig(s.previousGeneration) === link.doc.previousGeneration)) continue;
        const e = applySuccession(tx, { wire: link.wire, newCertificate: link.certificate, policy: this.policy, trust: this.trust, now: this.now() });
        effects.push(e);
        pin = e.pin;
      }
      this.persistTrustIn(tx);
      tx.delete("chainProgress", accountHex);
      return { effects, pin };
    });
    return { pin: applied.pin, verified, accepted: applied.effects };
  }

  /** The report side of an applied chain: counters and events for every accepted link. */
  private reportAccepted(accepted: readonly SuccessionEffect[], report: SyncReport): void {
    for (const effect of accepted) {
      if (effect.outcome !== "ACCEPTED") continue;
      report.metadata.successions++;
      report.metadata.rotations++;
      this.emit({ kind: "accountKeyChanged", accountName: effect.accountName, quarantined: false });
      this.emit({ kind: "deviceChanged", identityId: effect.pin.accountId, generation: effect.pin.generation });
    }
  }

  private securityCodeOf(e: unknown): ErrorCode | undefined {
    return e instanceof KavachError && (e.code === "EQUIVOCATION" || e.code === "ROLLBACK" || e.code === "SUCCESSION_BINDING" || e.code === "DEVICE_ID_REUSED" || e.code === "SUPERSEDED_IDENTITY") ? e.code : undefined;
  }

  /** Accept a member's certificate; a changed account key is quarantined unless a succession chain or a reset receipt explains it. */
  private async acceptMemberCertificate(resolved: ResolvedAccount, report: SyncReport): Promise<void> {
    const wire = resolved.certificate;
    const resetReceipt = resolved.resetReceipt;
    const doc = expectType<AccountDevice>(verifyDocument(wire), DocumentType.AccountDevice, "sync");
    const existing = await this.store.read((tx) => tx.list("pins").find(([, p]) => p.accountName === doc.accountName)?.[1]);
    let current = existing ? rowToPin(existing) : undefined;
    const accountId = current?.accountId ?? resolvedAccountId(resolved);
    const chain = resolved.successions ?? [];
    // A served chain is followed whenever there is one, even when the served key equals the pinned
    // one: a certificate under a retired key at a higher generation must be refused as a return to
    // that identity, never accepted as a plain device change. Links already on record cost nothing.
    if (current && chain.length > 0) {
      try {
        const r = await this.followChain({ accountId, accountName: doc.accountName, current, firstPage: chain, next: resolved.successionsNext, budget: this.syncBudget });
        this.reportAccepted(r.accepted, report);
        current = r.pin;
      } catch (e) {
        report.errors.push(syncError("succession", e));
        // A deployment that refuses successions quarantines the key change below, as a bare
        // directory key change. Anything else leaves the pin where it was until the next sync.
        if (!isKavachError(e, "UNSUPPORTED_TYPE")) {
          const code = this.securityCodeOf(e);
          if (code) this.emit({ kind: "securityError", code, detail: doc.accountName });
          return;
        }
      }
      if (!current) return;
    }
    let verified: VerifiedLink[] = [];
    if (!current && chain.length > 0) {
      // A first contact with an account that went through successions: the chain is verified from
      // the root to the served key before any pin is written, under the same policy gate as for an
      // established contact. A deployment that refuses successions pins nothing and quarantines.
      try {
        verified = (await this.followChain({ accountId, accountName: doc.accountName, finalIdentityId: pinFromCertificate(doc).identityId, firstPage: chain, next: resolved.successionsNext, budget: this.syncBudget })).verified;
      } catch (e) {
        report.errors.push(syncError("succession", e));
        if (isKavachError(e, "UNSUPPORTED_TYPE")) {
          const already = await this.store.read((tx) => tx.get("quarantine", doc.accountName));
          await this.store.transaction((tx) => tx.put("quarantine", doc.accountName, { accountName: doc.accountName, certificate: toHex(wire), reason: "succession refused", at: big(this.now()) }));
          report.metadata.quarantined++;
          if (!already) this.emit({ kind: "accountKeyChanged", accountName: doc.accountName, quarantined: true });
        } else {
          const code = this.securityCodeOf(e);
          if (code) this.emit({ kind: "securityError", code, detail: doc.accountName });
        }
        return;
      }
    }
    let outcome;
    try {
      outcome = acceptCertificate(current, wire);
    } catch (e) {
      if (isKavachError(e, "ACCOUNT_KEY_CHANGED") && current) {
        await this.onKeyChanged(current, wire, resetReceipt, report);
        return;
      }
      if (e instanceof KavachError) {
        report.errors.push(syncError("certificate", e));
        if (e.code === "EQUIVOCATION" || e.code === "DEVICE_ROLLBACK" || e.code === "DEVICE_ID_REUSED") this.emit({ kind: "securityError", code: e.code, detail: doc.accountName });
        return;
      }
      throw e;
    }
    if (outcome.outcome === "DUPLICATE") return;
    const p = current ? outcome.pin : { ...outcome.pin, accountId };
    await this.store.transaction((tx) => {
      tx.put("pins", toHex(p.accountId), pinToRow(p));
      if (verified.length) {
        recordChainIn(tx, verified, this.now());
        rootIdentityIn(tx, p.accountId, p.accountName, resolved.rootCertificate);
      }
      if (!tx.get("identities", toHex(p.identityId))) {
        const last = resolved.successions?.at(-1);
        const since = last ? expectType<AccountSuccession>(parseDocument(last.wire), DocumentType.AccountSuccession, "sync").newGeneration : 1n;
        tx.put("identities", toHex(p.identityId), { accountId: toHex(p.accountId), accountName: p.accountName, accountKey: toHex(p.accountKey), sinceGeneration: big(since), retired: false });
      }
      if (outcome.previous) {
        const old = tx.get("certificates", toHex(outcome.previous.certificateHash));
        if (old) tx.put("certificates", toHex(outcome.previous.certificateHash), { ...old, current: false });
      }
      tx.put("certificates", toHex(p.certificateHash), { identityId: toHex(p.accountId), certificateHash: toHex(p.certificateHash), signingKey: toHex(p.signingKey), boxKey: toHex(p.boxKey), streamId: toHex(p.streamId), generation: big(p.generation), wire: toHex(p.certificate), current: true });
      if (outcome.rotate) {
        const ch = t3ApplyChange(tx, { kind: "deviceChanged", identityId: p.accountId, certificateHash: p.certificateHash });
        if (ch.changed) report.metadata.rotations++;
      }
    });
    report.metadata.certificates++;
    if (outcome.rotate) this.emit({ kind: "deviceChanged", identityId: p.accountId, generation: p.generation });
  }

  private async onKeyChanged(current: AccountPin, wire: Uint8Array, receipt: Uint8Array | undefined, report: SyncReport): Promise<void> {
    if (receipt) {
      try {
        const effect = this.trust.apply(receipt, wire, current.accountName, current.identityId, this.now());
        // One transaction: a receipt is never on record without the closures and rotations it
        // causes, so a restart cannot see it as a duplicate with nothing done.
        await this.store.transaction((tx) => {
          this.persistTrustIn(tx);
          if (effect.outcome === "ACCOUNT_KEY_CHANGED") this.applyResetIn(tx, current, effect.newIdentityId);
        });
        if (effect.outcome === "ACCOUNT_KEY_CHANGED") {
          report.metadata.resets++;
          this.emit({ kind: "accountKeyChanged", accountName: current.accountName, quarantined: false });
        }
        return;
      } catch (e) {
        report.errors.push(syncError("resetReceipt", e));
        if (isKavachError(e, "RESET_KEYS_REQUIRED") || isKavachError(e, "RESET_CLOCK_UNTRUSTED")) {
          // Deferred: sharing continues under the pinned key; the receipt is tried again later.
          return;
        }
      }
    }
    // A bare directory key change: quarantine the new key, keep the pin, close nothing.
    const already = await this.store.read((tx) => tx.get("quarantine", current.accountName));
    await this.store.transaction((tx) => tx.put("quarantine", current.accountName, { accountName: current.accountName, certificate: toHex(wire), reason: receipt ? "receipt rejected" : "no receipt", at: big(this.now()) }));
    report.metadata.quarantined++;
    if (!already) this.emit({ kind: "accountKeyChanged", accountName: current.accountName, quarantined: true });
  }

  /** Peers on a validated reset: stop sharing to the old identity, close its circles, rotate. */
  private applyResetIn(tx: Tx, old: AccountPin, newIdentityId: Uint8Array): void {
    const accountHex = toHex(old.accountId);
    tx.delete("pins", accountHex);
    tx.delete("quarantine", old.accountName);
    for (const [k, c] of tx.list("certificates")) if (c.identityId === accountHex) tx.put("certificates", k, { ...c, current: false });
    // Every identity of the chain is retired; the root remembers the reset, so no successor of
    // the old account is ever a recipient again.
    for (const [k, r] of tx.list("identities")) if (r.accountId === accountHex) tx.put("identities", k, k === accountHex ? { ...r, retired: true, resetAt: big(this.now()) } : { ...r, retired: true });
    for (const [k, c] of tx.list("circles")) {
      if (c.ownerIdentityId === accountHex) {
        t3Circle(tx, { ...c, status: "closed" }, { kind: "leave", circleId: fromHex(k) });
      } else if (c.members.includes(accountHex)) {
        t3ApplyChange(tx, { kind: "deviceChanged", identityId: old.accountId, certificateHash: newIdentityId });
      }
    }
    forgetAuthorIn(tx, old.accountId);
  }

  private persistTrustIn(tx: Tx): void {
    const rows = this.trust.toRows();
    if (rows.list) tx.put("resetList", "list", rows.list);
    tx.put("clock", "clock", rows.clock);
    const hashes = rows.accepted;
    for (const e of rows.events) tx.put("resetReceipts", e.resetId, { accountName: e.accountName, oldIdentityId: e.oldIdentityId, newIdentityId: e.newIdentityId, receiptHash: hashes.find((h) => h) ?? "" });
    for (const r of rows.retired) tx.put("retiredIdentities", r, { identityId: r });
  }

  private async persistTrust(): Promise<void> {
    await this.store.transaction((tx) => this.persistTrustIn(tx));
  }

  private async onLeft(c: CircleState): Promise<void> {
    // Removed from a circle: stop opening its authors unless another circle still has them.
    const { pin } = this.requireAccount("left");
    const others = await this.store.read((tx) => tx.list("circles").filter(([, x]) => x.circleId !== toHex(c.circleId) && x.status === "member").flatMap(([, x]) => x.members));
    for (const m of c.members) {
      if (equalBytes(m, pin.accountId) || others.includes(toHex(m))) continue;
      await forgetAuthor(this.store, m);
    }
  }

  private async retire(): Promise<void> {
    this.retired = true;
    await this.store.transaction((tx) => {
      const meta = tx.get("meta", META);
      if (meta) tx.put("meta", META, { ...meta, state: "RETIRED" });
      for (const [k, r] of tx.list("outbox")) if (r.status === "queued" || r.status === "inflight") tx.put("outbox", k, { ...r, wire: "", status: "cancelled", reason: "retired" });
    });
    await this.secrets.delete("deviceSeed");
    this.device = undefined;
    await this.emitState();
  }

  // Receiving and reads ---------------------------------------------------------------------------

  receive(wire: Uint8Array): Promise<ReceiveResult> {
    return receiveRecord(this.inboxDeps(), wire);
  }

  history(query?: HistoryQuery): Promise<HistoryEntry[]> {
    return history(this.store, this.policy, query);
  }

  historyPage(query?: HistoryQuery): Promise<HistoryPage> {
    return historyPage(this.store, this.policy, query);
  }

  newestEntry(query?: Pick<HistoryQuery, "authorIdentityId" | "kind">): Promise<HistoryEntry | undefined> {
    return newest(this.store, this.policy, query);
  }

  newest(identityId: Uint8Array, kind: RecordKind): Promise<Newest | undefined> {
    return newestSlot(this.store, identityId, kind, this.now());
  }

  keyChanges(options: { accountId?: Uint8Array; limit?: number } = {}): Promise<KeyChangeEntry[]> {
    const limit = Math.max(1, Math.min(500, Math.floor(options.limit ?? 50)));
    const who = options.accountId ? toHex(options.accountId) : undefined;
    return this.store.read((tx) =>
      tx
        .list("keyChanges")
        .map(([, r]) => r)
        .filter((r) => who === undefined || r.accountId === who)
        // Newest first; two changes accepted in one transaction order by generation.
        .sort((x, y) => (unbig(y.acceptedAt) > unbig(x.acceptedAt) ? 1 : unbig(y.acceptedAt) < unbig(x.acceptedAt) ? -1 : unbig(y.generation) > unbig(x.generation) ? 1 : unbig(y.generation) < unbig(x.generation) ? -1 : 0))
        .slice(0, limit)
        .map((r) => ({
          accountId: fromHex(r.accountId),
          accountName: r.accountName,
          previousIdentityId: fromHex(r.previousIdentityId),
          newIdentityId: fromHex(r.newIdentityId),
          generation: unbig(r.generation),
          reason: r.reason,
          successionId: r.successionId === undefined ? undefined : fromHex(r.successionId),
          acceptedAt: unbig(r.acceptedAt)
        }))
    );
  }



  // Circles ---------------------------------------------------------------------------------------

  private async listCircles(): Promise<CircleSummary[]> {
    const self = this.selfPin?.accountId;
    const now = this.now();
    return this.store.read((tx) =>
      tx.list("circles").map(([, r]) => {
        const c = rowToCircle(r);
        return { circleId: c.circleId, ownerIdentityId: c.ownerIdentityId, revision: c.revision, members: c.members, enabled: c.enabled, status: c.status, snapshotAgeMs: c.verifiedAt ? now - c.verifiedAt : 0n, owned: !!self && equalBytes(c.ownerIdentityId, self) };
      })
    );
  }

  /**
   * Bring the vault in line with the circle rows: the one path for every cause. A write the host
   * never confirmed is settled first (its exact bytes, else the host's verified current vault).
   * Then, while the rows are marked as changed, the vault is derived from them inside one
   * transaction, stored as prepared bytes and published. Nothing comes from a caller's view of
   * the state, so a change that landed in the rows reaches the vault however the process dies.
   */
  private async syncVault(): Promise<void> {
    if (!this.vaultEnabled) return;
    const { account, pin } = this.requireAccount("vault");
    const recoveryKey = await this.secrets.get("recoveryKey");
    const accountSeed = await this.secrets.get("accountSeed");
    if (!recoveryKey || !accountSeed) throw new KavachError("RECOVERY_REQUIRED", "vault");
    const accountKey = account.account.publicKey;
    let conflicts = 0;
    for (let round = 0; round < 8; round++) {
      const unconfirmed = await this.store.read((tx) => tx.get("vault", VAULT));
      if (unconfirmed?.pending) {
        await this.settlePendingVault(unconfirmed, recoveryKey, accountKey);
        continue;
      }
      const prepared = await this.store.transaction((tx) => {
        const row = tx.get("vault", VAULT);
        if (!row || row.pending || !row.dirty) return undefined;
        const opened = openVault(fromHex(row.wire), recoveryKey, this.accountName, accountKey);
        const entries = reconcileEntries(opened.entries, tx.list("circles").map(([, r]) => r));
        if (sameEntries(entries, opened.entries)) {
          t9Vault(tx, { ...row, dirty: false });
          return undefined;
        }
        const revision = unbig(row.revision);
        const next = buildVault({ accountName: this.accountName, accountKey, vaultRevision: revision + 1n }, { accountSeed, lastDeviceGeneration: pin.generation, lastCertificateHash: pin.certificateHash, entries }, recoveryKey);
        t9Vault(tx, { revision: big(revision + 1n), hash: toHex(next.hash), wire: toHex(next.wire), pending: true, dirty: false });
        return { wire: next.wire, hash: toHex(next.hash), expectedRevision: revision, expectedHash: fromHex(row.hash) };
      });
      if (!prepared) return;
      const outcome = await this.transport.directory.publishVault({ expectedRevision: prepared.expectedRevision, expectedHash: prepared.expectedHash, newVault: prepared.wire });
      if (outcome.status === "COMMITTED" || outcome.status === "ALREADY_COMMITTED") {
        await this.confirmVault(prepared.hash);
        continue; // a change made while publishing has marked the row again
      }
      if (outcome.status === "CONFLICT" && outcome.current) {
        if (++conflicts >= 3) break;
        await this.adoptCurrentVault(outcome.current, recoveryKey, accountKey, prepared.expectedRevision);
        continue;
      }
      throw new KavachError("STORAGE_FAILURE", "vault", `publishVault ${outcome.status}`);
    }
    throw new KavachError("STORAGE_FAILURE", "vault", "vault conflict persisted");
  }

  /** The host holds the prepared bytes with this hash: they are the committed vault now. A marker set meanwhile stays. */
  private async confirmVault(hash: string): Promise<void> {
    await this.store.transaction((tx) => {
      const row = tx.get("vault", VAULT);
      if (row?.pending && row.hash === hash) t9Vault(tx, { ...row, pending: false });
    });
  }

  /**
   * Publish the exact bytes of a vault write the host never confirmed. Either the host has them
   * now or its current vault replaces the unconfirmed one locally.
   */
  private async settlePendingVault(row: VaultRow, recoveryKey: Uint8Array, accountKey: Uint8Array): Promise<void> {
    const localRevision = unbig(row.revision) - 1n;
    const outcome = await this.transport.directory.publishVault({ expectedRevision: localRevision, expectedHash: undefined, newVault: fromHex(row.wire) });
    if (outcome.status === "COMMITTED" || outcome.status === "ALREADY_COMMITTED") return this.confirmVault(row.hash);
    if (outcome.status === "CONFLICT" && outcome.current) return this.adoptCurrentVault(outcome.current, recoveryKey, accountKey, localRevision);
    throw new KavachError("STORAGE_FAILURE", "vault", `publishVault ${outcome.status}`);
  }

  /**
   * Take the host's current vault as the local committed one. It has to open under this account's
   * recovery key, be bound to this account, and not fall behind the revision already committed
   * locally; otherwise the local copy is kept and the caller fails. The adopted vault is marked:
   * whatever the rows say and it does not is derived again on top of it.
   */
  private async adoptCurrentVault(current: Uint8Array, recoveryKey: Uint8Array, accountKey: Uint8Array, localRevision: bigint): Promise<void> {
    const { header } = openVault(current, recoveryKey, this.accountName, accountKey);
    if (header.vaultRevision < localRevision) throw new KavachError("ROLLBACK", "vault", `host vault at ${header.vaultRevision}, local at ${localRevision}`);
    const { hash } = parseVaultHeader(current);
    await this.store.transaction((tx) => t9Vault(tx, { revision: big(header.vaultRevision), hash: toHex(hash), wire: toHex(current), pending: false, dirty: true }));
  }

  private async createCircle(): Promise<{ circleId: Uint8Array }> {
    const { account, pin } = this.requireAccount("createCircle");
    const circleId = newCircleId();
    const genesis = createCircleSnapshot({ identityId: pin.accountId, accountSecretKey: account.account.secretKey }, circleId);
    const state = acceptSnapshot(pinCircle(circleId, pin.accountId, true, "member"), genesis, pin.accountKey, pin.accountId, this.now());
    if (state.outcome !== "ACCEPTED") throw new KavachError("STORAGE_FAILURE", "createCircle");
    await this.store.transaction((tx) => {
      t3Circle(tx, { ...circleToRow(state.state), pending: { snapshot: toHex(genesis), revision: "1" } });
      this.recordPreferenceIn(tx, circleId, true);
    });
    const published = await this.publishPendingSnapshot(circleId);
    if (published !== "COMMITTED") throw new KavachError("STORAGE_FAILURE", "createCircle", published);
    await this.store.transaction((tx) => {
      t3ApplyChange(tx, { kind: "join", circleId });
      t9MarkVault(tx);
    });
    await this.syncVault();
    await this.pushPreferencesQuietly();
    this.emit({ kind: "circleChanged", circleId, revision: 1n, status: "member" });
    return { circleId };
  }

  private async requestJoin(circleId: Uint8Array, ownerIdentityId: Uint8Array, shareOnApproval: boolean): Promise<void> {
    this.requireAccount("requestJoin");
    await this.store.transaction((tx) => {
      const existing = tx.get("circles", toHex(circleId));
      if (!existing || existing.status === "left") this.recordPreferenceIn(tx, circleId, shareOnApproval);
      if (!existing) t3Circle(tx, circleToRow(pinCircle(circleId, ownerIdentityId, shareOnApproval, "requested")));
      else if (existing.status === "left") {
        // An explicit rejoin: the pinned owner and the revision reached stay, so no older snapshot
        // can be served, and the new preference replaces the one the leave cleared.
        if (existing.ownerIdentityId !== toHex(ownerIdentityId)) throw new KavachError("NOT_AUTHORIZED", "requestJoin", "another owner is pinned for this circle");
        t3Circle(tx, { ...existing, status: "requested", enabled: shareOnApproval, pending: undefined });
      }
    });
    // The vault before the request: a recovering device finds the pin either way.
    await this.syncVault();
    const outcome = await this.transport.directory.requestJoin(circleId);
    if (outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") throw new KavachError("STORAGE_FAILURE", "requestJoin", outcome.status);
    await this.pushPreferencesQuietly();
  }

  /** The host's copy of a preference, best effort now and by sync later. */
  private async pushPreferencesQuietly(): Promise<void> {
    if (!acceptsSuccession(this.policy)) return;
    try {
      await this.pushPreferences();
    } catch {
      /* retried by sync */
    }
  }

  private async approve(circleId: Uint8Array, accountName: string): Promise<{ revision: bigint }> {
    const [resolved] = await this.transport.directory.resolveAccounts([accountName]);
    if (!resolved) throw new KavachError("METADATA_REQUIRED", "approve", "unknown account");
    const report: SyncReport = { metadata: { certificates: 0, snapshots: 0, rotations: 0, quarantined: 0, resets: 0, successions: 0 }, epoch: "unchanged", outbox: { sent: 0, accepted: 0, cancelled: 0, unknown: 0, retry: 0 }, inbox: { streams: 0, stored: 0, keyPending: 0, invalid: 0, acked: 0, hasMore: false }, purged: 0, errors: [] };
    await this.acceptMemberCertificate(resolved, report);
    const requester = resolvedAccountId(resolved);
    const pinned = await this.pinFor(requester);
    if (!pinned || !equalBytes(pinned.certificateHash, expectType<AccountDevice>(verifyDocument(resolved.certificate), DocumentType.AccountDevice).bodyHash)) throw new KavachError("ACCOUNT_KEY_CHANGED", "approve", "requester's key is quarantined");
    return this.changeMembership(circleId, { admit: requester });
  }

  private async changeMembership(circleId: Uint8Array, change: { admit: Uint8Array } | { remove: Uint8Array } | { close: true }): Promise<{ revision: bigint }> {
    const { account, pin } = this.requireAccount("changeMembership");
    for (let attempt = 0; attempt < 3; attempt++) {
      const row = await this.store.read((tx) => tx.get("circles", toHex(circleId)));
      if (!row) throw new KavachError("NOT_AUTHORIZED", "changeMembership", "unknown circle");
      if (row.pending) {
        // An earlier change the host never confirmed goes first; this one is built on its result.
        await this.publishPendingSnapshot(circleId);
        continue;
      }
      const state = rowToCircle(row);
      if (state.status === "closed") return { revision: state.revision };
      const successor = successorSnapshot(state, change, { identityId: pin.accountId, accountSecretKey: account.account.secretKey });
      if (!successor) {
        if (!("close" in change)) return { revision: state.revision };
        // Nobody but the owner to tell: the close is local, and the vault entry goes with it.
        await this.store.transaction((tx) => {
          const r = tx.get("circles", toHex(circleId));
          if (r) t3Circle(tx, { ...r, status: "closed", enabled: false, pending: undefined }, { kind: "leave", circleId });
          else t3ApplyChange(tx, { kind: "leave", circleId });
        });
        this.emit({ kind: "circleChanged", circleId, revision: state.revision, status: "closed" });
        await this.syncVault();
        return { revision: state.revision };
      }
      await this.store.transaction((tx) => t8OwnerSnapshot(tx, circleId, successor, state.revision + 1n, "close" in change));
      const published = await this.publishPendingSnapshot(circleId);
      if (published === "COMMITTED") return { revision: await this.store.read((tx) => unbig(tx.get("circles", toHex(circleId))?.revision ?? "0")) };
    }
    throw new KavachError("STORAGE_FAILURE", "changeMembership", "conflict persisted");
  }

  /**
   * Publish a circle's pending successor (T8) and, once the host holds it, accept it locally with
   * the revision bump, the live-pin cleanup of anyone it removed and the change event. Called by
   * the change itself and again by every sync while a successor is pending, so a change whose
   * publication failed is never left admitted-but-sharing. On CONFLICT the host's snapshot is
   * accepted and the pending successor dropped; the caller rebuilds its change on top.
   */
  private async publishPendingSnapshot(circleId: Uint8Array): Promise<"COMMITTED" | "CONFLICT" | "NONE"> {
    const stage = "publishSnapshot";
    const { pin } = this.requireAccount(stage);
    const row = await this.store.read((tx) => tx.get("circles", toHex(circleId)));
    if (!row?.pending) return "NONE";
    const pending = row.pending;
    const state = rowToCircle(row);
    const successor = fromHex(pending.snapshot);
    const expectedRevision = unbig(pending.revision) - 1n;
    const outcome = await this.transport.directory.publishOwnedCircle({ circleId, expectedRevision, expectedHash: expectedRevision === state.revision ? state.bodyHash : undefined, newSnapshot: successor });
    if (outcome.status === "COMMITTED" || outcome.status === "ALREADY_COMMITTED") {
      const accepted = acceptSnapshot(state, successor, pin.accountKey, pin.accountId, this.now());
      if (accepted.outcome !== "ACCEPTED" && accepted.outcome !== "DUPLICATE") throw new KavachError("STORAGE_FAILURE", stage, "the successor was refused locally");
      let next = pending.close ? { ...accepted.state, status: "closed" as const } : accepted.state;
      await this.store.transaction((tx) => {
        // The row may have moved while the publication was in flight (sharing disabled, the
        // circle closed): the host's answer settles membership, never the user's newer preference.
        const live = tx.get("circles", toHex(circleId));
        if (live) next = { ...next, enabled: live.enabled, status: live.status === "closed" ? "closed" : next.status };
        t3Circle(tx, { ...circleToRow(next), pending: undefined }, { kind: "snapshot", circleId, revision: next.revision });
      });
      const after = new Set(next.members.map(toHex));
      for (const m of state.members) {
        if (after.has(toHex(m)) || equalBytes(m, pin.accountId)) continue;
        const stillElsewhere = await this.store.read((tx) => tx.list("circles").some(([, c]) => c.circleId !== toHex(circleId) && c.status === "member" && c.members.includes(toHex(m))));
        if (!stillElsewhere) await forgetAuthor(this.store, m);
      }
      this.emit({ kind: "circleChanged", circleId, revision: next.revision, status: next.status });
      if (pending.close) await this.syncVault();
      return "COMMITTED";
    }
    if (outcome.status === "CONFLICT" && outcome.current) {
      const accepted = acceptSnapshot(state, outcome.current, pin.accountKey, pin.accountId, this.now());
      await this.store.transaction((tx) => t3Circle(tx, { ...circleToRow(accepted.outcome === "ACCEPTED" ? accepted.state : state), pending: undefined }));
      return "CONFLICT";
    }
    throw new KavachError("STORAGE_FAILURE", stage, outcome.status);
  }

  private async leave(circleId: Uint8Array): Promise<void> {
    const { pin } = this.requireAccount("leave");
    const row = await this.store.read((tx) => tx.get("circles", toHex(circleId)));
    if (!row) return;
    if (row.ownerIdentityId === toHex(pin.accountId)) throw new KavachError("NOT_AUTHORIZED", "leave", "the owner closes instead");
    const state = rowToCircle(row);
    await this.store.transaction((tx) => {
      t3Circle(tx, circleToRow({ ...state, enabled: false, status: "left" }), { kind: "leave", circleId });
    });
    await this.onLeft(state);
    await this.syncVault();
    await this.transport.directory.requestLeave(circleId);
    this.emit({ kind: "circleChanged", circleId, revision: state.revision, status: "left" });
  }

  private async setEnabled(circleId: Uint8Array, enabled: boolean): Promise<void> {
    const row = await this.store.read((tx) => tx.get("circles", toHex(circleId)));
    if (!row) throw new KavachError("NOT_AUTHORIZED", "setEnabled", "unknown circle");
    if (row.enabled === enabled) {
      await this.syncVault();
      return;
    }
    await this.store.transaction((tx) => {
      t3Circle(tx, { ...row, enabled }, { kind: enabled ? "enable" : "disable", circleId });
      this.recordPreferenceIn(tx, circleId, enabled);
    });
    await this.syncVault();
    await this.pushPreferencesQuietly();
  }

  /** The user's latest action on a circle's preference, with the local sequence that a host response must name to clear it. */
  private recordPreferenceIn(tx: Tx, circleId: Uint8Array, enabled: boolean): void {
    const key = toHex(circleId);
    const row = tx.get("preferences", key) ?? { circleId: key, enabled, revision: "0", pending: undefined, nextSequence: "1" };
    const sequence = row.nextSequence;
    tx.put("preferences", key, { ...row, enabled, pending: { enabled, sequence }, nextSequence: big(unbig(sequence) + 1n) });
  }

  /**
   * Send pending preference changes to the host (amendment A1, section 7). On CONFLICT the
   * device's latest persisted action wins, read from the store at retry time, and is written again
   * at the served revision; a response clears only the sequence it answered.
   */
  private async pushPreferences(report?: SyncReport): Promise<void> {
    if (!acceptsSuccession(this.policy) || !this.selfPin) return;
    const pending = await this.store.read((tx) => tx.list("preferences").filter(([, p]) => p.pending !== undefined).map(([, p]) => p.circleId));
    for (const key of pending) {
      for (let attempt = 0; attempt < 3; attempt++) {
        const row = await this.store.read((tx) => tx.get("preferences", key));
        if (!row?.pending) break;
        const sent = row.pending;
        const outcome = await this.transport.directory.setSharingPreference(fromHex(key), sent.enabled, unbig(row.revision));
        if (outcome.status === "COMMITTED" || outcome.status === "ALREADY_COMMITTED") {
          await this.store.transaction((tx) => {
            const live = tx.get("preferences", key);
            if (!live) return;
            const cleared = live.pending?.sequence === sent.sequence ? undefined : live.pending;
            // A late success for an older request never moves the revision back.
            const revision = outcome.revision > unbig(live.revision) ? big(outcome.revision) : live.revision;
            tx.put("preferences", key, { ...live, revision, pending: cleared });
          });
          break;
        }
        if (outcome.status === "CONFLICT") {
          // Adopt the served revision; the latest persisted action is re-sent against it.
          await this.store.transaction((tx) => {
            const live = tx.get("preferences", key);
            if (live) tx.put("preferences", key, { ...live, revision: big(outcome.revision) });
          });
          continue;
        }
        if (report) report.errors.push({ operation: "preference", code: outcome.status === "UNAUTHORIZED" ? "NOT_AUTHORIZED" : "NETWORK", stage: "preference", retryable: outcome.status !== "UNAUTHORIZED" });
        break;
      }
    }
  }

  /** Close: the successor names only the owner; its publication forgets the members and removes the vault entry. */
  private async closeCircle(circleId: Uint8Array): Promise<void> {
    await this.changeMembership(circleId, { close: true });
  }

  // Account recovery (amendment A1) ---------------------------------------------------------------

  async prepareReplacement(): Promise<ReplacementProposal> {
    const stage = "prepareReplacement";
    if (!acceptsSuccession(this.policy)) throw new KavachError("NOT_AUTHORIZED", stage, "this deployment does not use account recovery");
    const opened = await openStore(this.store, this.secrets, this.accountName);
    if (opened.kind !== "fresh") throw new KavachError("MALFORMED", stage, "an account already exists on this device");
    const existing = await this.store.read((tx) => tx.get("replacement", "pending"));
    const roots = await this.secrets.get("pendingReplacement");
    if (existing && !existing.stale && roots && roots.length === RESET_ROOTS_BYTES) return proposalOf(existing);
    const [resolved] = await this.transport.directory.resolveAccounts([this.accountName]);
    if (!resolved) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "unknown account");
    const current = expectType<AccountDevice>(verifyDocument(resolved.certificate), DocumentType.AccountDevice, stage);
    const accountId = resolvedAccountId(resolved);
    // Fresh roots: nothing from the old device, nothing from the host. The certificate is at the
    // next generation under the new key; the vault is fresh at revision 1 so that identity
    // continuity works on the next replacement.
    const accountSeed = newAccountSeed();
    const device = newDevice();
    const recoveryKey = newRecoveryKey();
    const instanceId = randomBytes(16);
    const successionId = randomBytes(16);
    const account = openAccount(this.accountName, accountSeed, accountId);
    const generation = current.generation + 1n;
    const certificate = certify(account, device, generation);
    const pin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice, stage), undefined, accountId);
    const vault = this.vaultEnabled ? buildVault({ accountName: this.accountName, accountKey: account.account.publicKey, vaultRevision: 1n }, { accountSeed, lastDeviceGeneration: generation, lastCertificateHash: pin.certificateHash, entries: [] }, recoveryKey) : undefined;
    // T11: roots in the secret store, the exact bytes in the store, before anything is sent.
    await this.secrets.set("pendingReplacement", concat(accountSeed, device.deviceSeed, recoveryKey, instanceId, device.deviceId));
    const row: ReplacementRow = {
      successionId: toHex(successionId),
      accountName: this.accountName,
      accountId: toHex(accountId),
      expectedCertificateHash: toHex(current.bodyHash),
      expectedGeneration: big(current.generation),
      certificate: toHex(certificate),
      vault: vault ? toHex(vault.wire) : undefined,
      vaultHash: vault ? toHex(vault.hash) : undefined,
      deviceId: toHex(device.deviceId),
      stale: false,
      conflictGeneration: undefined
    };
    await this.store.transaction((tx) => tx.put("replacement", "pending", row));
    await this.emitState();
    return proposalOf(row);
  }

  async completeReplacement(input: { successionId: Uint8Array; authorization: Uint8Array }): Promise<{ identityId: Uint8Array; generation: bigint }> {
    const stage = "completeReplacement";
    // Already activated (by an earlier call, or by a sync that found the commit on the chain): idempotent.
    if (this.selfPin && this.account && !this.retired) return { identityId: this.selfPin.identityId, generation: this.selfPin.generation };
    const row = await this.store.read((tx) => tx.get("replacement", "pending"));
    if (!row || row.successionId !== toHex(input.successionId)) throw new KavachError("MALFORMED", stage, "no such prepared replacement on this device");
    if (row.stale) throw new KavachError("REPLACEMENT_CONFLICT", stage, row.conflictGeneration === undefined ? "the account moved" : `the account is at generation ${row.conflictGeneration}`);
    const roots = await this.secrets.get("pendingReplacement");
    if (!roots || roots.length !== RESET_ROOTS_BYTES) throw new KavachError("RECOVERY_REQUIRED", stage, "replacement prepared without its roots");
    let outcome: Awaited<ReturnType<Directory["succeedAccount"]>>;
    try {
      outcome = await this.transport.directory.succeedAccount({
        accountName: this.accountName,
        expectedCertificateHash: fromHex(row.expectedCertificateHash),
        newCertificate: fromHex(row.certificate),
        newVault: row.vault === undefined ? undefined : fromHex(row.vault),
        successionId: input.successionId,
        authorization: input.authorization
      });
    } catch (e) {
      if (!isKavachError(e, "NETWORK")) throw e;
      // Unknown: the chain says whether ours committed. Never a second identity.
      const link = await this.findOwnLink(row).catch(() => undefined);
      if (!link) throw new KavachError("SUCCESSION_PENDING", stage, "the commit's outcome is unknown; call again with the same proposal");
      outcome = { status: "COMMITTED", succession: link.wire };
    }
    if (outcome.status === "CONFLICT") {
      // Definitive: the current certificate moved under the proposal, and the succession id is
      // not on the chain (that answers first). The proposal can never commit: it is marked stale
      // and its keys, never activated anywhere, are discarded.
      let current: bigint | undefined;
      try {
        current = outcome.current ? expectType<AccountDevice>(verifyDocument(outcome.current), DocumentType.AccountDevice, stage).generation : undefined;
      } catch {
        current = undefined;
      }
      await this.store.transaction((tx) => tx.put("replacement", "pending", { ...row, stale: true, conflictGeneration: current === undefined ? undefined : big(current) }));
      await this.secrets.delete("pendingReplacement");
      await this.emitState();
      throw new KavachError("REPLACEMENT_CONFLICT", stage, current === undefined ? "the account moved" : `the account is at generation ${current}`);
    }
    if (outcome.status === "UNAUTHORIZED") throw new KavachError("AUTHORIZATION_REQUIRED", stage, "the host refused the authorization; obtain a fresh one for the same proposal");
    if ((outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") || !outcome.succession) {
      throw new KavachError("SUCCESSION_PENDING", stage, `host answered ${outcome.status}`);
    }
    return this.activateReplacement(row, roots, outcome.succession);
  }

  /** Our own link on the host's chain, if the proposal committed: the one naming our succession id and certificate. */
  private async findOwnLink(row: ReplacementRow): Promise<SuccessionLink | undefined> {
    const page = await this.transport.directory.getSuccessions(fromHex(row.accountId), unbig(row.expectedGeneration), 8);
    for (const l of page.successions) {
      try {
        const doc = expectType<AccountSuccession>(parseDocument(l.wire), DocumentType.AccountSuccession, "resume");
        if (toHex(doc.successionId) === row.successionId && equalBytes(l.certificate, fromHex(row.certificate))) return l;
      } catch {
        /* not ours */
      }
    }
    return undefined;
  }

  /** The reset-key list, fetched when the one held is not fresh. */
  private async ensureResetList(): Promise<void> {
    const now = this.now();
    if (this.trust.fresh(now)) return;
    const wire = await this.transport.directory.getResetKeyList();
    if (!wire) return;
    this.trust.install(wire, now);
    await this.persistTrust();
  }

  /**
   * Activate: verify the returned succession exactly as a peer would, against the previous state
   * pinned from the host, then the T1 header under the new identity with the account id carried
   * from the proposal. A succession that does not verify leaves the proposal intact.
   */
  private async activateReplacement(row: ReplacementRow, roots: Uint8Array, succession: Uint8Array): Promise<{ identityId: Uint8Array; generation: bigint }> {
    const stage = "completeReplacement";
    await this.ensureResetList();
    const previousWire = await this.transport.directory.getCertificate(fromHex(row.expectedCertificateHash));
    if (!previousWire) throw new KavachError("METADATA_REQUIRED", stage, "the previous certificate is not served");
    const previous = expectType<AccountDevice>(verifyDocument(previousWire), DocumentType.AccountDevice, stage);
    if (toHex(previous.bodyHash) !== row.expectedCertificateHash) throw new KavachError("SUCCESSION_BINDING", stage, "the served certificate is not the expected one");
    const accountId = fromHex(row.accountId);
    const previousPin = pinFromCertificate(previous, undefined, accountId);
    // The account's earlier successions, if any: the chain from the root to the previous identity,
    // verified through the one chain path and kept, so this device holds every key the account
    // has signed with (an owned circle's snapshot from before an earlier replacement) and can
    // follow its own chain later (to learn of its retirement).
    const [me] = await this.transport.directory.resolveAccounts([this.accountName]);
    // The evidence must be there before anything is written: without the account's resolution the
    // history is unknown, not empty, and the proposal stays for the next call. An empty history is
    // right only when the previous identity is the account root.
    if (!me) throw new KavachError("METADATA_REQUIRED", stage, "the account's history is not served; the proposal stays");
    const served = me.successions ?? [];
    const ownSuccession = authenticateSuccession(succession, this.trust, this.now());
    if (served.length === 0 && me.successionsNext === undefined && !equalBytes(previousPin.identityId, accountId)) throw new KavachError("METADATA_REQUIRED", stage, "the account's earlier successions are not served; the proposal stays");
    // Bounded by the generation this device's own succession left from, on every page alike.
    const history = served.length > 0 || me.successionsNext !== undefined ? (await this.followChain({ accountId, accountName: this.accountName, finalIdentityId: previousPin.identityId, untilGeneration: ownSuccession.previousGeneration, firstPage: served, next: me.successionsNext })).verified : [];
    const accountSeed = roots.subarray(0, 32);
    const deviceSeed = roots.subarray(32, 64);
    const recoveryKey = roots.subarray(64, 96);
    const instanceId = roots.subarray(96, 112);
    const deviceId = roots.subarray(112, 128);
    const account = openAccount(this.accountName, accountSeed, accountId);
    const device = deviceFromSeed(deviceSeed, deviceId);
    const certificate = fromHex(row.certificate);
    const doc = expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice, stage);
    const pin = pinFromCertificate(doc, undefined, accountId);
    // Roots first, then the store: a crash in between leaves a device the next call finishes.
    await t1Secrets(this.secrets, { accountSeed, deviceSeed, recoveryKey, instanceId });
    await this.store.transaction((tx) => {
      // The previous state as a first contact pins it, then the succession as a peer verifies it:
      // nothing is written unless the document binds this account, this generation and this key.
      tx.put("pins", toHex(accountId), pinToRow(previousPin));
      tx.put("certificates", toHex(previousPin.certificateHash), { identityId: toHex(accountId), certificateHash: toHex(previousPin.certificateHash), signingKey: toHex(previousPin.signingKey), boxKey: toHex(previousPin.boxKey), streamId: toHex(previousPin.streamId), generation: big(previous.generation), wire: toHex(previousWire), current: true });
      recordChainIn(tx, history, this.now());
      rootIdentityIn(tx, accountId, this.accountName, me?.rootCertificate);
      const effect = applySuccession(tx, { wire: succession, newCertificate: certificate, policy: this.policy, trust: this.trust, now: this.now() });
      if (!equalBytes(effect.newIdentityId, account.identityId) || toHex(effect.accountId) !== row.accountId) throw new KavachError("SUCCESSION_BINDING", stage, "the succession does not name this device's key");
      this.persistTrustIn(tx);
      t1Header(tx, { account, device, certificate, instanceId, generation: doc.generation });
      if (row.vault !== undefined && row.vaultHash !== undefined) t9Vault(tx, { revision: "1", hash: row.vaultHash, wire: row.vault, pending: false, dirty: false });
      t3ApplyChange(tx, { kind: "ownActivation" });
      t1Activate(tx);
      const meta = tx.get("meta", META);
      if (meta) tx.put("meta", META, { ...meta, bootstrap: { complete: false } });
      tx.delete("replacement", "pending");
    });
    await this.secrets.delete("pendingReplacement");
    this.account = account;
    this.device = device;
    this.selfPin = pin;
    this.retired = false;
    try {
      await this.provider?.save(this.accountName, pin.identityId, recoveryKey);
    } catch {
      /* reported by recoveryStatus() */
    }
    await this.emitState();
    return { identityId: pin.identityId, generation: pin.generation };
  }

  /**
   * Discovery after account recovery (amendment A1, section 5): the host lists the account's
   * circles page by page; each is pinned only when its snapshot verifies under the owner's
   * verified chain and names this account as the host says. Discovery is not permission to share:
   * the circle is enabled only if the served preference says so. Never writes membership; an
   * owner's successor republishes the served snapshot at the next revision.
   */
  private async bootstrap(report: SyncReport, state: NonNullable<MetaRow["bootstrap"]>): Promise<{ circles: number; pending: number; failed: number }> {
    const out = { circles: 0, pending: 0, failed: 0 };
    // A circle that could not be adopted is kept with what the host served and retried by every
    // sync; a failure never advances past it silently, and never undoes another circle.
    let retry: BootstrapRetryRow[] = state.retry ?? [];
    let cursor = state.cursor;
    let pagesDone = state.pagesDone === true;
    const adopt = async (c: CircleListing): Promise<boolean> => {
      try {
        const r = await this.adoptListing(c, report);
        if (r === "member") out.circles++;
        else if (r === "pending") out.pending++;
        return true;
      } catch (e) {
        out.failed++;
        report.errors.push(syncError("bootstrap", e, { circleId: c.circleId }));
        return false;
      }
    };
    const save = (done: boolean): Promise<void> =>
      this.store.transaction((tx) => {
        const meta = tx.get("meta", META);
        if (!meta) return;
        const bootstrap = done && retry.length === 0 ? { complete: true } : { ...(cursor === undefined ? {} : { cursor }), complete: false, retry, pagesDone: done };
        tx.put("meta", META, { ...meta, bootstrap });
        t9MarkVault(tx);
      });
    const stillFailing: BootstrapRetryRow[] = [];
    for (const r of retry) {
      const listing: CircleListing = { circleId: fromHex(r.circleId), ownerAccountId: fromHex(r.ownerAccountId), role: r.role, snapshot: r.snapshot === undefined ? undefined : fromHex(r.snapshot), enabled: r.enabled, preferenceRevision: unbig(r.preferenceRevision) };
      if (!(await adopt(listing))) stillFailing.push(r);
    }
    retry = stillFailing;
    for (let pages = 0; !pagesDone && pages < 64; pages++) {
      let page;
      try {
        page = await this.transport.directory.listCircles(cursor);
      } catch (e) {
        // What landed stays; the cursor says where to resume on the next sync.
        report.errors.push(syncError("bootstrap", e));
        await save(false);
        return out;
      }
      for (const c of page.circles) {
        if (!(await adopt(c))) retry.push({ circleId: toHex(c.circleId), ownerAccountId: toHex(c.ownerAccountId), role: c.role, snapshot: c.snapshot === undefined ? undefined : toHex(c.snapshot), enabled: c.enabled, preferenceRevision: big(c.preferenceRevision) });
      }
      cursor = page.cursor;
      if (cursor === undefined) pagesDone = true;
      await save(pagesDone);
    }
    await save(pagesDone);
    return out;
  }

  private async adoptListing(c: CircleListing, report: SyncReport): Promise<"member" | "pending" | "skipped"> {
    const stage = "bootstrap";
    const { pin, account } = this.requireAccount(stage);
    const key = toHex(c.circleId);
    const existing = await this.store.read((tx) => tx.get("circles", key));
    if (existing && (existing.revision !== "0" || existing.status === "requested")) return "skipped"; // a restart between pages
    if (!c.snapshot) return "skipped"; // closed: nothing to pin, nothing to reopen
    const ownerIsMe = equalBytes(c.ownerAccountId, pin.accountId);
    let ownerPin = ownerIsMe ? pin : await this.pinFor(c.ownerAccountId);
    if (!ownerPin) {
      const [r] = await this.transport.directory.resolveIdentities([c.ownerAccountId]);
      if (r) await this.acceptMemberCertificate(r, report);
      ownerPin = await this.pinFor(c.ownerAccountId);
    }
    if (!ownerPin) throw new KavachError("METADATA_REQUIRED", stage, "the circle's owner cannot be resolved");
    const enabled = c.enabled === true;
    const base = pinCircle(c.circleId, c.ownerAccountId, enabled, c.role === "pending" ? "requested" : "member");
    const accepted = await this.acceptSnapshotFrom(base, c.snapshot, ownerPin, this.now());
    if (accepted.outcome !== "ACCEPTED") throw new KavachError("MALFORMED", stage, "an empty snapshot");
    let state = accepted.state;
    const named = c.role === "owner" ? equalBytes(state.ownerIdentityId, pin.accountId) : c.role === "member" ? state.members.some((m) => equalBytes(m, pin.accountId)) : true;
    if (!named) throw new KavachError("NOT_AUTHORIZED", stage, "the snapshot does not name this account as the host says");
    if (c.role === "pending") state = { ...state, status: "requested" };
    // The successor owner republishes what it was served at the next revision; the host's
    // compare-and-swap decides.
    const republish = ownerIsMe ? buildCircleSnapshot({ circleId: c.circleId, ownerIdentityId: pin.accountId, revision: state.revision + 1n, members: state.members }, account.account.secretKey) : undefined;
    await this.store.transaction((tx) => {
      const row = circleToRow(state);
      t3Circle(tx, republish ? { ...row, pending: { snapshot: toHex(republish), revision: big(state.revision + 1n) } } : row, { kind: "snapshot", circleId: c.circleId, revision: state.revision });
      if (state.status === "member") t3ApplyChange(tx, { kind: "join", circleId: c.circleId });
      tx.put("preferences", key, { circleId: key, enabled, revision: big(c.preferenceRevision), pending: undefined, nextSequence: "1" });
    });
    this.emit({ kind: "circleChanged", circleId: c.circleId, revision: state.revision, status: state.status });
    if (republish) {
      try {
        await this.publishPendingSnapshot(c.circleId);
      } catch (e) {
        report.errors.push(syncError("publishSnapshot", e));
      }
    }
    return state.status === "requested" ? "pending" : "member";
  }

  // Reset -----------------------------------------------------------------------------------------

  async resetAccount(options: { confirmed: true; reauthProof?: Uint8Array }): Promise<{ identityId: Uint8Array }> {
    const stage = "resetAccount";
    if (!options.confirmed) throw new KavachError("NOT_AUTHORIZED", stage, "reset requires confirmation");
    const { pin } = this.requireAccount(stage);
    if (await this.store.read((tx) => tx.get("pendingReset", "pending"))) return this.resumeReset(stage, options.reauthProof);
    const accountSeed = newAccountSeed();
    const account = openAccount(this.accountName, accountSeed);
    const device = newDevice();
    const certificate = certify(account, device, 1n);
    const newPin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice));
    const recoveryKey = newRecoveryKey();
    const vault = this.vaultEnabled ? buildVault({ accountName: this.accountName, accountKey: account.account.publicKey, vaultRevision: 1n }, { accountSeed, lastDeviceGeneration: 1n, lastCertificateHash: newPin.certificateHash, entries: [] }, recoveryKey) : undefined;
    const resetId = randomBytes(16);
    const instanceId = randomBytes(16);
    // Persisted before it is sent: the host may commit the new identity and the response be lost,
    // and the only keys that can continue are these. Roots in the secret store, wires in the store.
    await this.secrets.set("pendingReset", concat(accountSeed, device.deviceSeed, recoveryKey, instanceId, device.deviceId));
    await this.store.transaction((tx) => tx.put("pendingReset", "pending", { resetId: toHex(resetId), oldIdentityId: toHex(pin.identityId), certificate: toHex(certificate), vault: vault ? toHex(vault.wire) : undefined, vaultHash: vault ? toHex(vault.hash) : undefined }));
    return this.resumeReset(stage, options.reauthProof);
  }

  /** Send (or re-send) the persisted reset with its own reset id, and finish locally once the host holds it. */
  private async resumeReset(stage: string, reauthProof?: Uint8Array): Promise<{ identityId: Uint8Array }> {
    const row = await this.store.read((tx) => tx.get("pendingReset", "pending"));
    const roots = await this.secrets.get("pendingReset");
    if (!row || !roots || roots.length !== RESET_ROOTS_BYTES) throw new KavachError("RECOVERY_REQUIRED", stage, "reset pending without its roots");
    const certificate = fromHex(row.certificate);
    expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice, stage);
    const outcome = await this.transport.directory.resetAccount({ accountName: this.accountName, expectedOldIdentityId: fromHex(row.oldIdentityId), newCertificate: certificate, newVault: row.vault === undefined ? undefined : fromHex(row.vault), resetId: fromHex(row.resetId), reauthProof: reauthProof ?? new Uint8Array() });
    if ((outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") || !outcome.receipt) throw new KavachError("NOT_AUTHORIZED", stage, `host refused reset: ${outcome.status}`);
    return this.finishReset(stage, row, roots);
  }

  /**
   * The local half of a reset the host holds: the new roots, then a new store under the new
   * identity. Nothing of the old identity's keys survives. Safe to run again after a crash at
   * any point, until the pending row is gone.
   */
  private async finishReset(stage: string, row: PendingResetRow, roots: Uint8Array): Promise<{ identityId: Uint8Array }> {
    const accountSeed = roots.subarray(0, 32);
    const deviceSeed = roots.subarray(32, 64);
    const recoveryKey = roots.subarray(64, 96);
    const instanceId = roots.subarray(96, 112);
    const deviceId = roots.subarray(112, 128);
    const account = openAccount(this.accountName, accountSeed);
    const device = deviceFromSeed(deviceSeed, deviceId);
    const certificate = fromHex(row.certificate);
    const newPin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice, stage));
    await t1Secrets(this.secrets, { accountSeed, deviceSeed, recoveryKey, instanceId });
    await this.store.transaction((tx) => {
      for (const table of ["meta", "self", "pins", "certificates", "quarantine", "circles", "revision", "vault", "epochs", "stream", "outbox", "history", "historyIndex", "enqueueKeys", "newest", "successions", "identities", "keyChanges", "replacement", "preferences", "chainProgress", "readerEpochs", "subscriptions", "unresolved", "activation", "pendingReset"] as const) {
        for (const [k] of tx.list(table)) tx.delete(table, k);
      }
      t1Header(tx, { account, device, certificate, instanceId, generation: 1n });
      if (row.vault !== undefined && row.vaultHash !== undefined) t9Vault(tx, { revision: "1", hash: row.vaultHash, wire: row.vault, pending: false, dirty: false });
      t1Activate(tx);
    });
    await this.secrets.delete("pendingReset");
    this.account = account;
    this.device = device;
    this.selfPin = newPin;
    try {
      await this.provider?.save(this.accountName, newPin.identityId, recoveryKey);
    } catch {
      /* reported by recoveryStatus() */
    }
    await this.emitState();
    return { identityId: newPin.identityId };
  }

  /**
   * A reset the host committed whose local half was interrupted: the roots already name the new
   * identity while the store header still names the old one, which openStore would refuse. The
   * roots are switched only after the host confirmed, so the new identity is the one to finish.
   */
  private async finishInterruptedReset(): Promise<void> {
    const row = await this.store.read((tx) => tx.get("pendingReset", "pending"));
    if (!row) return;
    const [roots, accountSeed] = await Promise.all([this.secrets.get("pendingReset"), this.secrets.get("accountSeed")]);
    if (!roots || roots.length !== RESET_ROOTS_BYTES || !accountSeed || !equalBytes(accountSeed, roots.subarray(0, 32))) return;
    await this.finishReset("load", row, roots);
  }

  async close(): Promise<void> {
    this.listeners.clear();
  }
}

