/**
 * The client (protocol sections 13 and 14): one asynchronous object over the store, the
 * transport, the recovery provider and the reset trust. States are emitted only after the
 * corresponding durable transition.
 */
import { equalBytes, fromHex, toHex } from "./bytes.js";
import { resolveAudience, type ResolvedAudience } from "./audience.js";
import { acceptSnapshot, checkMemberResolution, createCircleSnapshot, newCircleId, pinCircle, successorSnapshot, type CircleState } from "./circle.js";
import { DocumentType, encodeLocation, expectType, parseVaultHeader, verifyDocument, type AccountDevice, type Location, type RecordKind } from "./codec.js";
import { randomBytes, ready, type BoxKeypair } from "./crypto.js";
import { prepareEpoch, resolvePublish, type PreparedEpoch } from "./epoch.js";
import { KavachError, isKavachError } from "./errors.js";
import { acceptCertificate, certify, deviceFromSeed, newAccountSeed, newDevice, openAccount, pinFromCertificate, type AccountPin, type DeviceKeys, type OwnAccount } from "./identity.js";
import { forgetAuthor, history, latest, purgeHistory, receive as receiveRecord, syncStream, type HistoryEntry, type HistoryQuery, type Latest, type ReceiveResult } from "./inbox.js";
import { drain, enqueue, outboxCount } from "./outbox.js";
import { validatePolicy, type RetentionPolicy } from "./policy.js";
import { ResetTrust, type ResetTrustConfig } from "./reset.js";
import { big, circleToRow, pinToRow, rowToCircle, rowToPin, rowToPrepared, unbig } from "./rows.js";
import type { SecretStore, Store } from "./store.js";
import { META, REVISION, STREAM, VAULT, openStore, t1Activate, t1Header, t1Secrets, t2PrepareActivation, t3ApplyChange, t4PersistPrepared, t5Committed, t8OwnerSnapshot, t9Vault } from "./transactions.js";
import type { Transport, TransportHint } from "./transport.js";
import { buildVault, encodeRecoveryCode, newRecoveryKey, recoverAccount, removeEntry, upsertEntry, type ProviderStatusResult, type RecoveryProvider, type VaultEntry } from "./vault.js";

export type ClientStatus = "fresh" | "ready" | "locked" | "accountRecoveryRequired" | "activationPending" | "retired" | "paused" | "quarantined";
export type PauseReason = "sync" | "rotation" | "metadata" | "limit";

export interface ClientState {
  readonly status: ClientStatus;
  readonly paused: PauseReason | undefined;
  readonly identityId: Uint8Array | undefined;
  readonly certificateHash: Uint8Array | undefined;
  readonly generation: bigint | undefined;
  readonly outbox: number;
  /** Authors whose current epoch has not yet reached this device. */
  readonly waitingFor: readonly Uint8Array[];
  readonly circles: readonly CircleSummary[];
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
  | { kind: "needsLocation"; reason: string }
  | { kind: "cancelled"; recordId: Uint8Array; reason: string }
  | { kind: "queued"; recordId: Uint8Array; recordKind: RecordKind }
  | { kind: "accepted"; recordId: Uint8Array }
  | { kind: "latestUpdated"; identityId: Uint8Array }
  | { kind: "checkIn"; identityId: Uint8Array; recordId: Uint8Array }
  | { kind: "waiting"; identityId: Uint8Array }
  | { kind: "joinRequests"; circleId: Uint8Array; accountNames: readonly string[] }
  | { kind: "circleChanged"; circleId: Uint8Array; revision: bigint; status: CircleState["status"] }
  | { kind: "accountKeyChanged"; accountName: string; quarantined: boolean }
  | { kind: "securityError"; code: string; detail: string }
  | { kind: "stateChanged"; state: ClientState };

export interface OpenOptions {
  readonly accountName: string;
  readonly retentionPolicy: unknown;
  readonly recoveryProvider: RecoveryProvider;
  readonly resetTrust: ResetTrustConfig;
  readonly secretStore: SecretStore;
  readonly store: Store;
  readonly transport: Transport;
  readonly now?: () => bigint;
}

export interface Client {
  readonly accountName: string;
  getState(): Promise<ClientState>;
  subscribe(listener: (event: ClientEvent) => void): () => void;
  initializeAccount(): Promise<{ identityId: Uint8Array }>;
  recoveryStatus(): Promise<ProviderStatusResult>;
  recoveryCode(): Promise<string>;
  restoreAccount(recoveryCode?: string): Promise<{ identityId: Uint8Array; generation: bigint }>;
  enqueueLocation(location: Location): Promise<{ recordId: Uint8Array }>;
  enqueueCheckIn(payload: Location | Uint8Array): Promise<{ recordId: Uint8Array }>;
  enqueue(payload: Uint8Array): Promise<{ recordId: Uint8Array }>;
  sync(): Promise<SyncReport>;
  receive(wire: Uint8Array): Promise<ReceiveResult>;
  history(query?: HistoryQuery): Promise<HistoryEntry[]>;
  latest(identityId: Uint8Array): Promise<Latest | undefined>;
  inspect(): Promise<{ identityId: Uint8Array | undefined; certificateHash: Uint8Array | undefined; generation: bigint | undefined; desiredRevision: bigint; activeEpoch: number | undefined }>;
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

export interface SyncReport {
  metadata: { certificates: number; snapshots: number; rotations: number; quarantined: number; resets: number };
  epoch: "unchanged" | "prepared" | "paused" | "pending";
  outbox: { sent: number; accepted: number; cancelled: number; unknown: number; retry: number };
  inbox: { streams: number; stored: number; keyPending: number; acked: number };
  purged: number;
  errors: string[];
}

const RESET_LIST_RECHECK_MS = 86_400_000n;

export async function open(options: OpenOptions): Promise<Client> {
  await ready();
  const policy = validatePolicy(options.retentionPolicy);
  const impl = new ClientImpl(options, policy);
  await impl.load();
  return impl;
}

class ClientImpl implements Client {
  readonly accountName: string;
  private readonly store: Store;
  private readonly secrets: SecretStore;
  private readonly transport: Transport;
  private readonly provider: RecoveryProvider;
  private readonly now: () => bigint;
  private readonly listeners = new Set<(e: ClientEvent) => void>();
  private account: OwnAccount | undefined;
  private device: DeviceKeys | undefined;
  private selfPin: AccountPin | undefined;
  private trust: ResetTrust;
  private syncing: Promise<SyncReport> | undefined;
  private metadataDirty = true;
  private unobserve: (() => void) | undefined;
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
    const opened = await openStore(this.store, this.secrets, this.accountName);
    if (opened.kind === "fresh") return;
    this.account = opened.account;
    const deviceSeed = await this.secrets.get("deviceSeed");
    const self = await this.store.read((tx) => tx.get("self", "self"));
    if (deviceSeed && self) {
      this.device = deviceFromSeed(deviceSeed, fromHex(self.deviceId));
      const pinRow = await this.store.read((tx) => tx.get("pins", toHex(opened.account.identityId)));
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
    this.unobserve = this.transport.observe((h: TransportHint) => {
      if (h === "metadataChanged" || h === "resume" || h === "online") this.metadataDirty = true;
    });
  }

  private emit(event: ClientEvent): void {
    for (const l of this.listeners) l(event);
  }

  subscribe(listener: (event: ClientEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private requireAccount(stage: string): { account: OwnAccount; device: DeviceKeys; pin: AccountPin } {
    if (!this.account || !this.device || !this.selfPin) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "no account on this device");
    return { account: this.account, device: this.device, pin: this.selfPin };
  }

  private selfView(): { identityId: Uint8Array; certificateHash: Uint8Array; box: BoxKeypair } {
    const { device, pin } = this.requireAccount("self");
    return { identityId: pin.identityId, certificateHash: pin.certificateHash, box: device.box };
  }

  private outboxDeps() {
    const { device, pin } = this.requireAccount("outbox");
    return {
      store: this.store,
      relay: this.transport.relay,
      policy: this.policy,
      now: this.now,
      author: () => ({ streamId: pin.streamId, signingSecretKey: device.signing.secretKey, generation: pin.generation, identityId: pin.identityId }),
      events: {
        queued: (recordId: Uint8Array, recordKind: RecordKind) => this.emit({ kind: "queued", recordId, recordKind }),
        accepted: (recordId: Uint8Array) => this.emit({ kind: "accepted", recordId }),
        cancelled: (recordId: Uint8Array, reason: string) => this.emit({ kind: "cancelled", recordId, reason }),
        needsLocation: (reason: string) => this.emit({ kind: "needsLocation", reason }),
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
          if (r.result === "updated" && r.kind === 0) this.emit({ kind: "latestUpdated", identityId: r.authorIdentityId });
          if (r.result === "updated" && r.kind === 1) this.emit({ kind: "checkIn", identityId: r.authorIdentityId, recordId: r.recordId });
        },
        waiting: (identityId: Uint8Array) => this.emit({ kind: "waiting", identityId }),
        securityError: (code: string, detail: string) => this.emit({ kind: "securityError", code, detail })
      }
    };
  }

  // State -----------------------------------------------------------------------------------------

  async getState(): Promise<ClientState> {
    const meta = await this.store.read((tx) => tx.get("meta", META));
    const base = { identityId: this.selfPin?.identityId, certificateHash: this.selfPin?.certificateHash, generation: this.selfPin?.generation, outbox: 0, waitingFor: [] as Uint8Array[], circles: [] as CircleSummary[] };
    if (!meta || !this.account) return { status: "fresh", paused: undefined, ...base };
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
    const selfHex = toHex(this.selfPin.identityId);
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

  async inspect() {
    const [stream, revision] = await this.store.read((tx) => [tx.get("stream", STREAM), tx.get("revision", REVISION)] as const);
    return {
      identityId: this.selfPin?.identityId,
      certificateHash: this.selfPin?.certificateHash,
      generation: this.selfPin?.generation,
      desiredRevision: revision ? unbig(revision.desiredRevision) : 1n,
      activeEpoch: stream?.activeEpoch
    };
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
    const vault = buildVault({ accountName: this.accountName, accountKey: account.account.publicKey, vaultRevision: 1n }, { accountSeed, lastDeviceGeneration: 1n, lastCertificateHash: pin.certificateHash, entries: [] }, recoveryKey);
    const outcome = await this.transport.directory.registerAccount({ certificate, vault: vault.wire });
    if (outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") throw new KavachError("NOT_AUTHORIZED", stage, `host refused registration: ${outcome.status}`);
    await this.store.transaction((tx) => {
      t9Vault(tx, { revision: "1", hash: toHex(vault.hash), wire: toHex(vault.wire), pending: false });
      t1Activate(tx);
    });
    this.account = account;
    this.device = device;
    this.selfPin = pin;
    // The recovery key goes to the provider; enrollment never blocks on it or on the code.
    try {
      await this.provider.save(this.accountName, pin.identityId, recoveryKey);
    } catch {
      /* status is reported by recoveryStatus() */
    }
    this.unobserve ??= this.transport.observe((h) => {
      if (h === "metadataChanged" || h === "resume" || h === "online") this.metadataDirty = true;
    });
    await this.emitState();
    return { identityId: pin.identityId };
  }

  async recoveryStatus(): Promise<ProviderStatusResult> {
    return this.provider.status();
  }

  async recoveryCode(): Promise<string> {
    const key = await this.secrets.get("recoveryKey");
    if (!key) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", "recoveryCode");
    return encodeRecoveryCode(key);
  }

  async restoreAccount(recoveryCode?: string): Promise<{ identityId: Uint8Array; generation: bigint }> {
    const stage = "restoreAccount";
    const opened = await openStore(this.store, this.secrets, this.accountName);
    if (opened.kind === "ACTIVE" || opened.kind === "RETIRED") throw new KavachError("MALFORMED", stage, "an account already exists on this device");
    const [resolved] = await this.transport.directory.resolveAccounts([this.accountName]);
    if (!resolved) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "unknown account");
    const current = expectType<AccountDevice>(verifyDocument(resolved.certificate), DocumentType.AccountDevice, stage);
    const vaultWire = await this.transport.directory.getVault(this.accountName);
    if (!vaultWire) throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, "no vault");
    const identity = pinFromCertificate(current).identityId;
    const recovered = await recoverAccount({
      accountName: this.accountName,
      identityId: identity,
      accountKey: resolved.accountKey,
      vaultWire,
      provider: this.provider,
      ...(recoveryCode === undefined ? {} : { recoveryCode })
    });
    const account = openAccount(this.accountName, recovered.vault.accountSeed);
    // Fresh device keys and a fresh local store. Nothing from the old device is copied.
    const device = newDevice();
    const generation = current.generation + 1n;
    const certificate = certify(account, device, generation);
    const pin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice));
    const header = parseVaultHeader(vaultWire);
    const nextVault = buildVault(
      { accountName: this.accountName, accountKey: account.account.publicKey, vaultRevision: header.vaultRevision + 1n },
      { accountSeed: recovered.vault.accountSeed, lastDeviceGeneration: generation, lastCertificateHash: pin.certificateHash, entries: recovered.vault.entries },
      recovered.recoveryKey
    );
    const instanceId = randomBytes(16);
    await t1Secrets(this.secrets, { accountSeed: recovered.vault.accountSeed, deviceSeed: device.deviceSeed, recoveryKey: recovered.recoveryKey, instanceId });
    await this.store.transaction((tx) => {
      t1Header(tx, { account, device, certificate, instanceId, generation });
      t2PrepareActivation(tx, {
        certificate: toHex(certificate),
        vault: toHex(nextVault.wire),
        vaultRevision: big(header.vaultRevision + 1n),
        expectedCertificateHash: toHex(current.bodyHash),
        expectedVaultRevision: big(header.vaultRevision),
        expectedVaultHash: toHex(header.hash)
      });
    });
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
    await this.store.transaction((tx) => {
      tx.delete("activation", "pending");
      t9Vault(tx, { revision: big(header.vaultRevision + 1n), hash: toHex(nextVault.hash), wire: toHex(nextVault.wire), pending: false });
      for (const e of recovered.vault.entries) {
        const owned = equalBytes(e.ownerIdentityId, pin.identityId);
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
      await this.provider.save(this.accountName, pin.identityId, recovered.recoveryKey);
    } catch {
      /* reported by recoveryStatus() */
    }
    this.unobserve ??= this.transport.observe((h) => {
      if (h === "metadataChanged" || h === "resume" || h === "online") this.metadataDirty = true;
    });
    this.metadataDirty = true;
    await this.emitState();
    return { identityId: pin.identityId, generation };
  }

  private async emitState(): Promise<void> {
    this.emit({ kind: "stateChanged", state: await this.getState() });
  }

  // Sending ---------------------------------------------------------------------------------------

  async enqueueLocation(location: Location): Promise<{ recordId: Uint8Array }> {
    return this.enqueueKind(0, encodeLocation(location));
  }

  async enqueueCheckIn(payload: Location | Uint8Array): Promise<{ recordId: Uint8Array }> {
    return this.enqueueKind(1, payload instanceof Uint8Array ? payload : encodeLocation(payload));
  }

  async enqueue(payload: Uint8Array): Promise<{ recordId: Uint8Array }> {
    return this.enqueueKind(1, payload);
  }

  private async enqueueKind(kind: RecordKind, payload: Uint8Array): Promise<{ recordId: Uint8Array }> {
    const deps = this.outboxDeps();
    await this.ensureEpoch();
    try {
      const r = await enqueue(deps, kind, payload);
      return { recordId: r.recordId };
    } catch (e) {
      if (isKavachError(e, "ROTATION_REQUIRED") || isKavachError(e, "COUNTER_EXHAUSTED")) {
        await this.ensureEpoch();
        const r = await enqueue(deps, kind, payload);
        this.emit({ kind: "needsLocation", reason: "rotation" });
        return { recordId: r.recordId };
      }
      throw e;
    }
  }

  // Epochs ----------------------------------------------------------------------------------------

  private async currentAudience(): Promise<ResolvedAudience> {
    const { pin } = this.requireAccount("audience");
    const retired = new Set(this.trust.state.retired);
    return this.store.read((tx) => {
      const pins = new Map(tx.list("pins").map(([k, p]) => [k, rowToPin(p)]));
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
        prepared = prepareEpoch({
          author: { identityId: pin.identityId, certificateHash: pin.certificateHash, streamId: pin.streamId, signingSecretKey: device.signing.secretKey },
          epoch: stream.highestCommittedEpoch + 1,
          createdAt: this.now(),
          audience,
          desiredRevision: revision
        });
        await this.store.transaction((tx) => t4PersistPrepared(tx, prepared));
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
        if (attempt > 0 || stream.activeEpoch === undefined) this.emit({ kind: "needsLocation", reason: "rotation" });
        return "prepared";
      }
    }
    return "pending";
  }

  // Sync ------------------------------------------------------------------------------------------

  async sync(): Promise<SyncReport> {
    if (this.syncing) return this.syncing;
    this.syncing = this.runSync().finally(() => {
      this.syncing = undefined;
    });
    return this.syncing;
  }

  private async runSync(): Promise<SyncReport> {
    const report: SyncReport = {
      metadata: { certificates: 0, snapshots: 0, rotations: 0, quarantined: 0, resets: 0 },
      epoch: "unchanged",
      outbox: { sent: 0, accepted: 0, cancelled: 0, unknown: 0, retry: 0 },
      inbox: { streams: 0, stored: 0, keyPending: 0, acked: 0 },
      purged: 0,
      errors: []
    };
    if (!this.account || !this.selfPin) return report;
    const meta = await this.store.read((tx) => tx.get("meta", META));
    if (!meta || meta.state === "RETIRED") return report;
    try {
      await this.syncMetadata(report);
    } catch (e) {
      report.errors.push(e instanceof KavachError ? `${e.code}@${e.stage}` : String(e));
    }
    const after = await this.store.read((tx) => tx.get("meta", META));
    if (after?.state === "RETIRED") return report;
    try {
      report.epoch = await this.ensureEpoch();
    } catch (e) {
      report.errors.push(e instanceof KavachError ? `${e.code}@${e.stage}` : String(e));
    }
    try {
      report.outbox = await drain(this.outboxDeps());
    } catch (e) {
      report.errors.push(e instanceof KavachError ? `${e.code}@${e.stage}` : String(e));
    }
    try {
      const subs = await this.transport.relay.listSubscriptions();
      for (const s of subs) {
        const known = await this.store.read((tx) => tx.list("certificates").some(([, c]) => c.streamId === toHex(s.streamId)));
        if (!known) continue;
        const r = await syncStream(this.inboxDeps(), s.streamId, s.authorIdentityId);
        report.inbox.streams++;
        report.inbox.stored += r.stored;
        report.inbox.keyPending += r.keyPending;
        if (r.acked !== undefined) report.inbox.acked++;
      }
    } catch (e) {
      report.errors.push(e instanceof KavachError ? `${e.code}@${e.stage}` : String(e));
    }
    report.purged = await purgeHistory(this.store, this.policy, this.now());
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
        // Our own key changed at the host: only a receipt we produced explains that; otherwise ignore.
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
          report.errors.push(e instanceof KavachError ? `${e.code}@${e.stage}` : String(e));
        }
      }
    }
    // Circles: owners we have not pinned yet, then snapshots, then members' certificates.
    const circles = await this.store.read((tx) => tx.list("circles").map(([, c]) => rowToCircle(c)));
    const unknownOwners: Uint8Array[] = [];
    for (const c of circles) {
      if (c.status === "closed" || c.status === "quarantined" || c.status === "left") continue;
      if (!equalBytes(c.ownerIdentityId, pin.identityId) && !(await this.pinFor(c.ownerIdentityId))) unknownOwners.push(c.ownerIdentityId);
    }
    if (unknownOwners.length > 0) {
      for (const r of await this.transport.directory.resolveIdentities(unknownOwners)) await this.acceptMemberCertificate(r.certificate, r.resetReceipt, report);
    }
    const memberIds = new Map<string, Uint8Array>();
    for (const c of circles) {
      if (c.status === "closed" || c.status === "quarantined" || c.status === "left") continue;
      const ownerPin = equalBytes(c.ownerIdentityId, pin.identityId) ? pin : await this.pinFor(c.ownerIdentityId);
      if (!ownerPin) {
        memberIds.set(toHex(c.ownerIdentityId), c.ownerIdentityId);
        continue;
      }
      const wire = await this.transport.directory.getCircle(c.circleId);
      if (wire) {
        try {
          const r = acceptSnapshot(c, wire, ownerPin.accountKey, pin.identityId, now);
          if (r.outcome === "ACCEPTED") {
            await this.store.transaction((tx) => {
              const row = tx.get("circles", toHex(c.circleId));
              tx.put("circles", toHex(c.circleId), { ...circleToRow(r.state), pending: row?.pending && unbig(row.pending.revision) <= r.state.revision ? undefined : row?.pending });
              const ch = t3ApplyChange(tx, { kind: "snapshot", circleId: c.circleId, revision: r.state.revision });
              if (ch.changed) report.metadata.rotations++;
            });
            report.metadata.snapshots++;
            this.emit({ kind: "circleChanged", circleId: c.circleId, revision: r.state.revision, status: r.state.status });
            if (r.state.status === "left") await this.onLeft(c);
            for (const m of r.state.members) memberIds.set(toHex(m), m);
          } else for (const m of c.members) memberIds.set(toHex(m), m);
        } catch (e) {
          if (isKavachError(e, "EQUIVOCATION")) {
            await this.store.transaction((tx) => tx.put("circles", toHex(c.circleId), circleToRow({ ...c, status: "quarantined" })));
            this.emit({ kind: "securityError", code: "EQUIVOCATION", detail: "two snapshots at one revision" });
          } else report.errors.push(e instanceof KavachError ? `${e.code}@${e.stage}` : String(e));
          for (const m of c.members) memberIds.set(toHex(m), m);
        }
      } else for (const m of c.members) memberIds.set(toHex(m), m);
      if (equalBytes(c.ownerIdentityId, pin.identityId) && c.status === "member") {
        const requests = await this.transport.directory.readRequests(c.circleId);
        const joins = requests.filter((r) => r.action === "join").map((r) => r.accountName);
        if (joins.length) this.emit({ kind: "joinRequests", circleId: c.circleId, accountNames: joins });
        for (const r of requests.filter((r) => r.action === "leave")) {
          const [acct] = await this.transport.directory.resolveAccounts([r.accountName]);
          if (!acct) continue;
          const leaver = pinFromCertificate(expectType<AccountDevice>(verifyDocument(acct.certificate), DocumentType.AccountDevice));
          try {
            await this.changeMembership(c.circleId, { remove: leaver.identityId });
          } catch (e) {
            report.errors.push(e instanceof KavachError ? `${e.code}@${e.stage}` : String(e));
          }
        }
      }
    }
    memberIds.delete(toHex(pin.identityId));
    if (memberIds.size > 0) {
      const resolved = await this.transport.directory.resolveIdentities([...memberIds.values()]);
      const byIdentity = new Map<string, { accountName: string; accountKey: Uint8Array }>();
      for (const r of resolved) {
        const doc = expectType<AccountDevice>(verifyDocument(r.certificate), DocumentType.AccountDevice, "sync");
        const iid = toHex(pinFromCertificate(doc).identityId);
        byIdentity.set(iid, { accountName: r.accountName, accountKey: r.accountKey });
        await this.acceptMemberCertificate(r.certificate, r.resetReceipt, report);
      }
      checkMemberResolution(byIdentity);
    }
    this.metadataDirty = false;
  }

  private async pinFor(identityId: Uint8Array): Promise<AccountPin | undefined> {
    const row = await this.store.read((tx) => tx.get("pins", toHex(identityId)));
    return row ? rowToPin(row) : undefined;
  }

  /** Accept a member's certificate; a changed account key is quarantined unless a valid receipt explains it. */
  private async acceptMemberCertificate(wire: Uint8Array, resetReceipt: Uint8Array | undefined, report: SyncReport): Promise<void> {
    const doc = expectType<AccountDevice>(verifyDocument(wire), DocumentType.AccountDevice, "sync");
    const existing = await this.store.read((tx) => tx.list("pins").find(([, p]) => p.accountName === doc.accountName)?.[1]);
    const current = existing ? rowToPin(existing) : undefined;
    let outcome;
    try {
      outcome = acceptCertificate(current, wire);
    } catch (e) {
      if (isKavachError(e, "ACCOUNT_KEY_CHANGED") && current) {
        await this.onKeyChanged(current, wire, resetReceipt, report);
        return;
      }
      if (e instanceof KavachError) {
        report.errors.push(`${e.code}@${e.stage}`);
        if (e.code === "EQUIVOCATION" || e.code === "DEVICE_ROLLBACK" || e.code === "DEVICE_ID_REUSED") this.emit({ kind: "securityError", code: e.code, detail: doc.accountName });
        return;
      }
      throw e;
    }
    if (outcome.outcome === "DUPLICATE") return;
    const p = outcome.pin;
    await this.store.transaction((tx) => {
      tx.put("pins", toHex(p.identityId), pinToRow(p));
      if (outcome.previous) {
        const old = tx.get("certificates", toHex(outcome.previous.certificateHash));
        if (old) tx.put("certificates", toHex(outcome.previous.certificateHash), { ...old, current: false });
      }
      tx.put("certificates", toHex(p.certificateHash), { identityId: toHex(p.identityId), certificateHash: toHex(p.certificateHash), signingKey: toHex(p.signingKey), boxKey: toHex(p.boxKey), streamId: toHex(p.streamId), generation: big(p.generation), wire: toHex(p.certificate), current: true });
      if (outcome.rotate) {
        const ch = t3ApplyChange(tx, { kind: "deviceChanged", identityId: p.identityId, certificateHash: p.certificateHash });
        if (ch.changed) report.metadata.rotations++;
      }
    });
    report.metadata.certificates++;
    if (outcome.rotate) this.emit({ kind: "deviceChanged", identityId: p.identityId, generation: p.generation });
  }

  private async onKeyChanged(current: AccountPin, wire: Uint8Array, receipt: Uint8Array | undefined, report: SyncReport): Promise<void> {
    if (receipt) {
      try {
        const effect = this.trust.apply(receipt, wire, current.accountName, current.identityId, this.now());
        await this.persistTrust();
        if (effect.outcome === "ACCOUNT_KEY_CHANGED") {
          await this.applyReset(current, effect.newIdentityId);
          report.metadata.resets++;
          this.emit({ kind: "accountKeyChanged", accountName: current.accountName, quarantined: false });
        }
        return;
      } catch (e) {
        report.errors.push(e instanceof KavachError ? `${e.code}@${e.stage}` : String(e));
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
  private async applyReset(old: AccountPin, newIdentityId: Uint8Array): Promise<void> {
    await this.store.transaction((tx) => {
      tx.delete("pins", toHex(old.identityId));
      tx.delete("quarantine", old.accountName);
      for (const [k, c] of tx.list("certificates")) if (c.identityId === toHex(old.identityId)) tx.put("certificates", k, { ...c, current: false });
      for (const [k, c] of tx.list("circles")) {
        if (c.ownerIdentityId === toHex(old.identityId)) {
          tx.put("circles", k, { ...c, status: "closed" });
          t3ApplyChange(tx, { kind: "leave", circleId: fromHex(k) });
        } else if (c.members.includes(toHex(old.identityId))) {
          t3ApplyChange(tx, { kind: "deviceChanged", identityId: old.identityId, certificateHash: newIdentityId });
        }
      }
    });
    await forgetAuthor(this.store, old.identityId);
  }

  private async persistTrust(): Promise<void> {
    const rows = this.trust.toRows();
    await this.store.transaction((tx) => {
      if (rows.list) tx.put("resetList", "list", rows.list);
      tx.put("clock", "clock", rows.clock);
      const hashes = rows.accepted;
      for (const e of rows.events) tx.put("resetReceipts", e.resetId, { accountName: e.accountName, oldIdentityId: e.oldIdentityId, newIdentityId: e.newIdentityId, receiptHash: hashes.find((h) => h) ?? "" });
      for (const r of rows.retired) tx.put("retiredIdentities", r, { identityId: r });
    });
  }

  private async onLeft(c: CircleState): Promise<void> {
    // Removed from a circle: stop opening its authors unless another circle still has them.
    const { pin } = this.requireAccount("left");
    const others = await this.store.read((tx) => tx.list("circles").filter(([, x]) => x.circleId !== toHex(c.circleId) && x.status === "member").flatMap(([, x]) => x.members));
    for (const m of c.members) {
      if (equalBytes(m, pin.identityId) || others.includes(toHex(m))) continue;
      await forgetAuthor(this.store, m);
    }
  }

  private async retire(): Promise<void> {
    await this.store.transaction((tx) => {
      const meta = tx.get("meta", META);
      if (meta) tx.put("meta", META, { ...meta, state: "RETIRED" });
      for (const [k, r] of tx.list("outbox")) if (r.status === "queued" || r.status === "inflight") tx.put("outbox", k, { ...r, status: "cancelled", reason: "retired" });
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
    return history(this.store, query);
  }

  latest(identityId: Uint8Array): Promise<Latest | undefined> {
    return latest(this.store, identityId, this.now());
  }

  // Circles ---------------------------------------------------------------------------------------

  private async listCircles(): Promise<CircleSummary[]> {
    const self = this.selfPin?.identityId;
    const now = this.now();
    return this.store.read((tx) =>
      tx.list("circles").map(([, r]) => {
        const c = rowToCircle(r);
        return { circleId: c.circleId, ownerIdentityId: c.ownerIdentityId, revision: c.revision, members: c.members, enabled: c.enabled, status: c.status, snapshotAgeMs: c.verifiedAt ? now - c.verifiedAt : 0n, owned: !!self && equalBytes(c.ownerIdentityId, self) };
      })
    );
  }

  private async vaultUpdate(mutate: (entries: readonly VaultEntry[]) => VaultEntry[]): Promise<void> {
    const { account, pin } = this.requireAccount("vault");
    const recoveryKey = await this.secrets.get("recoveryKey");
    const accountSeed = await this.secrets.get("accountSeed");
    if (!recoveryKey || !accountSeed) throw new KavachError("RECOVERY_REQUIRED", "vault");
    for (let attempt = 0; attempt < 3; attempt++) {
      const row = await this.store.read((tx) => tx.get("vault", VAULT));
      let entries: readonly VaultEntry[] = [];
      let revision = 0n;
      let hash: Uint8Array | undefined;
      if (row) {
        const { openVault } = await import("./codec.js");
        const opened = openVault(fromHex(row.wire), recoveryKey, this.accountName, account.account.publicKey);
        entries = opened.entries;
        revision = unbig(row.revision);
        hash = fromHex(row.hash);
      }
      const next = buildVault({ accountName: this.accountName, accountKey: account.account.publicKey, vaultRevision: revision + 1n }, { accountSeed, lastDeviceGeneration: pin.generation, lastCertificateHash: pin.certificateHash, entries: mutate(entries) }, recoveryKey);
      await this.store.transaction((tx) => t9Vault(tx, { revision: big(revision + 1n), hash: toHex(next.hash), wire: toHex(next.wire), pending: true }));
      const outcome = await this.transport.directory.publishVault({ expectedRevision: revision, expectedHash: hash, newVault: next.wire });
      if (outcome.status === "COMMITTED" || outcome.status === "ALREADY_COMMITTED") {
        await this.store.transaction((tx) => t9Vault(tx, { revision: big(revision + 1n), hash: toHex(next.hash), wire: toHex(next.wire), pending: false }));
        return;
      }
      if (outcome.status === "CONFLICT" && outcome.current) {
        const h = parseVaultHeader(outcome.current);
        await this.store.transaction((tx) => t9Vault(tx, { revision: big(h.vaultRevision), hash: toHex(h.hash), wire: toHex(outcome.current ?? new Uint8Array()), pending: false }));
        continue;
      }
      throw new KavachError("STORAGE_FAILURE", "vault", `publishVault ${outcome.status}`);
    }
    throw new KavachError("STORAGE_FAILURE", "vault", "vault conflict persisted");
  }

  private async createCircle(): Promise<{ circleId: Uint8Array }> {
    const { account, pin } = this.requireAccount("createCircle");
    const circleId = newCircleId();
    const genesis = createCircleSnapshot({ identityId: pin.identityId, accountSecretKey: account.account.secretKey }, circleId);
    const state = acceptSnapshot(pinCircle(circleId, pin.identityId, true, "member"), genesis, pin.accountKey, pin.identityId, this.now());
    if (state.outcome !== "ACCEPTED") throw new KavachError("STORAGE_FAILURE", "createCircle");
    await this.store.transaction((tx) => tx.put("circles", toHex(circleId), { ...circleToRow(state.state), pending: { snapshot: toHex(genesis), revision: "1" } }));
    const outcome = await this.transport.directory.publishOwnedCircle({ circleId, expectedRevision: 0n, expectedHash: undefined, newSnapshot: genesis });
    if (outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") throw new KavachError("STORAGE_FAILURE", "createCircle", outcome.status);
    await this.store.transaction((tx) => {
      const row = tx.get("circles", toHex(circleId));
      if (row) tx.put("circles", toHex(circleId), { ...row, pending: undefined });
      t3ApplyChange(tx, { kind: "join", circleId });
    });
    await this.vaultUpdate((entries) => upsertEntry(entries, { circleId, ownerIdentityId: pin.identityId, sharingEnabled: true }));
    this.emit({ kind: "circleChanged", circleId, revision: 1n, status: "member" });
    return { circleId };
  }

  private async requestJoin(circleId: Uint8Array, ownerIdentityId: Uint8Array, shareOnApproval: boolean): Promise<void> {
    this.requireAccount("requestJoin");
    // The vault entry first, then the request: a recovering device finds the pin either way.
    await this.vaultUpdate((entries) => upsertEntry(entries, { circleId, ownerIdentityId, sharingEnabled: shareOnApproval }));
    await this.store.transaction((tx) => {
      if (!tx.get("circles", toHex(circleId))) tx.put("circles", toHex(circleId), circleToRow(pinCircle(circleId, ownerIdentityId, shareOnApproval, "requested")));
    });
    const outcome = await this.transport.directory.requestJoin(circleId);
    if (outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") throw new KavachError("STORAGE_FAILURE", "requestJoin", outcome.status);
    this.metadataDirty = true;
  }

  private async approve(circleId: Uint8Array, accountName: string): Promise<{ revision: bigint }> {
    const [resolved] = await this.transport.directory.resolveAccounts([accountName]);
    if (!resolved) throw new KavachError("METADATA_REQUIRED", "approve", "unknown account");
    const report: SyncReport = { metadata: { certificates: 0, snapshots: 0, rotations: 0, quarantined: 0, resets: 0 }, epoch: "unchanged", outbox: { sent: 0, accepted: 0, cancelled: 0, unknown: 0, retry: 0 }, inbox: { streams: 0, stored: 0, keyPending: 0, acked: 0 }, purged: 0, errors: [] };
    await this.acceptMemberCertificate(resolved.certificate, resolved.resetReceipt, report);
    const requester = pinFromCertificate(expectType<AccountDevice>(verifyDocument(resolved.certificate), DocumentType.AccountDevice));
    const pinned = await this.pinFor(requester.identityId);
    if (!pinned) throw new KavachError("ACCOUNT_KEY_CHANGED", "approve", "requester's key is quarantined");
    return this.changeMembership(circleId, { admit: requester.identityId });
  }

  private async changeMembership(circleId: Uint8Array, change: { admit: Uint8Array } | { remove: Uint8Array } | { close: true }): Promise<{ revision: bigint }> {
    const { account, pin } = this.requireAccount("changeMembership");
    for (let attempt = 0; attempt < 3; attempt++) {
      const row = await this.store.read((tx) => tx.get("circles", toHex(circleId)));
      if (!row) throw new KavachError("NOT_AUTHORIZED", "changeMembership", "unknown circle");
      const state = rowToCircle(row);
      const successor = successorSnapshot(state, change, { identityId: pin.identityId, accountSecretKey: account.account.secretKey });
      if (!successor) return { revision: state.revision };
      await this.store.transaction((tx) => t8OwnerSnapshot(tx, circleId, successor, state.revision + 1n));
      const outcome = await this.transport.directory.publishOwnedCircle({ circleId, expectedRevision: state.revision, expectedHash: state.bodyHash, newSnapshot: successor });
      if (outcome.status === "COMMITTED" || outcome.status === "ALREADY_COMMITTED") {
        const accepted = acceptSnapshot(state, successor, pin.accountKey, pin.identityId, this.now());
        if (accepted.outcome !== "ACCEPTED") throw new KavachError("STORAGE_FAILURE", "changeMembership");
        const next = "close" in change ? { ...accepted.state, status: "closed" as const } : accepted.state;
        await this.store.transaction((tx) => {
          tx.put("circles", toHex(circleId), { ...circleToRow(next), pending: undefined });
          t3ApplyChange(tx, { kind: "snapshot", circleId, revision: next.revision });
        });
        if ("remove" in change) {
          const stillElsewhere = await this.store.read((tx) => tx.list("circles").some(([, c]) => c.circleId !== toHex(circleId) && c.status === "member" && c.members.includes(toHex(change.remove))));
          if (!stillElsewhere) await forgetAuthor(this.store, change.remove);
        }
        this.emit({ kind: "circleChanged", circleId, revision: next.revision, status: next.status });
        return { revision: next.revision };
      }
      if (outcome.status === "CONFLICT" && outcome.current) {
        const accepted = acceptSnapshot(state, outcome.current, pin.accountKey, pin.identityId, this.now());
        if (accepted.outcome === "ACCEPTED") await this.store.transaction((tx) => tx.put("circles", toHex(circleId), { ...circleToRow(accepted.state), pending: undefined }));
        continue;
      }
      throw new KavachError("STORAGE_FAILURE", "changeMembership", outcome.status);
    }
    throw new KavachError("STORAGE_FAILURE", "changeMembership", "conflict persisted");
  }

  private async leave(circleId: Uint8Array): Promise<void> {
    const { pin } = this.requireAccount("leave");
    const row = await this.store.read((tx) => tx.get("circles", toHex(circleId)));
    if (!row) return;
    if (row.ownerIdentityId === toHex(pin.identityId)) throw new KavachError("NOT_AUTHORIZED", "leave", "the owner closes instead");
    const state = rowToCircle(row);
    await this.store.transaction((tx) => {
      tx.put("circles", toHex(circleId), circleToRow({ ...state, enabled: false, status: "left" }));
      t3ApplyChange(tx, { kind: "leave", circleId });
    });
    await this.onLeft(state);
    await this.vaultUpdate((entries) => removeEntry(entries, circleId));
    await this.transport.directory.requestLeave(circleId);
    this.emit({ kind: "circleChanged", circleId, revision: state.revision, status: "left" });
  }

  private async setEnabled(circleId: Uint8Array, enabled: boolean): Promise<void> {
    const row = await this.store.read((tx) => tx.get("circles", toHex(circleId)));
    if (!row) throw new KavachError("NOT_AUTHORIZED", "setEnabled", "unknown circle");
    if (row.enabled === enabled) return;
    await this.store.transaction((tx) => {
      tx.put("circles", toHex(circleId), { ...row, enabled });
      t3ApplyChange(tx, { kind: enabled ? "enable" : "disable", circleId });
    });
    await this.vaultUpdate((entries) => entries.map((e) => (equalBytes(e.circleId, circleId) ? { ...e, sharingEnabled: enabled } : e)));
  }

  private async closeCircle(circleId: Uint8Array): Promise<void> {
    await this.changeMembership(circleId, { close: true });
    const members = await this.store.read((tx) => tx.get("circles", toHex(circleId))?.members ?? []);
    const { pin } = this.requireAccount("close");
    for (const m of members) if (m !== toHex(pin.identityId)) await forgetAuthor(this.store, fromHex(m));
    await this.vaultUpdate((entries) => removeEntry(entries, circleId));
  }

  // Reset -----------------------------------------------------------------------------------------

  async resetAccount(options: { confirmed: true; reauthProof?: Uint8Array }): Promise<{ identityId: Uint8Array }> {
    const stage = "resetAccount";
    if (!options.confirmed) throw new KavachError("NOT_AUTHORIZED", stage, "reset requires confirmation");
    const { pin } = this.requireAccount(stage);
    const accountSeed = newAccountSeed();
    const account = openAccount(this.accountName, accountSeed);
    const device = newDevice();
    const certificate = certify(account, device, 1n);
    const newPin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice));
    const recoveryKey = newRecoveryKey();
    const vault = buildVault({ accountName: this.accountName, accountKey: account.account.publicKey, vaultRevision: 1n }, { accountSeed, lastDeviceGeneration: 1n, lastCertificateHash: newPin.certificateHash, entries: [] }, recoveryKey);
    const resetId = randomBytes(16);
    const outcome = await this.transport.directory.resetAccount({ accountName: this.accountName, expectedOldIdentityId: pin.identityId, newCertificate: certificate, newVault: vault.wire, resetId, reauthProof: options.reauthProof ?? new Uint8Array() });
    if ((outcome.status !== "COMMITTED" && outcome.status !== "ALREADY_COMMITTED") || !outcome.receipt) throw new KavachError("NOT_AUTHORIZED", stage, `host refused reset: ${outcome.status}`);
    // A new identity: a new store under it. Nothing of the old identity's keys survives.
    const instanceId = randomBytes(16);
    await t1Secrets(this.secrets, { accountSeed, deviceSeed: device.deviceSeed, recoveryKey, instanceId });
    await this.store.transaction((tx) => {
      for (const table of ["meta", "self", "pins", "certificates", "quarantine", "circles", "revision", "vault", "epochs", "stream", "outbox", "history", "livePins", "readerEpochs", "subscriptions", "unresolved", "activation"] as const) {
        for (const [k] of tx.list(table)) tx.delete(table, k);
      }
      t1Header(tx, { account, device, certificate, instanceId, generation: 1n });
      t9Vault(tx, { revision: "1", hash: toHex(vault.hash), wire: toHex(vault.wire), pending: false });
      t1Activate(tx);
    });
    this.account = account;
    this.device = device;
    this.selfPin = newPin;
    try {
      await this.provider.save(this.accountName, newPin.identityId, recoveryKey);
    } catch {
      /* reported by recoveryStatus() */
    }
    await this.emitState();
    return { identityId: newPin.identityId };
  }

  async close(): Promise<void> {
    this.unobserve?.();
    this.listeners.clear();
  }
}

