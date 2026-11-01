/**
 * The transport the host implements (protocol section 13): a directory and a relay. The SDK
 * passes opaque bytes through unchanged; no plaintext payload ever enters this interface.
 */

export type MutationStatus = "COMMITTED" | "ALREADY_COMMITTED" | "CONFLICT" | "IGNORED_OLDER" | "RETRYABLE" | "UNAUTHORIZED" | "PERMANENT_FAILURE";

export interface MutationOutcome {
  readonly status: MutationStatus;
  /** On CONFLICT: the bytes the host currently holds, when it can return them. */
  readonly current?: Uint8Array | undefined;
  readonly currentRevision?: bigint | undefined;
}

export interface ResolvedAccount {
  readonly accountName: string;
  readonly accountKey: Uint8Array;
  /** The current certificate wire. */
  readonly certificate: Uint8Array;
  /** When the account's key changed through a reset: the receipt that proves it. */
  readonly resetReceipt?: Uint8Array | undefined;
}

export interface JoinRequest {
  readonly circleId: Uint8Array;
  readonly accountName: string;
  readonly action: "join" | "leave";
  readonly requestedAt: bigint;
}

export interface Directory {
  resolveAccounts(names: readonly string[]): Promise<readonly ResolvedAccount[]>;
  /** Snapshots name identities; the directory maps them back to accounts (host-trusted, like first contact). */
  resolveIdentities(identityIds: readonly Uint8Array[]): Promise<readonly ResolvedAccount[]>;
  getCertificate(hash: Uint8Array): Promise<Uint8Array | undefined>;
  activateDevice(input: {
    accountName: string;
    expectedCertificateHash: Uint8Array;
    expectedVaultRevision: bigint;
    expectedVaultHash: Uint8Array;
    newCertificate: Uint8Array;
    newVault: Uint8Array;
  }): Promise<MutationOutcome>;
  registerAccount(input: { certificate: Uint8Array; vault: Uint8Array }): Promise<MutationOutcome>;
  getVault(accountName: string): Promise<Uint8Array | undefined>;
  publishVault(input: { expectedRevision: bigint; expectedHash: Uint8Array | undefined; newVault: Uint8Array }): Promise<MutationOutcome>;
  getCircle(circleId: Uint8Array): Promise<Uint8Array | undefined>;
  publishOwnedCircle(input: { circleId: Uint8Array; expectedRevision: bigint; expectedHash: Uint8Array | undefined; newSnapshot: Uint8Array }): Promise<MutationOutcome>;
  requestJoin(circleId: Uint8Array): Promise<MutationOutcome>;
  requestLeave(circleId: Uint8Array): Promise<MutationOutcome>;
  readRequests(circleId: Uint8Array): Promise<readonly JoinRequest[]>;
  getResetKeyList(): Promise<Uint8Array | undefined>;
  getResetReceipt(resetId: Uint8Array): Promise<Uint8Array | undefined>;
  resetAccount(input: {
    accountName: string;
    expectedOldIdentityId: Uint8Array;
    newCertificate: Uint8Array;
    newVault: Uint8Array;
    resetId: Uint8Array;
    reauthProof: Uint8Array;
  }): Promise<MutationOutcome & { receipt?: Uint8Array | undefined }>;
}

export interface EpochBundle {
  readonly manifest: Uint8Array;
  /** The caller's own wrap. */
  readonly wrap: Uint8Array | undefined;
}

export type AppendStatus = "ACCEPTED" | "ALREADY_ACCEPTED" | "EQUIVOCATION" | "STALE_APPEND" | "RETRYABLE" | "UNAUTHORIZED" | "SUPERSEDED_DEVICE" | "EPOCH_FENCED";

export interface AppendOutcome {
  readonly status: AppendStatus;
  readonly deliverySeq?: bigint;
}

export interface ReadRecordsResult {
  readonly records: readonly { readonly deliverySeq: bigint; readonly wire: Uint8Array }[];
  readonly nextSeq: bigint;
  readonly tail: bigint;
  readonly expiredThrough: bigint;
  readonly committedCursor: bigint;
}

export interface Relay {
  getCurrentEpoch(streamId: Uint8Array): Promise<{ epoch: number; manifestHash: Uint8Array } | undefined>;
  getEpoch(streamId: Uint8Array, epoch: number): Promise<EpochBundle | undefined>;
  publishEpoch(input: {
    streamId: Uint8Array;
    expectedEpoch: number;
    expectedHash: Uint8Array | undefined;
    manifest: Uint8Array;
    wraps: ReadonlyMap<string, Uint8Array>;
  }): Promise<MutationOutcome & { currentEpoch?: number | undefined; currentManifest?: Uint8Array | undefined }>;
  /** MUST be callable from inside T6h without awaiting: it queues the bytes synchronously and returns a promise. */
  appendRecord(recordId: Uint8Array, wire: Uint8Array): Promise<AppendOutcome>;
  readRecords(streamId: Uint8Array, afterSeq: bigint, limit: number): Promise<ReadRecordsResult>;
  ackThrough(streamId: Uint8Array, cursor: bigint): Promise<{ status: "COMMITTED" | "CURSOR_OUT_OF_RANGE" | "RETRYABLE" | "UNAUTHORIZED"; committedCursor?: bigint }>;
  /** The streams this reader is subscribed to (the host creates subscriptions). */
  listSubscriptions(): Promise<readonly { streamId: Uint8Array; authorIdentityId: Uint8Array }[]>;
}

export interface Transport {
  readonly directory: Directory;
  readonly relay: Relay;
}
