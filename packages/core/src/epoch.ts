/**
 * Epochs, wraps, publication and the reader side (protocol section 8).
 */
import { equalBytes, toHex } from "./bytes.js";
import type { ResolvedAudience } from "./audience.js";
import { DocumentType, buildEpochManifest, expectType, parseDocument, verifyDocument, type EpochManifest, type Parsed } from "./codec.js";
import { KEY_BYTES, bodyHash, keyCommitment, openSealedBox, randomBytes, sealBox, wrapHash, type BoxKeypair } from "./crypto.js";
import { KavachError } from "./errors.js";

export const MAX_COUNTER = 0xffff_ffff;
export const MAX_EPOCH = 0xffff_ffff;

export interface AuthorKeys {
  readonly identityId: Uint8Array;
  readonly certificateHash: Uint8Array;
  readonly streamId: Uint8Array;
  readonly signingSecretKey: Uint8Array;
}

/** Everything T4 persists before any network call. */
export interface PreparedEpoch {
  readonly epoch: number;
  readonly manifest: Uint8Array;
  readonly manifestHash: Uint8Array;
  /** Wrap per recipient identity id (hex), the author's own included. */
  readonly wraps: ReadonlyMap<string, Uint8Array>;
  readonly epochKey: Uint8Array;
  readonly capturedRevision: bigint;
  readonly audienceKey: string;
  readonly createdAt: bigint;
}

/** Prepare an epoch: fresh random key, one sealed box per row, one signature. */
export function prepareEpoch(input: {
  readonly author: AuthorKeys;
  readonly epoch: number;
  readonly createdAt: bigint;
  readonly audience: ResolvedAudience;
  readonly desiredRevision: bigint;
  readonly epochKey?: Uint8Array;
}): PreparedEpoch {
  const stage = "prepareEpoch";
  if (input.epoch < 1 || input.epoch > MAX_EPOCH) throw new KavachError("COUNTER_EXHAUSTED", stage, "epoch space exhausted; replace the stream");
  const epochKey = input.epochKey ?? randomBytes(KEY_BYTES);
  const wraps = new Map<string, Uint8Array>();
  const rows = input.audience.rows.map((row) => {
    const wrap = sealBox(epochKey, row.boxKey);
    wraps.set(toHex(row.identityId), wrap);
    return { identityId: row.identityId, certificateHash: row.certificateHash, wrapHash: wrapHash(wrap) };
  });
  if (!rows.some((r) => equalBytes(r.identityId, input.author.identityId))) throw new KavachError("MALFORMED", stage, "author missing from audience");
  const manifest = buildEpochManifest(
    {
      streamId: input.author.streamId,
      authorIdentityId: input.author.identityId,
      authorCertificateHash: input.author.certificateHash,
      epoch: input.epoch,
      createdAt: input.createdAt,
      keyCommitment: keyCommitment(input.author.streamId, input.epoch, epochKey),
      audience: rows
    },
    input.author.signingSecretKey
  );
  return {
    epoch: input.epoch,
    manifest,
    manifestHash: bodyHash(manifest.subarray(0, manifest.length - 64)),
    wraps,
    epochKey,
    capturedRevision: input.desiredRevision,
    audienceKey: input.audience.key,
    createdAt: input.createdAt
  };
}

// Publication ----------------------------------------------------------------------------------

export type PublishOutcome =
  | { readonly status: "COMMITTED" }
  | { readonly status: "ALREADY_COMMITTED" }
  | { readonly status: "CONFLICT"; readonly currentEpoch: number; readonly currentManifest: Uint8Array | undefined }
  | { readonly status: "RETRYABLE" }
  | { readonly status: "UNAUTHORIZED" }
  | { readonly status: "PERMANENT_FAILURE" };

export type PublishResolution = "COMMITTED" | "RETRY";

/**
 * Resolve a publish outcome for a prepared epoch. Identical bytes at the slot mean committed; a
 * different valid body at the same epoch is `EQUIVOCATION`; a higher committed epoch than the one
 * prepared means local state was lost and the device must replace its stream.
 */
export function resolvePublish(prepared: PreparedEpoch, outcome: PublishOutcome): PublishResolution {
  const stage = "publishEpoch";
  switch (outcome.status) {
    case "COMMITTED":
    case "ALREADY_COMMITTED":
      return "COMMITTED";
    case "RETRYABLE":
      return "RETRY";
    case "UNAUTHORIZED":
      throw new KavachError("NOT_AUTHORIZED", stage);
    case "PERMANENT_FAILURE":
      throw new KavachError("STORAGE_FAILURE", stage, "host refused the epoch permanently");
    case "CONFLICT": {
      if (outcome.currentEpoch === prepared.epoch && outcome.currentManifest) {
        if (equalBytes(outcome.currentManifest, prepared.manifest)) return "COMMITTED";
        const theirs = parseDocument(outcome.currentManifest);
        if (theirs.type === DocumentType.EpochManifest && theirs.epoch === prepared.epoch) {
          throw new KavachError("EQUIVOCATION", stage, "a different manifest is committed at this epoch");
        }
      }
      if (outcome.currentEpoch >= prepared.epoch) {
        throw new KavachError("RECOVERY_REQUIRED", stage, "the host holds a higher epoch for this stream; local state was lost");
      }
      return "RETRY";
    }
  }
}

export type PromotionOutcome = "PROMOTED" | "OBSOLETE";

/** After commit: promote only if the captured revision and the exact audience still match. */
export function promote(prepared: PreparedEpoch, currentDesiredRevision: bigint, currentAudienceKey: string): PromotionOutcome {
  return prepared.capturedRevision === currentDesiredRevision && prepared.audienceKey === currentAudienceKey ? "PROMOTED" : "OBSOLETE";
}

// Rotation triggers -----------------------------------------------------------------------------

export type RotationReason = "counterExhausted" | "hygiene" | "clockReversal";

export interface ActiveEpochView {
  readonly createdAt: bigint;
  readonly nextCounter: number;
  readonly lastSentAt: bigint | undefined;
}

export function rotationReason(active: ActiveEpochView, now: bigint, hygieneRotationMs: bigint): RotationReason | undefined {
  if (active.nextCounter > MAX_COUNTER) return "counterExhausted";
  if (active.lastSentAt !== undefined && now < active.lastSentAt) return "clockReversal";
  if (now - active.createdAt > hygieneRotationMs) return "hygiene";
  return undefined;
}

// Reader side ----------------------------------------------------------------------------------

export interface AuthorCertificateView {
  readonly certificateHash: Uint8Array;
  readonly signingKey: Uint8Array;
  readonly streamId: Uint8Array;
  readonly current: boolean;
}

export interface AuthorView {
  readonly identityId: Uint8Array;
  /** The author's current certificate and any archived ones the reader still holds, by hash (hex). */
  readonly certificates: ReadonlyMap<string, AuthorCertificateView>;
}

export interface SelfView {
  readonly identityId: Uint8Array;
  readonly certificateHash: Uint8Array;
  readonly box: BoxKeypair;
}

export interface OpenedEpoch {
  readonly manifest: Parsed<EpochManifest>;
  readonly epochKey: Uint8Array;
  /** The manifest belongs to a device of the author that is no longer current: history only. */
  readonly superseded: boolean;
}

/**
 * Every check of section 8 before a key is stored: manifest signature under the certificate it
 * names, that certificate's identity and stream, the author's own row, the reader's own row at
 * its current certificate, the wrap hash, the sealed box and the key commitment.
 */
export function openEpoch(manifestWire: Uint8Array, author: AuthorView, self: SelfView, wrap: Uint8Array): OpenedEpoch {
  const stage = "openEpoch";
  const parsed = expectType<EpochManifest>(parseDocument(manifestWire), DocumentType.EpochManifest, stage);
  const cert = author.certificates.get(toHex(parsed.authorCertificateHash));
  if (!cert) throw new KavachError("SUPERSEDED_DEVICE", stage, "manifest names a certificate that is not the author's current one");
  const manifest = expectType<EpochManifest>(verifyDocument(manifestWire, cert.signingKey), DocumentType.EpochManifest, stage);
  if (!equalBytes(manifest.authorIdentityId, author.identityId) || !equalBytes(manifest.streamId, cert.streamId)) {
    throw new KavachError("MALFORMED", stage, "manifest identity or stream does not match the certificate");
  }
  const authorRow = manifest.audience.find((r) => equalBytes(r.identityId, author.identityId));
  if (!authorRow || !equalBytes(authorRow.certificateHash, manifest.authorCertificateHash)) {
    throw new KavachError("MALFORMED", stage, "author row does not name the author certificate");
  }
  const selfRow = manifest.audience.find((r) => equalBytes(r.identityId, self.identityId));
  if (!selfRow || !equalBytes(selfRow.certificateHash, self.certificateHash)) {
    throw new KavachError("NOT_AUTHORIZED", stage, "this device is not addressed by the epoch");
  }
  if (!equalBytes(wrapHash(wrap), selfRow.wrapHash)) throw new KavachError("WRAP_HASH_MISMATCH", stage);
  const epochKey = openSealedBox(wrap, self.box, stage);
  if (!equalBytes(keyCommitment(manifest.streamId, manifest.epoch, epochKey), manifest.keyCommitment)) {
    throw new KavachError("KEY_COMMITMENT_MISMATCH", stage);
  }
  return { manifest, epochKey, superseded: !cert.current };
}
