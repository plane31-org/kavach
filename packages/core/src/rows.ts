/** Conversions between domain objects and the JSON-safe rows of the store. */
import { fromHex, toHex } from "./bytes.js";
import type { CircleState } from "./circle.js";
import type { AccountPin } from "./identity.js";
import type { RevisionState } from "./audience.js";
import type { PreparedEpoch } from "./epoch.js";
import type { CircleRow, EpochRow, PinRow, RevisionRow } from "./store.js";

export const big = (v: bigint): string => v.toString();
export const unbig = (v: string): bigint => BigInt(v);

export function pinToRow(p: AccountPin): PinRow {
  return {
    accountName: p.accountName,
    accountKey: toHex(p.accountKey),
    identityId: toHex(p.identityId),
    generation: big(p.generation),
    certificateHash: toHex(p.certificateHash),
    certificate: toHex(p.certificate),
    deviceId: toHex(p.deviceId),
    signingKey: toHex(p.signingKey),
    boxKey: toHex(p.boxKey),
    streamId: toHex(p.streamId),
    deviceIds: p.deviceIds.map(toHex)
  };
}

export function rowToPin(r: PinRow): AccountPin {
  return {
    accountName: r.accountName,
    accountKey: fromHex(r.accountKey),
    identityId: fromHex(r.identityId),
    generation: unbig(r.generation),
    certificateHash: fromHex(r.certificateHash),
    certificate: fromHex(r.certificate),
    deviceId: fromHex(r.deviceId),
    signingKey: fromHex(r.signingKey),
    boxKey: fromHex(r.boxKey),
    streamId: fromHex(r.streamId),
    deviceIds: r.deviceIds.map(fromHex)
  };
}

export function circleToRow(c: CircleState): CircleRow {
  return {
    circleId: toHex(c.circleId),
    ownerIdentityId: toHex(c.ownerIdentityId),
    revision: big(c.revision),
    bodyHash: c.bodyHash ? toHex(c.bodyHash) : undefined,
    snapshot: c.snapshot ? toHex(c.snapshot) : undefined,
    members: c.members.map(toHex),
    enabled: c.enabled,
    status: c.status,
    verifiedAt: big(c.verifiedAt)
  };
}

export function rowToCircle(r: CircleRow): CircleState {
  return {
    circleId: fromHex(r.circleId),
    ownerIdentityId: fromHex(r.ownerIdentityId),
    revision: unbig(r.revision),
    bodyHash: r.bodyHash ? fromHex(r.bodyHash) : undefined,
    snapshot: r.snapshot ? fromHex(r.snapshot) : undefined,
    members: r.members.map(fromHex),
    enabled: r.enabled,
    status: r.status,
    verifiedAt: unbig(r.verifiedAt)
  };
}

export function revisionToRow(s: RevisionState, paused: RevisionRow["paused"]): RevisionRow {
  return {
    desiredRevision: big(s.desiredRevision),
    seenSnapshots: Object.fromEntries([...s.seenSnapshots].map(([k, v]) => [k, big(v)])),
    seenCertificates: Object.fromEntries([...s.seenCertificates]),
    paused
  };
}

export function rowToRevision(r: RevisionRow): RevisionState {
  return {
    desiredRevision: unbig(r.desiredRevision),
    seenSnapshots: new Map(Object.entries(r.seenSnapshots).map(([k, v]) => [k, unbig(v)])),
    seenCertificates: new Map(Object.entries(r.seenCertificates))
  };
}

export function preparedToRow(p: PreparedEpoch): EpochRow {
  return {
    epoch: p.epoch,
    status: "prepared",
    manifest: toHex(p.manifest),
    manifestHash: toHex(p.manifestHash),
    wraps: Object.fromEntries([...p.wraps].map(([k, v]) => [k, toHex(v)])),
    epochKey: toHex(p.epochKey),
    capturedRevision: big(p.capturedRevision),
    audienceKey: p.audienceKey,
    createdAt: big(p.createdAt),
    nextCounter: 0,
    lastSentAt: undefined
  };
}

export function rowToPrepared(r: EpochRow): PreparedEpoch {
  return {
    epoch: r.epoch,
    manifest: fromHex(r.manifest),
    manifestHash: fromHex(r.manifestHash),
    wraps: new Map(Object.entries(r.wraps).map(([k, v]) => [k, fromHex(v)])),
    epochKey: fromHex(r.epochKey),
    capturedRevision: unbig(r.capturedRevision),
    audienceKey: r.audienceKey,
    createdAt: unbig(r.createdAt)
  };
}
