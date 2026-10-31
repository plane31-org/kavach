/**
 * Circle membership and owner approval (protocol section 6).
 *
 * Membership is one owner-signed snapshot. Join and leave requests are host state with no
 * signature; the owner builds every successor from trusted local state plus one change.
 */
import { compareBytes, equalBytes, toHex } from "./bytes.js";
import { DocumentType, buildCircleSnapshot, expectType, verifyDocument, type CircleSnapshot, type Parsed } from "./codec.js";
import { randomBytes } from "./crypto.js";
import { KavachError } from "./errors.js";

export type CircleStatus = "requested" | "member" | "left" | "quarantined" | "closed";

/** What the SDK persists per circle it has pinned. */
export interface CircleState {
  readonly circleId: Uint8Array;
  readonly ownerIdentityId: Uint8Array;
  /** 0n until the first verified snapshot. */
  readonly revision: bigint;
  readonly bodyHash: Uint8Array | undefined;
  readonly snapshot: Uint8Array | undefined;
  readonly members: readonly Uint8Array[];
  readonly enabled: boolean;
  readonly status: CircleStatus;
  /** When the current snapshot was verified, for showing its age. */
  readonly verifiedAt: bigint;
}

export type SnapshotOutcome =
  | { readonly outcome: "ACCEPTED"; readonly state: CircleState; readonly snapshot: Parsed<CircleSnapshot> }
  | { readonly outcome: "DUPLICATE"; readonly state: CircleState };

export function newCircleId(): Uint8Array {
  return randomBytes(16);
}

export function pinCircle(circleId: Uint8Array, ownerIdentityId: Uint8Array, enabled: boolean, status: CircleStatus = "requested"): CircleState {
  return { circleId, ownerIdentityId, revision: 0n, bodyHash: undefined, snapshot: undefined, members: [], enabled, status, verifiedAt: 0n };
}

/**
 * Accept a snapshot for a pinned circle under the pinned owner's account key.
 * A lower revision is `ROLLBACK`; the same revision with the same body is a duplicate and with a
 * different valid body is `EQUIVOCATION`, which quarantines the circle. Membership status comes
 * from the snapshot: the account is a member when it is listed and waiting when it is not.
 */
export function acceptSnapshot(state: CircleState, wire: Uint8Array, ownerAccountKey: Uint8Array, selfIdentityId: Uint8Array, now: bigint): SnapshotOutcome {
  const stage = "acceptSnapshot";
  const doc = expectType<CircleSnapshot>(verifyDocument(wire, ownerAccountKey), DocumentType.CircleSnapshot, stage);
  if (!equalBytes(doc.circleId, state.circleId) || !equalBytes(doc.ownerIdentityId, state.ownerIdentityId)) {
    throw new KavachError("MALFORMED", stage, "snapshot is for another circle or owner");
  }
  if (doc.revision < state.revision) throw new KavachError("ROLLBACK", stage);
  if (doc.revision === state.revision) {
    if (state.bodyHash && equalBytes(doc.bodyHash, state.bodyHash)) return { outcome: "DUPLICATE", state };
    throw new KavachError("EQUIVOCATION", stage, "two snapshots at one revision");
  }
  // A member that is no longer listed has been removed, whether by a removal or a closure; the
  // two are indistinguishable to a member and mean the same thing locally. Only the owner's own
  // explicit close sets "closed".
  const listed = doc.members.some((m) => equalBytes(m, selfIdentityId));
  let status: CircleStatus = state.status;
  if (state.status === "quarantined") status = "quarantined";
  else if (listed) status = "member";
  else if (state.status === "member") status = "left";
  return {
    outcome: "ACCEPTED",
    snapshot: doc,
    state: { ...state, revision: doc.revision, bodyHash: doc.bodyHash, snapshot: wire, members: doc.members, status, verifiedAt: now }
  };
}

/** Two different account keys for one account name among resolved members is a forgery attempt. */
export function checkMemberResolution(resolved: ReadonlyMap<string, { accountName: string; accountKey: Uint8Array }>): void {
  const byName = new Map<string, string>();
  for (const [iid, r] of resolved) {
    const seen = byName.get(r.accountName);
    if (seen !== undefined && seen !== toHex(r.accountKey)) {
      throw new KavachError("EQUIVOCATION", "resolveMembers", `two keys for ${r.accountName}`);
    }
    byName.set(r.accountName, toHex(r.accountKey));
    void iid;
  }
}

// Owner side -----------------------------------------------------------------------------------

export interface OwnerKeys {
  readonly identityId: Uint8Array;
  readonly accountSecretKey: Uint8Array;
}

/** Revision 1 with the owner as sole member. */
export function createCircleSnapshot(owner: OwnerKeys, circleId: Uint8Array): Uint8Array {
  return buildCircleSnapshot({ circleId, ownerIdentityId: owner.identityId, revision: 1n, members: [owner.identityId] }, owner.accountSecretKey);
}

export type MembershipChange = { readonly admit: Uint8Array } | { readonly remove: Uint8Array } | { readonly close: true };

/**
 * The successor snapshot from trusted local state plus one change. Returns `undefined` when the
 * change is already reflected (approval of an admitted account is idempotent).
 */
export function successorSnapshot(state: CircleState, change: MembershipChange, owner: OwnerKeys): Uint8Array | undefined {
  if (!equalBytes(state.ownerIdentityId, owner.identityId)) throw new KavachError("NOT_AUTHORIZED", "successorSnapshot", "not the owner");
  if (state.status === "closed") throw new KavachError("NOT_AUTHORIZED", "successorSnapshot", "circle closed");
  let members: Uint8Array[];
  if ("admit" in change) {
    if (state.members.some((m) => equalBytes(m, change.admit))) return undefined;
    members = [...state.members, change.admit];
    if (members.length > 100) throw new KavachError("RECIPIENT_LIMIT", "successorSnapshot");
  } else if ("remove" in change) {
    if (equalBytes(change.remove, owner.identityId)) throw new KavachError("NOT_AUTHORIZED", "successorSnapshot", "the owner cannot leave without closing");
    if (!state.members.some((m) => equalBytes(m, change.remove))) return undefined;
    members = state.members.filter((m) => !equalBytes(m, change.remove));
  } else {
    members = [owner.identityId];
    if (state.members.length === 1) return undefined;
  }
  members.sort(compareBytes);
  return buildCircleSnapshot({ circleId: state.circleId, ownerIdentityId: owner.identityId, revision: state.revision + 1n, members }, owner.accountSecretKey);
}

/** The owner's restored device signs revision plus one over the current snapshot; the revision never resets. */
export function isOwner(state: CircleState, selfIdentityId: Uint8Array): boolean {
  return equalBytes(state.ownerIdentityId, selfIdentityId);
}
