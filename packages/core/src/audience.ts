/**
 * Audience resolution and the desired revision (protocol section 7).
 */
import { compareBytes, equalBytes, toHex } from "./bytes.js";
import type { CircleState } from "./circle.js";
import { KavachError } from "./errors.js";
import type { AccountPin } from "./identity.js";

export const MAX_AUDIENCE = 100;

export interface AudienceEntry {
  readonly identityId: Uint8Array;
  readonly certificateHash: Uint8Array;
  readonly boxKey: Uint8Array;
}

export interface ResolvedAudience {
  /** Sorted by identity id, self included. */
  readonly rows: readonly AudienceEntry[];
  /** Rows other than self. */
  readonly recipientCount: number;
  /** A digest-friendly description of the exact certificate-bound audience. */
  readonly key: string;
}

export function isEligible(circle: CircleState, selfIdentityId: Uint8Array): boolean {
  return (
    circle.status === "member" &&
    circle.enabled &&
    circle.revision > 0n &&
    circle.members.some((m) => equalBytes(m, selfIdentityId))
  );
}

/**
 * Self plus every member of every eligible circle, each at its current certificate. Anything
 * missing is `METADATA_REQUIRED`; more than 100 distinct accounts is `RECIPIENT_LIMIT`. The
 * author never guesses, omits a recipient or reuses an obsolete key.
 */
export function resolveAudience(self: AccountPin, circles: readonly CircleState[], pins: ReadonlyMap<string, AccountPin>): ResolvedAudience {
  const stage = "resolveAudience";
  const wanted = new Map<string, Uint8Array>();
  wanted.set(toHex(self.identityId), self.identityId);
  for (const c of circles) {
    if (!isEligible(c, self.identityId)) continue;
    for (const m of c.members) wanted.set(toHex(m), m);
  }
  if (wanted.size > MAX_AUDIENCE) throw new KavachError("RECIPIENT_LIMIT", stage, `${wanted.size} accounts`);
  const rows: AudienceEntry[] = [];
  for (const [hex, iid] of wanted) {
    const pin = hex === toHex(self.identityId) ? self : pins.get(hex);
    if (!pin) throw new KavachError("METADATA_REQUIRED", stage, "no certificate for a member");
    rows.push({ identityId: iid, certificateHash: pin.certificateHash, boxKey: pin.boxKey });
  }
  rows.sort((a, b) => compareBytes(a.identityId, b.identityId));
  return { rows, recipientCount: rows.length - 1, key: rows.map((r) => toHex(r.identityId) + ":" + toHex(r.certificateHash)).join(",") };
}

// Desired revision -----------------------------------------------------------------------------

export type AudienceEvent =
  | { readonly kind: "snapshot"; readonly circleId: Uint8Array; readonly revision: bigint }
  | { readonly kind: "deviceChanged"; readonly identityId: Uint8Array; readonly certificateHash: Uint8Array }
  | { readonly kind: "ownActivation" }
  | { readonly kind: "join"; readonly circleId: Uint8Array }
  | { readonly kind: "leave"; readonly circleId: Uint8Array }
  | { readonly kind: "enable"; readonly circleId: Uint8Array }
  | { readonly kind: "disable"; readonly circleId: Uint8Array }
  | { readonly kind: "counterExhausted" }
  | { readonly kind: "hygiene" }
  | { readonly kind: "clockReversal" };

export interface RevisionState {
  readonly desiredRevision: bigint;
  /** Highest snapshot revision processed per circle, so reprocessing does not increment. */
  readonly seenSnapshots: ReadonlyMap<string, bigint>;
  /** Certificate hash last accepted per recipient, so a replayed certificate does not increment. */
  readonly seenCertificates: ReadonlyMap<string, string>;
}

export const initialRevisionState: RevisionState = { desiredRevision: 1n, seenSnapshots: new Map(), seenCertificates: new Map() };

export interface Invalidation {
  /** The active epoch is no longer usable; allocated counters are burned. */
  readonly clearActiveEpoch: true;
  /** Outbox rows sealed under the obsolete revision and not yet handed off are cancelled. */
  readonly cancelObsoleteOutbox: true;
  readonly paused: "rotation";
}

export const INVALIDATION: Invalidation = { clearActiveEpoch: true, cancelObsoleteOutbox: true, paused: "rotation" };

/**
 * Apply one event. Returns the new state and whether the desired revision moved. Every move
 * is a rotation: the caller performs the invalidation in the same transaction (T3).
 */
export function applyAudienceEvent(state: RevisionState, event: AudienceEvent): { state: RevisionState; changed: boolean } {
  const bump = (extra?: Partial<RevisionState>): { state: RevisionState; changed: true } => ({
    state: { ...state, ...extra, desiredRevision: state.desiredRevision + 1n },
    changed: true
  });
  switch (event.kind) {
    case "snapshot": {
      const key = toHex(event.circleId);
      const seen = state.seenSnapshots.get(key) ?? 0n;
      if (event.revision <= seen) return { state, changed: false };
      const seenSnapshots = new Map(state.seenSnapshots);
      seenSnapshots.set(key, event.revision);
      return bump({ seenSnapshots });
    }
    case "deviceChanged": {
      const key = toHex(event.identityId);
      const hash = toHex(event.certificateHash);
      if (state.seenCertificates.get(key) === hash) return { state, changed: false };
      const seenCertificates = new Map(state.seenCertificates);
      seenCertificates.set(key, hash);
      return bump({ seenCertificates });
    }
    default:
      return bump();
  }
}
