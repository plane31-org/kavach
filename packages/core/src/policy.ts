/**
 * The versioned retention policy a profile passes to `open()` (protocol section 13): the global
 * windows, and one declaration per record kind the product uses. The SDK treats a kind as an
 * opaque small integer whose behaviour is what the declaration says. No defaults.
 */
import { KavachError } from "./errors.js";

/** How the SDK treats one record kind; what the kind means is the product's. */
export interface KindDeclaration {
  /** The kind number carried by the record. Until revision 8 the wire carries 0, 1 or 2. */
  readonly kind: number;
  /** How long a reader keeps records and the newest slot's payload, from `sentAt`. */
  readonly retentionMs: bigint;
  /** `keepAll`: every queued record is sent. `latestWins`: a newer queued record of this kind cancels the older one (`superseded`). */
  readonly queue: "keepAll" | "latestWins";
  /** Whether records are kept in indexed, pageable history. */
  readonly history: boolean;
  /** Whether one newest-per-author slot is kept, from the author's current device, ordered by event time. */
  readonly newest: boolean;
  /**
   * The header bits the relay may see for this kind (0 to 7, 0 when absent), for routing and
   * notifications without content; what each value means is the product's and its host's. Values
   * 4 to 7 need revision 11 on the host and every reader first: an earlier reader rejects them.
   */
  readonly headerClass: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;
}

/**
 * Which replacement models the product enables (protocol section 4, revision 9): `continuity`,
 * the device holds the account key, recovered through the platform or a code, and the host can
 * never rebind a key; `recovery`, the host's authority signs a succession to fresh keys after
 * the product's fresh authentication; or `both`. A property of the app build, enforced by every
 * verifying peer: a client without `recovery` rejects every succession document.
 */
export type ReplacementModel = "continuity" | "recovery" | "both";

export interface RetentionPolicy {
  readonly version: number;
  readonly replacement: ReplacementModel;
  readonly deliveryWindowMs: bigint;
  readonly appendRetryWindowMs: bigint;
  readonly hygieneRotationMs: bigint;
  readonly maxOutboxRecords: number;
  readonly maxOutboxBytes: number;
  readonly kinds: readonly KindDeclaration[];
}

/** The largest kind the envelope carries. */
export const MAX_WIRE_KIND = 255;

const FIELDS: readonly (keyof RetentionPolicy)[] = ["version", "replacement", "deliveryWindowMs", "appendRetryWindowMs", "hygieneRotationMs", "maxOutboxRecords", "maxOutboxBytes", "kinds"];

/** A missing or malformed policy is rejected; the SDK never substitutes defaults. */
export function validatePolicy(policy: unknown): RetentionPolicy {
  const stage = "policy";
  if (typeof policy !== "object" || policy === null) throw new KavachError("MALFORMED", stage, "retention policy missing");
  const p = policy as Record<string, unknown>;
  for (const f of FIELDS) if (!(f in p)) throw new KavachError("MALFORMED", stage, `retention policy lacks ${f}`);
  const big = (f: string, v: unknown): bigint => {
    if (typeof v !== "bigint" || v <= 0n) throw new KavachError("MALFORMED", stage, `${f} must be a positive bigint`);
    return v;
  };
  const int = (f: string, v: unknown): number => {
    if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) throw new KavachError("MALFORMED", stage, `${f} must be a positive integer`);
    return v;
  };
  if (!Array.isArray(p.kinds) || p.kinds.length === 0) throw new KavachError("MALFORMED", stage, "kinds must declare at least one kind");
  const seen = new Set<number>();
  const kinds: KindDeclaration[] = p.kinds.map((raw: unknown, i: number) => {
    if (typeof raw !== "object" || raw === null) throw new KavachError("MALFORMED", stage, `kinds[${i}] must be an object`);
    const k = raw as Record<string, unknown>;
    const kind = k.kind;
    if (typeof kind !== "number" || !Number.isInteger(kind) || kind < 0 || kind > MAX_WIRE_KIND) throw new KavachError("MALFORMED", stage, `kinds[${i}].kind must be an integer from 0 to ${MAX_WIRE_KIND}`);
    if (seen.has(kind)) throw new KavachError("MALFORMED", stage, `kind ${kind} declared twice`);
    seen.add(kind);
    if (k.queue !== "keepAll" && k.queue !== "latestWins") throw new KavachError("MALFORMED", stage, `kinds[${i}].queue must be keepAll or latestWins`);
    if (typeof k.history !== "boolean" || typeof k.newest !== "boolean") throw new KavachError("MALFORMED", stage, `kinds[${i}].history and .newest must be booleans`);
    if (!k.history && !k.newest) throw new KavachError("MALFORMED", stage, `kinds[${i}] keeps nothing: declare history or newest`);
    const headerClass = k.headerClass ?? 0;
    if (typeof headerClass !== "number" || !Number.isInteger(headerClass) || headerClass < 0 || headerClass > 7) throw new KavachError("MALFORMED", stage, `kinds[${i}].headerClass must be 0 to 7`);
    return { kind, retentionMs: big(`kinds[${i}].retentionMs`, k.retentionMs), queue: k.queue, history: k.history, newest: k.newest, headerClass: headerClass as KindDeclaration["headerClass"] };
  });
  if (p.replacement !== "continuity" && p.replacement !== "recovery" && p.replacement !== "both") throw new KavachError("MALFORMED", stage, "replacement must be continuity, recovery or both");
  return {
    version: int("version", p.version),
    replacement: p.replacement,
    deliveryWindowMs: big("deliveryWindowMs", p.deliveryWindowMs),
    appendRetryWindowMs: big("appendRetryWindowMs", p.appendRetryWindowMs),
    hygieneRotationMs: big("hygieneRotationMs", p.hygieneRotationMs),
    maxOutboxRecords: int("maxOutboxRecords", p.maxOutboxRecords),
    maxOutboxBytes: int("maxOutboxBytes", p.maxOutboxBytes),
    kinds
  };
}

/** The declaration of a kind, or `undefined` for one the product did not declare. */
export function kindOf(policy: RetentionPolicy, kind: number): KindDeclaration | undefined {
  return policy.kinds.find((k) => k.kind === kind);
}

/** The kinds kept in history, in declaration order. */
export function historyKinds(policy: RetentionPolicy): readonly number[] {
  return policy.kinds.filter((k) => k.history).map((k) => k.kind);
}

/** Whether a deployment accepts successions at all; a peer without it rejects every type 9 document. */
export function acceptsSuccession(policy: RetentionPolicy): boolean {
  return policy.replacement !== "continuity";
}

/** Whether a device may replace itself by holding the account key (restoreAccount). */
export function allowsContinuity(policy: RetentionPolicy): boolean {
  return policy.replacement !== "recovery";
}
