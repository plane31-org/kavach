/** The versioned retention policy a profile passes to `open()` (protocol section 13). No defaults. */
import { KavachError } from "./errors.js";

export interface RetentionPolicy {
  readonly version: number;
  readonly deliveryWindowMs: bigint;
  readonly appendRetryWindowMs: bigint;
  readonly locationHistoryMs: bigint;
  readonly checkInHistoryMs: bigint;
  readonly hygieneRotationMs: bigint;
  readonly maxOutboxRecords: number;
  readonly maxOutboxBytes: number;
}

const FIELDS: readonly (keyof RetentionPolicy)[] = [
  "version",
  "deliveryWindowMs",
  "appendRetryWindowMs",
  "locationHistoryMs",
  "checkInHistoryMs",
  "hygieneRotationMs",
  "maxOutboxRecords",
  "maxOutboxBytes"
];

/** A missing or malformed policy is rejected; the SDK never substitutes defaults. */
export function validatePolicy(policy: unknown): RetentionPolicy {
  const stage = "policy";
  if (typeof policy !== "object" || policy === null) throw new KavachError("MALFORMED", stage, "retention policy missing");
  const p = policy as Record<string, unknown>;
  for (const f of FIELDS) if (!(f in p)) throw new KavachError("MALFORMED", stage, `retention policy lacks ${f}`);
  const big = (f: keyof RetentionPolicy): bigint => {
    const v = p[f];
    if (typeof v !== "bigint" || v <= 0n) throw new KavachError("MALFORMED", stage, `${f} must be a positive bigint`);
    return v;
  };
  const int = (f: keyof RetentionPolicy): number => {
    const v = p[f];
    if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) throw new KavachError("MALFORMED", stage, `${f} must be a positive integer`);
    return v;
  };
  return {
    version: int("version"),
    deliveryWindowMs: big("deliveryWindowMs"),
    appendRetryWindowMs: big("appendRetryWindowMs"),
    locationHistoryMs: big("locationHistoryMs"),
    checkInHistoryMs: big("checkInHistoryMs"),
    hygieneRotationMs: big("hygieneRotationMs"),
    maxOutboxRecords: int("maxOutboxRecords"),
    maxOutboxBytes: int("maxOutboxBytes")
  };
}
