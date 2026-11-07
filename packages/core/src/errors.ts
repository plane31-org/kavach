/** Error codes of Kavach v1, protocol section 14. The set is closed: new codes are a protocol change. */
export type ErrorCode =
  // Parsing
  | "SIZE_LIMIT"
  | "MALFORMED"
  | "UNSUPPORTED_VERSION"
  | "UNSUPPORTED_TYPE"
  | "BAD_PAYLOAD"
  // Authentication
  | "INVALID_KEY"
  | "BAD_SIGNATURE"
  | "DECRYPT_FAILED"
  | "WRAP_HASH_MISMATCH"
  | "KEY_COMMITMENT_MISMATCH"
  // Trust and state
  | "ACCOUNT_KEY_CHANGED"
  | "ACCOUNT_RECOVERY_REQUIRED"
  | "DEVICE_ROLLBACK"
  | "DEVICE_ID_REUSED"
  | "SUPERSEDED_DEVICE"
  | "VAULT_BINDING"
  | "RESET_BINDING"
  | "RESET_KEYS_REQUIRED"
  | "RESET_KEY_REVOKED"
  | "RESET_CLOCK_UNTRUSTED"
  | "ROLLBACK"
  | "EQUIVOCATION"
  | "METADATA_REQUIRED"
  | "KEY_PENDING"
  | "NOT_AUTHORIZED"
  | "ROTATION_REQUIRED"
  | "COUNTER_EXHAUSTED"
  | "RECIPIENT_LIMIT"
  /** A succession does not bind: certificate, identity, generation, account or previous state do not match (revision 9). */
  | "SUCCESSION_BINDING"
  /** A succession names a retired identity as previous or new; retirement is permanent. */
  | "SUPERSEDED_IDENTITY"
  /** Account recovery: the proposal has no valid authorization, or it expired, or a definitive conflict ended the proposal. */
  | "AUTHORIZATION_REQUIRED"
  | "AUTHORIZATION_EXPIRED"
  | "REPLACEMENT_CONFLICT"
  /** The outcome of a submitted succession is not yet known; retry or look it up. */
  | "SUCCESSION_PENDING"
  // Delivery
  | "CLOCK_SKEW"
  | "EXPIRED"
  | "QUEUE_FULL"
  | "CURSOR_OUT_OF_RANGE"
  | "STALE_APPEND"
  // Storage and transport
  | "LOCKED"
  | "CLOSED"
  | "RECOVERY_REQUIRED"
  | "STORAGE_FAILURE"
  | "RATE_LIMITED"
  /** The host could not be reached or did not answer in time; the same call may succeed later. A transport raises it, never a plain error. */
  | "NETWORK";

const RETRYABLE: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  "KEY_PENDING",
  "METADATA_REQUIRED",
  "RESET_KEYS_REQUIRED",
  "ROTATION_REQUIRED",
  "LOCKED",
  "STORAGE_FAILURE",
  "NETWORK",
  "RATE_LIMITED",
  "SUCCESSION_PENDING"
]);

/**
 * Every failure the SDK reports. `code` is one of the protocol's codes, `stage` is a safe
 * stage name for logs (never a secret, a payload or an identifier), `retryable` says whether
 * the same call may succeed later without any change of state.
 */
export class KavachError extends Error {
  readonly code: ErrorCode;
  readonly stage: string;
  readonly retryable: boolean;
  /** On `RATE_LIMITED`: how long the host asked the client to wait, when it said. */
  readonly retryAfterMs: number | undefined;

  constructor(code: ErrorCode, stage = "unknown", message?: string, options: { retryAfterMs?: number } = {}) {
    super(message ?? `${code} at ${stage}`);
    this.name = "KavachError";
    this.code = code;
    this.stage = stage;
    this.retryable = RETRYABLE.has(code);
    this.retryAfterMs = options.retryAfterMs;
  }
}

export function isKavachError(value: unknown, code?: ErrorCode): value is KavachError {
  return value instanceof KavachError && (code === undefined || value.code === code);
}
