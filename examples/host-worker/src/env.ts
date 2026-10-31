export interface Env {
  DIRECTORY: D1Database;
  STREAMS: DurableObjectNamespace;
  DELIVERY_WINDOW_MS: string;
  APPEND_RETRY_WINDOW_MS: string;
  REQUEST_TTL_MS: string;
  /** Hex seed of the operational reset key and its 16-byte id; absent means resets are refused. */
  RESET_OPERATIONAL_SEED?: string;
  RESET_KEY_ID?: string;
  /** Hex wire of the current management-signed key list. */
  RESET_KEY_LIST?: string;
  /** "true" lets a request carry X-Test-Now to drive the host clock. Tests only. */
  ALLOW_TEST_CLOCK?: string;
}
