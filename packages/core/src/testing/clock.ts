import type { RetentionPolicy } from "../policy.js";

/** A retention policy for tests: the Moyo profile's values. */
export const testPolicy: RetentionPolicy = {
  version: 1,
  deliveryWindowMs: 86_400_000n,
  appendRetryWindowMs: 604_800_000n,
  locationHistoryMs: 86_400_000n,
  checkInHistoryMs: 2_592_000_000n,
  hygieneRotationMs: 2_592_000_000n,
  maxOutboxRecords: 2000,
  maxOutboxBytes: 4 << 20
};

/** A controllable clock. */
export class TestClock {
  t = 1_700_000_000_000n;
  now = (): bigint => this.t;
  advance(ms: bigint): void {
    this.t += ms;
  }
}
