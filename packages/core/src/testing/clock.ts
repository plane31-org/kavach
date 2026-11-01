import type { RetentionPolicy } from "../policy.js";

/**
 * A retention policy for tests. Three kinds: 0 is kept a day in history with a newest slot
 * (a position); 1 is kept thirty days in history with no slot, every one news (an event); 2 is a
 * one-day slot only, latest wins while queued (a state).
 */
export const testPolicy: RetentionPolicy = {
  version: 1,
  deliveryWindowMs: 86_400_000n,
  appendRetryWindowMs: 604_800_000n,
  hygieneRotationMs: 2_592_000_000n,
  maxOutboxRecords: 2000,
  maxOutboxBytes: 4 << 20,
  kinds: [
    { kind: 0, retentionMs: 86_400_000n, queue: "keepAll", history: true, newest: true, headerClass: 0 },
    { kind: 1, retentionMs: 2_592_000_000n, queue: "keepAll", history: true, newest: false, headerClass: 1 },
    { kind: 2, retentionMs: 86_400_000n, queue: "latestWins", history: false, newest: true, headerClass: 2 }
  ]
};

/** A controllable clock. */
export class TestClock {
  t = 1_700_000_000_000n;
  now = (): bigint => this.t;
  advance(ms: bigint): void {
    this.t += ms;
  }
}
