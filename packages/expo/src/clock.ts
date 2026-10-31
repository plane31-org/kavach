/**
 * The trusted clock for the reset-key rules (protocol section 12): the platform clock under the
 * accurate-clock assumption, checked against a durable high-water mark and monotonic elapsed
 * time. A reading below the high-water mark is not trusted.
 */
import { u64, type SecretStore } from "@kavach/core/adapters";

export interface HighWaterStorage {
  get(): Promise<bigint | undefined>;
  set(value: bigint): Promise<void>;
}

/** The high-water mark kept next to the other roots in the secret store. */
export function highWaterInSecretStore(secrets: SecretStore & { get(name: string): Promise<Uint8Array | undefined>; set(name: string, value: Uint8Array): Promise<void> }): HighWaterStorage {
  const NAME = "clockHighWater";
  return {
    async get() {
      const v = await secrets.get(NAME);
      return v && v.length === 8 ? new DataView(v.buffer, v.byteOffset, 8).getBigUint64(0, false) : undefined;
    },
    async set(value) {
      await secrets.set(NAME, u64(value));
    }
  };
}

export class TrustedClock {
  private highWater: bigint | undefined;
  private readonly startedWall: bigint;
  private readonly startedMono: number;

  constructor(
    private readonly storage: HighWaterStorage,
    private readonly wall: () => bigint = () => BigInt(Date.now()),
    private readonly mono: () => number = () => performanceNow()
  ) {
    this.startedWall = wall();
    this.startedMono = mono();
  }

  async load(): Promise<void> {
    this.highWater = await this.storage.get();
  }

  /** Wall time in milliseconds, for timestamps. */
  now(): bigint {
    return this.wall();
  }

  /**
   * A time usable for the reset-key rules, or `undefined` when the clock went backwards past the
   * durable high-water mark or jumped against monotonic time by more than a minute.
   */
  async trustedNow(): Promise<bigint | undefined> {
    const now = this.wall();
    const expected = this.startedWall + BigInt(Math.round(this.mono() - this.startedMono));
    const drift = now > expected ? now - expected : expected - now;
    if (drift > 60_000n) return undefined;
    if (this.highWater !== undefined && now < this.highWater) return undefined;
    if (this.highWater === undefined || now > this.highWater) {
      this.highWater = now;
      await this.storage.set(now);
    }
    return now;
  }
}

function performanceNow(): number {
  const p = (globalThis as { performance?: { now(): number } }).performance;
  return p ? p.now() : Number(Date.now());
}
