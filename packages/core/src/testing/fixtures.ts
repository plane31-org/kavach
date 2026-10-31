/**
 * Protocol state a test builds by hand where an application would let the client build it:
 * accounts, devices and certificates for store tests, and a signed reset key list for a fake
 * or real host. Call `ready()` first.
 */
import { buildResetKeyList } from "../codec.js";
import { C, H, signingKeypairFromSeed, type SigningKeypair } from "../crypto.js";

export { accountKeypair, identityId } from "../crypto.js";
export { certify, deviceFromSeed, newDevice, openAccount, type DeviceKeys, type OwnAccount } from "../identity.js";

export interface TestResetKeys {
  /** The deployment's management keypair, derived from a fixed seed. */
  readonly management: SigningKeypair;
  /** The operational keypair that signs reset receipts, derived from a fixed seed. */
  readonly operational: SigningKeypair;
  readonly operationalKeyId: Uint8Array;
}

/** Deterministic management and operational keys: management seed H(C("identity")), operational seed H(C("stream")), key id 07x16. */
export function testResetKeys(): TestResetKeys {
  return {
    management: signingKeypairFromSeed(H(C("identity"))),
    operational: signingKeypairFromSeed(H(C("stream"))),
    operationalKeyId: new Uint8Array(16).fill(7)
  };
}

/** A key list of version 1, issued at `now` and valid for thirty days, signed by the management key. */
export function testResetKeyList(keys: TestResetKeys, now: bigint): Uint8Array {
  return buildResetKeyList(
    { version: 1n, issuedAt: now, expiresAt: now + 2_592_000_000n, keys: [{ keyId: keys.operationalKeyId, publicKey: keys.operational.publicKey }] },
    keys.management.secretKey
  );
}
