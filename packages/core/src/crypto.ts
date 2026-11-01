/**
 * The one cipher suite of Kavach v1 (protocol section 3) over a primitive backend.
 *
 * Everything here is a thin, checked wrapper: no algorithm choice, no fallback, no key
 * derivation other than the three the protocol names. Call `ready()` once before anything else;
 * it selects the portable backend unless `setCryptoBackend` chose another first.
 */
import { concat, isAllZero, u32, encodeName } from "./bytes.js";
import { KavachError } from "./errors.js";
import { currentBackend, setCryptoBackend, type BoxKeypair, type CryptoBackend, type SignKeypair as SigningKeypair } from "./crypto/backend.js";
import { nobleBackend } from "./crypto/noble.js";

export type { CryptoBackend, BoxKeypair, SigningKeypair };
export { setCryptoBackend };

/** Kept from the protocol's earlier name on purpose: changing it changes every vector. */
export const LABEL_PREFIX = "SealedStream/5/";
export const WIRE_VERSION = 5;
export const HASH_BYTES = 32;
export const KEY_BYTES = 32;
export const SEED_BYTES = 32;
export const NONCE_BYTES = 24;
export const TAG_BYTES = 16;
export const SIGNATURE_BYTES = 64;
export const PUBLIC_KEY_BYTES = 32;
export const SEALED_BOX_BYTES = 80;
export const DEVICE_ID_BYTES = 16;
/** Recovery code prefix, also kept from the earlier name. */
export const RECOVERY_CODE_PREFIX = "KV1R-";

export type Label =
  | "identity"
  | "stream"
  | "record-id"
  | "doc-hash"
  | "device-sign"
  | "device-box"
  | "account-sig"
  | "snapshot-sig"
  | "epoch-sig"
  | "record-sig"
  | "reset-sig"
  | "succession-sig"
  | "reset-keys-sig"
  | "epoch-key"
  | "wrap"
  | "record-aad"
  | "vault-aad";

/** Select a backend if none is set (the portable one) and resolve. Idempotent. */
export async function ready(): Promise<void> {
  if (!currentBackend()) {
    // The portable backend draws randomness from the Web Crypto global; Hermes has none until the
    // app installs one (the Expo helper does, from expo-crypto). Say so, rather than fail later.
    const g = globalThis as { crypto?: { getRandomValues?: unknown } };
    if (typeof g.crypto?.getRandomValues !== "function") throw new KavachError("INVALID_KEY", "ready", "no crypto.getRandomValues: install a secure random source before opening Kavach");
    setCryptoBackend(nobleBackend);
  }
}

/** The portable backend needs no loading, so it is selected on first use when nothing else was. */
function be(): CryptoBackend {
  const b = currentBackend();
  if (b) return b;
  setCryptoBackend(nobleBackend);
  return nobleBackend;
}

export function backendName(): CryptoBackend["name"] {
  return be().name;
}

function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 0x7f) throw new RangeError("label is not ASCII");
    out[i] = c;
  }
  return out;
}

/** `C(label)` = ASCII("SealedStream/5/" + label) || 0x00. */
export function C(label: Label): Uint8Array {
  return concat(ascii(LABEL_PREFIX + label), Uint8Array.of(0));
}

/** `H(x)`: BLAKE2b, 32-byte output, unkeyed. */
export function H(data: Uint8Array): Uint8Array {
  return be().blake2b(data, HASH_BYTES);
}

/** `D(seed, label)`: BLAKE2b keyed with the seed over `C(label)`, 32-byte output. */
export function D(seed: Uint8Array, label: Label): Uint8Array {
  if (seed.length !== SEED_BYTES) throw new KavachError("INVALID_KEY", "derive", "seed must be 32 bytes");
  return be().blake2b(C(label), HASH_BYTES, seed);
}

export function bodyHash(body: Uint8Array): Uint8Array {
  return H(concat(C("doc-hash"), body));
}

export function identityId(accountName: string, accountPublicKey: Uint8Array): Uint8Array {
  return H(concat(C("identity"), encodeName(accountName), accountPublicKey));
}

export function streamId(identity: Uint8Array, deviceId: Uint8Array): Uint8Array {
  return H(concat(C("stream"), identity, deviceId));
}

export function recordId(stream: Uint8Array, epoch: number, counter: number): Uint8Array {
  return H(concat(C("record-id"), stream, u32(epoch), u32(counter)));
}

export function wrapHash(wrap: Uint8Array): Uint8Array {
  return H(concat(C("wrap"), wrap));
}

export function keyCommitment(stream: Uint8Array, epoch: number, epochKey: Uint8Array): Uint8Array {
  return H(concat(C("epoch-key"), stream, u32(epoch), epochKey));
}

// Keys ---------------------------------------------------------------------------------------

/** `AK` from `accountSeed`. The only thing the account seed ever derives. */
export function accountKeypair(accountSeed: Uint8Array): SigningKeypair {
  return signingKeypairFromSeed(accountSeed);
}

/** `DSK` = Ed25519 from `D(deviceSeed, "device-sign")`. */
export function deviceSigningKeypair(deviceSeed: Uint8Array): SigningKeypair {
  return signingKeypairFromSeed(D(deviceSeed, "device-sign"));
}

/** `DEK` = `crypto_box_seed_keypair(D(deviceSeed, "device-box"))`. The seed is never used as a scalar. */
export function deviceBoxKeypair(deviceSeed: Uint8Array): BoxKeypair {
  return be().boxKeypairFromSeed(D(deviceSeed, "device-box"));
}

export function signingKeypairFromSeed(seed: Uint8Array): SigningKeypair {
  if (seed.length !== SEED_BYTES) throw new KavachError("INVALID_KEY", "keypair", "seed must be 32 bytes");
  return be().signKeypairFromSeed(seed);
}

/** An Ed25519 public key must be a canonical point on the main subgroup and not the identity. */
export function assertValidSigningKey(publicKey: Uint8Array, stage = "verify"): void {
  if (publicKey.length !== PUBLIC_KEY_BYTES || !be().isValidSignPoint(publicKey)) {
    throw new KavachError("INVALID_KEY", stage, "invalid Ed25519 public key");
  }
}

/**
 * An X25519 public key must not yield an all-zero shared secret. A fixed non-secret scalar
 * probes it; libsodium refuses the low-order result.
 */
const PROBE_SCALAR = new Uint8Array(32).fill(0x42);
export function assertValidBoxKey(publicKey: Uint8Array, stage = "verify"): void {
  if (publicKey.length !== PUBLIC_KEY_BYTES || isAllZero(publicKey)) {
    throw new KavachError("INVALID_KEY", stage, "invalid X25519 public key");
  }
  try {
    const shared = be().scalarMult(PROBE_SCALAR, publicKey);
    if (isAllZero(shared)) throw new Error("zero");
  } catch {
    throw new KavachError("INVALID_KEY", stage, "low-order X25519 public key");
  }
}

// Signatures ----------------------------------------------------------------------------------

/** Detached Ed25519 over `C(label) || body`. Not Ed25519ph, no intermediate hash. */
export function sign(secretKey: Uint8Array, label: Label, body: Uint8Array): Uint8Array {
  return be().signDetached(concat(C(label), body), secretKey);
}

// The Ed25519 group order L, little-endian, for the canonical-scalar check.
const L = Uint8Array.from([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
]);

function isCanonicalScalar(s: Uint8Array): boolean {
  // s < L, comparing little-endian from the most significant byte.
  for (let i = 31; i >= 0; i--) {
    const a = s[i] ?? 0;
    const b = L[i] ?? 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false;
}

/**
 * Verify a detached signature. Throws `INVALID_KEY` for an invalid or small-order key and
 * `BAD_SIGNATURE` for anything else that does not verify, including a non-canonical scalar.
 */
export function verify(publicKey: Uint8Array, label: Label, body: Uint8Array, signature: Uint8Array, stage = "verify"): void {
  assertValidSigningKey(publicKey, stage);
  if (signature.length !== SIGNATURE_BYTES || !isCanonicalScalar(signature.subarray(32))) {
    throw new KavachError("BAD_SIGNATURE", stage);
  }
  if (!be().verifyDetached(signature, concat(C(label), body), publicKey)) throw new KavachError("BAD_SIGNATURE", stage);
}

// AEAD ---------------------------------------------------------------------------------------

/** XChaCha20-Poly1305: returns ciphertext with the 16-byte tag appended. */
export function aeadSeal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (key.length !== KEY_BYTES || nonce.length !== NONCE_BYTES) throw new KavachError("INVALID_KEY", "aead");
  return be().aeadEncrypt(plaintext, aad, nonce, key);
}

export function aeadOpen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertextAndTag: Uint8Array, stage = "decrypt"): Uint8Array {
  if (key.length !== KEY_BYTES || nonce.length !== NONCE_BYTES) throw new KavachError("INVALID_KEY", stage);
  try {
    return be().aeadDecrypt(ciphertextAndTag, aad, nonce, key);
  } catch {
    throw new KavachError("DECRYPT_FAILED", stage);
  }
}

// Sealed boxes -------------------------------------------------------------------------------

/** The sealed-box nonce: BLAKE2b-24 over the ephemeral and recipient public keys, as libsodium defines it. */
export function sealedBoxNonce(ephemeralPublicKey: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  return be().blake2b(concat(ephemeralPublicKey, recipientPublicKey), NONCE_BYTES);
}

/** `crypto_box_seal` with a given ephemeral keypair (tests reproduce fixture wraps with it). */
export function sealBoxWith(epochKey: Uint8Array, recipientPublicKey: Uint8Array, ephemeral: BoxKeypair): Uint8Array {
  const nonce = sealedBoxNonce(ephemeral.publicKey, recipientPublicKey);
  return concat(ephemeral.publicKey, be().boxEasy(epochKey, nonce, recipientPublicKey, ephemeral.secretKey));
}

/** `crypto_box_seal` of a 32-byte epoch key: exactly 80 bytes. */
export function sealBox(epochKey: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  if (epochKey.length !== KEY_BYTES) throw new KavachError("INVALID_KEY", "seal");
  assertValidBoxKey(recipientPublicKey, "seal");
  return sealBoxWith(epochKey, recipientPublicKey, be().boxKeypair());
}

export function openSealedBox(box: Uint8Array, recipient: BoxKeypair, stage = "open-wrap"): Uint8Array {
  if (box.length !== SEALED_BOX_BYTES) throw new KavachError("MALFORMED", stage, "wrap must be 80 bytes");
  try {
    const ephemeralPublic = box.subarray(0, PUBLIC_KEY_BYTES);
    const nonce = sealedBoxNonce(ephemeralPublic, recipient.publicKey);
    return be().boxOpenEasy(box.subarray(PUBLIC_KEY_BYTES), nonce, ephemeralPublic, recipient.secretKey);
  } catch {
    throw new KavachError("DECRYPT_FAILED", stage);
  }
}

/** `crypto_box_seed_keypair`, exposed for tests that rebuild fixture wraps from their ephemeral seeds. */
export function boxKeypairFromSeed(seed: Uint8Array): BoxKeypair {
  return be().boxKeypairFromSeed(seed);
}

// Randomness and hygiene ----------------------------------------------------------------------

export function randomBytes(length: number): Uint8Array {
  return be().randomBytes(length);
}

/** Best-effort zeroisation. JavaScript gives no guarantee; the protocol says so. */
export function zero(bytes: Uint8Array): void {
  be().memzero(bytes);
}
