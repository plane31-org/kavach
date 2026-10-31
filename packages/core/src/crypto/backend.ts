/**
 * The primitive backend behind `crypto.ts`. Two implementations exist: `noble` (pure
 * JavaScript, runs on Hermes and in workerd, the default) and `sodium` (libsodium's wasm, for
 * Node and tests). Both are checked against the same vectors; the protocol never sees which one
 * is loaded.
 */
export interface SignKeypair {
  readonly publicKey: Uint8Array; // 32
  readonly secretKey: Uint8Array; // 64, libsodium layout: seed || public
}

export interface BoxKeypair {
  readonly publicKey: Uint8Array; // 32
  readonly secretKey: Uint8Array; // 32
}

export interface CryptoBackend {
  readonly name: "noble" | "sodium";
  blake2b(data: Uint8Array, outLen: number, key?: Uint8Array): Uint8Array;
  randomBytes(length: number): Uint8Array;
  signKeypairFromSeed(seed: Uint8Array): SignKeypair;
  signDetached(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verifyDetached(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
  /** Canonical, on the curve, on the main subgroup, not the identity. */
  isValidSignPoint(publicKey: Uint8Array): boolean;
  /** `crypto_box_seed_keypair`: scalar = SHA-512(seed)[0..32], public = X25519 base point multiple. */
  boxKeypairFromSeed(seed: Uint8Array): BoxKeypair;
  boxKeypair(): BoxKeypair;
  /** X25519; throws on an all-zero shared secret. */
  scalarMult(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  /** `crypto_box_easy`: XSalsa20-Poly1305 under HSalsa20(X25519(sk, pk)); output mac || ciphertext. */
  boxEasy(message: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
  boxOpenEasy(box: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
  /** XChaCha20-Poly1305 with the tag appended. */
  aeadEncrypt(plaintext: Uint8Array, aad: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  aeadDecrypt(ciphertextAndTag: Uint8Array, aad: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  memzero(bytes: Uint8Array): void;
}

let current: CryptoBackend | undefined;

export function setCryptoBackend(backend: CryptoBackend): void {
  current = backend;
}

export function currentBackend(): CryptoBackend | undefined {
  return current;
}
