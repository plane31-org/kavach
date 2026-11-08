/**
 * A libsodium backend over any object with libsodium's JavaScript API: `libsodium-wrappers-sumo`
 * on Node (wasm), or a native binding on a phone (`react-native-libsodium` over JSI), where it
 * replaces the portable backend's pure-JavaScript Ed25519 and X25519 with the C implementation.
 * The caller awaits `sodium.ready` before building the backend. Both backends pass the same vectors.
 */
import type { BoxKeypair, CryptoBackend, SignKeypair } from "./backend.js";
import { nobleBackend } from "./noble.js";

/** The subset of libsodium's API the backend needs; `crypto_core_ed25519_is_valid_point` is optional (a sumo build has it). */
export interface SodiumLike {
  crypto_generichash(outLen: number, data: Uint8Array, key?: Uint8Array | null): Uint8Array;
  randombytes_buf(length: number): Uint8Array;
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_sign_detached(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
  crypto_core_ed25519_is_valid_point?(point: Uint8Array): boolean;
  crypto_box_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_box_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_scalarmult(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  crypto_box_easy(message: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
  crypto_box_open_easy(box: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
  crypto_aead_xchacha20poly1305_ietf_encrypt(message: Uint8Array, aad: Uint8Array | null, secretNonce: Uint8Array | null, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_aead_xchacha20poly1305_ietf_decrypt(secretNonce: Uint8Array | null, ciphertext: Uint8Array, aad: Uint8Array | null, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  memzero?(bytes: Uint8Array): void;
}

/**
 * Build the backend over a ready libsodium object. Where the binding lacks
 * `crypto_core_ed25519_is_valid_point` (a non-sumo build), the public-key validity check of
 * section 3 runs on the portable implementation: it is a once-per-certificate check, so the
 * cost does not matter, and the rule is the same.
 */
export function sodiumBackend(sodium: SodiumLike): CryptoBackend {
  const validPoint = sodium.crypto_core_ed25519_is_valid_point?.bind(sodium);
  return {
    name: "sodium",
    blake2b: (data, outLen, key) => sodium.crypto_generichash(outLen, data, key ?? null),
    randomBytes: (length) => sodium.randombytes_buf(length),
    signKeypairFromSeed(seed): SignKeypair {
      const kp = sodium.crypto_sign_seed_keypair(seed);
      return { publicKey: kp.publicKey, secretKey: kp.privateKey };
    },
    signDetached: (message, secretKey) => sodium.crypto_sign_detached(message, secretKey),
    verifyDetached(signature, message, publicKey) {
      try {
        return sodium.crypto_sign_verify_detached(signature, message, publicKey);
      } catch {
        return false;
      }
    },
    isValidSignPoint: (publicKey) => (validPoint ? publicKey.length === 32 && validPoint(publicKey) : nobleBackend.isValidSignPoint(publicKey)),
    boxKeypairFromSeed(seed): BoxKeypair {
      const kp = sodium.crypto_box_seed_keypair(seed);
      return { publicKey: kp.publicKey, secretKey: kp.privateKey };
    },
    boxKeypair(): BoxKeypair {
      const kp = sodium.crypto_box_keypair();
      return { publicKey: kp.publicKey, secretKey: kp.privateKey };
    },
    scalarMult: (secretKey, publicKey) => sodium.crypto_scalarmult(secretKey, publicKey),
    boxEasy: (message, nonce, publicKey, secretKey) => sodium.crypto_box_easy(message, nonce, publicKey, secretKey),
    boxOpenEasy: (box, nonce, publicKey, secretKey) => sodium.crypto_box_open_easy(box, nonce, publicKey, secretKey),
    aeadEncrypt: (plaintext, aad, nonce, key) => sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key),
    aeadDecrypt: (ciphertextAndTag, aad, nonce, key) => sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertextAndTag, aad, nonce, key),
    memzero: (bytes) => (sodium.memzero ? sodium.memzero(bytes) : bytes.fill(0))
  };
}
