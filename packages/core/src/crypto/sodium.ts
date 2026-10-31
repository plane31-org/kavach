/**
 * The libsodium backend (wasm). Loaded only when asked for, so the default bundle never carries
 * the wasm; use it on Node, where it is faster than the portable backend, and to cross-check it.
 */
import type { BoxKeypair, CryptoBackend, SignKeypair } from "./backend.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

export async function loadSodiumBackend(): Promise<CryptoBackend> {
  const mod = (await import("libsodium-wrappers-sumo")) as unknown as { default?: Sodium } & Sodium;
  const sodium: Sodium = mod.default ?? mod;
  await sodium.ready;
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
    isValidSignPoint: (publicKey) => publicKey.length === 32 && sodium.crypto_core_ed25519_is_valid_point(publicKey),
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
    memzero: (bytes) => sodium.memzero(bytes)
  };
}
