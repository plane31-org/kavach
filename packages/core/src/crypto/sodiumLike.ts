/**
 * A libsodium backend over any object with libsodium's JavaScript API: `libsodium-wrappers-sumo`
 * on Node (wasm), or a native binding on a phone (`react-native-libsodium` over JSI), where it
 * replaces the portable backend's pure-JavaScript Ed25519 and X25519 with the C implementation.
 *
 * Bindings differ from libsodium's reference API in small ways (react-native-libsodium 1.7 has
 * no `crypto_scalarmult`, no `memzero`, no `crypto_core_ed25519_is_valid_point`, and its AEAD
 * takes only string associated data, while the protocol's is binary). So the backend is built per
 * function: each one the binding provides is checked once against the portable implementation
 * on known inputs, and a function the binding lacks or gets wrong on a type it does not support
 * falls back to the portable one, while a function that answers differently on the same input is
 * refused outright, since silently wrong bytes would be worse than slow ones. The caller awaits
 * `sodium.ready` before building. Both backends pass the same vectors.
 */
import { KavachError } from "../errors.js";
import type { BoxKeypair, CryptoBackend, SignKeypair } from "./backend.js";
import { nobleBackend } from "./noble.js";

/** The subset of libsodium's API the backend can use; everything but signing, boxing and hashing may be absent. */
export interface SodiumLike {
  crypto_generichash(outLen: number, data: Uint8Array, key?: Uint8Array | null): Uint8Array;
  randombytes_buf(length: number): Uint8Array;
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_sign_detached(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
  crypto_core_ed25519_is_valid_point?(point: Uint8Array): boolean;
  crypto_box_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_box_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_scalarmult?(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  crypto_box_easy(message: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
  crypto_box_open_easy(box: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
  crypto_aead_xchacha20poly1305_ietf_encrypt?(message: Uint8Array, aad: Uint8Array | null, secretNonce: Uint8Array | null, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_aead_xchacha20poly1305_ietf_decrypt?(secretNonce: Uint8Array | null, ciphertext: Uint8Array, aad: Uint8Array | null, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  memzero?(bytes: Uint8Array): void;
}

/** Which of the backend's operations run on the binding and which on the portable implementation, after the build-time check. */
export interface SodiumBackendReport {
  readonly native: readonly string[];
  readonly portable: readonly string[];
}

const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
/** The X25519 base point, for deriving a public key from a secret scalar on the portable implementation. */
const X25519_BASE = Uint8Array.from([9, ...new Array<number>(31).fill(0)]);

/** Build the backend; see the module comment for how each function is checked. */
export function sodiumBackend(sodium: SodiumLike): CryptoBackend {
  return buildSodiumBackend(sodium).backend;
}

/** One build per binding object: the checks run once in a JavaScript context, however often the same binding is installed. */
const built = new WeakMap<SodiumLike, { backend: CryptoBackend; report: SodiumBackendReport }>();

export function buildSodiumBackend(sodium: SodiumLike): { backend: CryptoBackend; report: SodiumBackendReport } {
  const cached = built.get(sodium);
  if (cached) return cached;
  const result = checkAndBuild(sodium);
  built.set(sodium, result);
  return result;
}

function checkAndBuild(sodium: SodiumLike): { backend: CryptoBackend; report: SodiumBackendReport } {
  const stage = "sodiumBackend";
  const native: string[] = [];
  const portable: string[] = [];
  const n = nobleBackend;
  // Known inputs: deterministic, so the check is the same on every device.
  const seed = Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff);
  const message = Uint8Array.from({ length: 70 }, (_, i) => (i * 29 + 3) & 0xff);
  const nonce24 = Uint8Array.from({ length: 24 }, (_, i) => (i * 13 + 5) & 0xff);
  const key32 = Uint8Array.from({ length: 32 }, (_, i) => (255 - i * 7) & 0xff);
  const aad = Uint8Array.from([0, 1, 2, 250, 251, 252]);

  /** A required function: present and agreeing with the portable implementation, or the binding is refused. */
  const required = (name: string, check: () => boolean): void => {
    let ok = false;
    try {
      ok = check();
    } catch {
      ok = false;
    }
    if (!ok) throw new KavachError("INVALID_KEY", stage, `${name} is missing or disagrees with the portable implementation; the binding cannot be used`);
    native.push(name);
  };
  /** An optional function: used when present and agreeing on the protocol's input types, portable otherwise. */
  const optional = (name: string, present: boolean, check: () => boolean): boolean => {
    let ok = false;
    if (present) {
      try {
        ok = check();
      } catch {
        ok = false;
      }
    }
    (ok ? native : portable).push(name);
    return ok;
  };

  const nSign = n.signKeypairFromSeed(seed);
  required("signKeypairFromSeed", () => {
    const kp = sodium.crypto_sign_seed_keypair(seed);
    return same(kp.publicKey, nSign.publicKey) && same(kp.privateKey, nSign.secretKey);
  });
  required("signDetached", () => same(sodium.crypto_sign_detached(message, nSign.secretKey), n.signDetached(message, nSign.secretKey)));
  required("verifyDetached", () => sodium.crypto_sign_verify_detached(n.signDetached(message, nSign.secretKey), message, nSign.publicKey) === true && sodium.crypto_sign_verify_detached(n.signDetached(message, nSign.secretKey), nonce24, nSign.publicKey) === false);
  required("blake2b", () => same(sodium.crypto_generichash(32, message, null), n.blake2b(message, 32)) && same(sodium.crypto_generichash(64, message, key32), n.blake2b(message, 64, key32)));
  const nBox = n.boxKeypairFromSeed(seed);
  required("boxKeypairFromSeed", () => {
    const kp = sodium.crypto_box_seed_keypair(seed);
    return same(kp.publicKey, nBox.publicKey) && same(kp.privateKey, nBox.secretKey);
  });
  required("boxKeypair", () => {
    // A fresh keypair cannot be compared with a known one; its public key must be the one its secret derives.
    const kp = sodium.crypto_box_keypair();
    return kp.publicKey.length === 32 && kp.privateKey.length === 32 && same(kp.publicKey, n.scalarMult(kp.privateKey, X25519_BASE));
  });
  const other = n.boxKeypairFromSeed(key32);
  required("boxEasy", () => same(sodium.crypto_box_easy(message, nonce24, other.publicKey, nBox.secretKey), n.boxEasy(message, nonce24, other.publicKey, nBox.secretKey)));
  required("boxOpenEasy", () => same(sodium.crypto_box_open_easy(n.boxEasy(message, nonce24, other.publicKey, nBox.secretKey), nonce24, nBox.publicKey, other.secretKey), message));
  required("randomBytes", () => sodium.randombytes_buf(16).length === 16);
  const scalarMultNative = optional("scalarMult", typeof sodium.crypto_scalarmult === "function", () => same(sodium.crypto_scalarmult?.(nBox.secretKey, other.publicKey) ?? new Uint8Array(), n.scalarMult(nBox.secretKey, other.publicKey)));
  const aeadNative = optional("aead", typeof sodium.crypto_aead_xchacha20poly1305_ietf_encrypt === "function" && typeof sodium.crypto_aead_xchacha20poly1305_ietf_decrypt === "function", () => {
    // The protocol's associated data is binary; a binding that takes only strings throws here and falls back.
    const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt?.(message, aad, null, nonce24, key32) ?? new Uint8Array();
    const opened = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt?.(null, n.aeadEncrypt(message, aad, nonce24, key32), aad, nonce24, key32) ?? new Uint8Array();
    return same(sealed, n.aeadEncrypt(message, aad, nonce24, key32)) && same(opened, message);
  });
  const validPointNative = optional("isValidSignPoint", typeof sodium.crypto_core_ed25519_is_valid_point === "function", () => sodium.crypto_core_ed25519_is_valid_point?.(nSign.publicKey) === true && sodium.crypto_core_ed25519_is_valid_point?.(new Uint8Array(32)) === false);
  const memzeroNative = optional("memzero", typeof sodium.memzero === "function", () => {
    const probe = Uint8Array.from([1, 2, 3]);
    sodium.memzero?.(probe);
    return probe.every((b) => b === 0);
  });

  const backend: CryptoBackend = {
    name: "sodium",
    blake2b: (data, outLen, key) => sodium.crypto_generichash(outLen, data, key ?? null),
    randomBytes: (length) => sodium.randombytes_buf(length),
    signKeypairFromSeed(s): SignKeypair {
      const kp = sodium.crypto_sign_seed_keypair(s);
      return { publicKey: kp.publicKey, secretKey: kp.privateKey };
    },
    signDetached: (m, secretKey) => sodium.crypto_sign_detached(m, secretKey),
    verifyDetached(signature, m, publicKey) {
      try {
        return sodium.crypto_sign_verify_detached(signature, m, publicKey);
      } catch {
        return false;
      }
    },
    isValidSignPoint: validPointNative ? (publicKey) => publicKey.length === 32 && sodium.crypto_core_ed25519_is_valid_point?.(publicKey) === true : (publicKey) => n.isValidSignPoint(publicKey),
    boxKeypairFromSeed(s): BoxKeypair {
      const kp = sodium.crypto_box_seed_keypair(s);
      return { publicKey: kp.publicKey, secretKey: kp.privateKey };
    },
    boxKeypair(): BoxKeypair {
      const kp = sodium.crypto_box_keypair();
      return { publicKey: kp.publicKey, secretKey: kp.privateKey };
    },
    scalarMult: scalarMultNative ? (secretKey, publicKey) => sodium.crypto_scalarmult?.(secretKey, publicKey) ?? n.scalarMult(secretKey, publicKey) : (secretKey, publicKey) => n.scalarMult(secretKey, publicKey),
    boxEasy: (m, nonce, publicKey, secretKey) => sodium.crypto_box_easy(m, nonce, publicKey, secretKey),
    boxOpenEasy: (box, nonce, publicKey, secretKey) => sodium.crypto_box_open_easy(box, nonce, publicKey, secretKey),
    aeadEncrypt: aeadNative ? (plaintext, a, nonce, key) => sodium.crypto_aead_xchacha20poly1305_ietf_encrypt?.(plaintext, a, null, nonce, key) ?? n.aeadEncrypt(plaintext, a, nonce, key) : (plaintext, a, nonce, key) => n.aeadEncrypt(plaintext, a, nonce, key),
    aeadDecrypt: aeadNative ? (c, a, nonce, key) => sodium.crypto_aead_xchacha20poly1305_ietf_decrypt?.(null, c, a, nonce, key) ?? n.aeadDecrypt(c, a, nonce, key) : (c, a, nonce, key) => n.aeadDecrypt(c, a, nonce, key),
    memzero: memzeroNative ? (bytes) => sodium.memzero?.(bytes) : (bytes) => bytes.fill(0)
  };
  return { backend, report: { native, portable } };
}
