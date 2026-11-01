/** The portable backend over the noble libraries (audited pure JavaScript). */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hsalsa, xsalsa20poly1305 } from "@noble/ciphers/salsa";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { blake2b } from "@noble/hashes/blake2b";
import { sha512 } from "@noble/hashes/sha512";
import { KavachError } from "../errors.js";

/**
 * Randomness from the Web Crypto global, read at every call. `@noble/hashes` captures
 * `globalThis.crypto` once when it is imported, which on Hermes is before the app has installed
 * a source (the Expo helper installs expo-crypto's inside `openKavach`), so noble's own
 * `randomBytes` would throw for the life of the process. Reading the global here, when the bytes
 * are needed, sees whatever is installed by then.
 */
function randomBytes(length: number): Uint8Array {
  const g = globalThis as { crypto?: { getRandomValues?: (array: Uint8Array) => Uint8Array } };
  const get = g.crypto?.getRandomValues;
  if (typeof get !== "function") throw new KavachError("INVALID_KEY", "randomBytes", "no crypto.getRandomValues: install a secure random source before opening Kavach");
  const out = new Uint8Array(length);
  // Web Crypto caps one call at 65,536 bytes; nothing here is near it, but the rule is kept.
  for (let offset = 0; offset < length; offset += 65_536) get.call(g.crypto, out.subarray(offset, Math.min(length, offset + 65_536)));
  return out;
}
import type { BoxKeypair, CryptoBackend, SignKeypair } from "./backend.js";

// "expand 32-byte k" as little-endian u32 words: the Salsa constant.
const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function u32(bytes: Uint8Array): Uint32Array {
  const out = new Uint32Array(bytes.length / 4);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < out.length; i++) out[i] = dv.getUint32(i * 4, true);
  return out;
}

function fromU32(words: Uint32Array): Uint8Array {
  const out = new Uint8Array(words.length * 4);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < words.length; i++) dv.setUint32(i * 4, words[i] ?? 0, true);
  return out;
}

/** `crypto_box_beforenm`: HSalsa20 of the X25519 shared secret with a zero nonce. */
function beforeNm(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(secretKey, publicKey);
  const out = new Uint32Array(8);
  hsalsa(SIGMA, u32(shared), u32(new Uint8Array(16)), out);
  return fromU32(out);
}

function isCanonicalY(bytes: Uint8Array): boolean {
  // y < 2^255 - 19, read little-endian with the sign bit cleared.
  const y = Uint8Array.from(bytes);
  y[31] = (y[31] ?? 0) & 0x7f;
  const P = Uint8Array.from([
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
  ]);
  for (let i = 31; i >= 0; i--) {
    const a = y[i] ?? 0;
    const b = P[i] ?? 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false;
}

export const nobleBackend: CryptoBackend = {
  name: "noble",
  blake2b: (data, outLen, key) => blake2b(data, key ? { dkLen: outLen, key } : { dkLen: outLen }),
  randomBytes: (length) => randomBytes(length),
  signKeypairFromSeed(seed): SignKeypair {
    const publicKey = ed25519.getPublicKey(seed);
    const secretKey = new Uint8Array(64);
    secretKey.set(seed, 0);
    secretKey.set(publicKey, 32);
    return { publicKey, secretKey };
  },
  signDetached: (message, secretKey) => ed25519.sign(message, secretKey.subarray(0, 32)),
  verifyDetached(signature, message, publicKey) {
    try {
      return ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  },
  isValidSignPoint(publicKey) {
    if (publicKey.length !== 32 || !isCanonicalY(publicKey)) return false;
    try {
      const p = ed25519.ExtendedPoint.fromHex(publicKey);
      p.assertValidity();
      return !p.equals(ed25519.ExtendedPoint.ZERO) && !p.isSmallOrder() && p.isTorsionFree();
    } catch {
      return false;
    }
  },
  boxKeypairFromSeed(seed): BoxKeypair {
    const secretKey = sha512(seed).slice(0, 32);
    return { publicKey: x25519.getPublicKey(secretKey), secretKey };
  },
  boxKeypair(): BoxKeypair {
    const secretKey = randomBytes(32);
    return { publicKey: x25519.getPublicKey(secretKey), secretKey };
  },
  scalarMult(secretKey, publicKey) {
    const shared = x25519.getSharedSecret(secretKey, publicKey); // throws on an all-zero result
    let acc = 0;
    for (const b of shared) acc |= b;
    if (acc === 0) throw new Error("low-order point");
    return shared;
  },
  boxEasy(message, nonce, publicKey, secretKey) {
    return xsalsa20poly1305(beforeNm(publicKey, secretKey), nonce).encrypt(message); // mac || ciphertext
  },
  boxOpenEasy(box, nonce, publicKey, secretKey) {
    return xsalsa20poly1305(beforeNm(publicKey, secretKey), nonce).decrypt(box);
  },
  aeadEncrypt: (plaintext, aad, nonce, key) => xchacha20poly1305(key, nonce, aad).encrypt(plaintext),
  aeadDecrypt: (ciphertextAndTag, aad, nonce, key) => xchacha20poly1305(key, nonce, aad).decrypt(ciphertextAndTag),
  memzero: (bytes) => bytes.fill(0)
};
