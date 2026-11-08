/**
 * The libsodium backend over an injected object (what a native binding on a phone provides):
 * the same bytes as the portable backend, and the validity check falling back where the binding
 * lacks it.
 */
import { createRequire } from "node:module";
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { C } from "../src/crypto.js";
import { nobleBackend } from "../src/crypto/noble.js";
import { buildSodiumBackend, sodiumBackend, type SodiumLike } from "../src/crypto/sodiumLike.js";
import { KavachError } from "../src/errors.js";
import { fixture, hex } from "./fixture.js";

const require = createRequire(import.meta.url);
let full: SodiumLike;
let partial: SodiumLike;

beforeAll(async () => {
  const mod = require("libsodium-wrappers-sumo") as { default?: SodiumLike & { ready: Promise<void> } } & SodiumLike & { ready: Promise<void> };
  const sodium = mod.default ?? mod;
  await sodium.ready;
  full = sodium;
  // A binding without the sumo-only validity check, as react-native-libsodium may be.
  const { crypto_core_ed25519_is_valid_point: _omitted, ...rest } = sodium;
  void _omitted;
  partial = rest as SodiumLike;
});

/** react-native-libsodium 1.7, as its native source shapes it: no scalarmult, memzero or validity check; AEAD on string AAD only. */
function nativeShaped(sodium: SodiumLike): SodiumLike {
  const { crypto_core_ed25519_is_valid_point: _a, crypto_scalarmult: _b, memzero: _c, ...rest } = sodium;
  void _a;
  void _b;
  void _c;
  const stringOnly = (aad: unknown): void => {
    if (typeof aad !== "string") throw new Error("crypto_aead_xchacha20poly1305_ietf_encrypt: input type not yet implemented");
  };
  return {
    ...rest,
    crypto_aead_xchacha20poly1305_ietf_encrypt: (m, aad, sn, nonce, key) => {
      stringOnly(aad);
      return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt?.(m, aad, sn, nonce, key) ?? new Uint8Array();
    },
    crypto_aead_xchacha20poly1305_ietf_decrypt: (sn, c, aad, nonce, key) => {
      stringOnly(aad);
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt?.(sn, c, aad, nonce, key) ?? new Uint8Array();
    }
  };
}

describe("buildSodiumBackend against a native-shaped binding", () => {
  it("runs signatures and boxes on the binding, the rest portable, and says so", () => {
    const { backend, report } = buildSodiumBackend(nativeShaped(full));
    expect([...report.native].sort()).toEqual(["blake2b", "boxEasy", "boxKeypair", "boxKeypairFromSeed", "boxOpenEasy", "randomBytes", "signDetached", "signKeypairFromSeed", "verifyDetached"]);
    expect([...report.portable].sort()).toEqual(["aead", "isValidSignPoint", "memzero", "scalarMult"]);
    // The protocol's binary associated data works through the fallback, and the bytes match the portable backend.
    const key = new Uint8Array(32).fill(4);
    const nonce = new Uint8Array(24).fill(6);
    const aad = Uint8Array.from([0, 255, 7]);
    const msg = new TextEncoder().encode("binary aad");
    expect(toHex(backend.aeadEncrypt(msg, aad, nonce, key))).toBe(toHex(nobleBackend.aeadEncrypt(msg, aad, nonce, key)));
    expect(toHex(backend.aeadDecrypt(nobleBackend.aeadEncrypt(msg, aad, nonce, key), aad, nonce, key))).toBe(toHex(msg));
    const a = backend.boxKeypairFromSeed(new Uint8Array(32).fill(1));
    const b = backend.boxKeypairFromSeed(new Uint8Array(32).fill(2));
    expect(toHex(backend.scalarMult(a.secretKey, b.publicKey))).toBe(toHex(nobleBackend.scalarMult(a.secretKey, b.publicKey)));
    expect(backend.isValidSignPoint(new Uint8Array(32))).toBe(false);
    const z = Uint8Array.from([9, 9]);
    backend.memzero(z);
    expect([...z]).toEqual([0, 0]);
  });

  it("the full wasm libsodium runs everything natively", () => {
    expect(buildSodiumBackend(full).report.portable).toEqual([]);
  });

  it("a generated keypair whose public key is not its secret's is refused; a scalarmult that throws falls back; one build per binding", () => {
    const mismatched: SodiumLike = {
      ...full,
      crypto_box_keypair: () => {
        const kp = full.crypto_box_keypair();
        return { publicKey: full.crypto_box_keypair().publicKey, privateKey: kp.privateKey };
      }
    };
    expect(() => sodiumBackend(mismatched)).toThrow(/boxKeypair/);
    const throwing: SodiumLike = {
      ...full,
      crypto_scalarmult: () => {
        throw new Error("not implemented");
      }
    };
    const { backend, report } = buildSodiumBackend(throwing);
    expect(report.portable).toEqual(["scalarMult"]);
    const a = backend.boxKeypairFromSeed(new Uint8Array(32).fill(1));
    const b = backend.boxKeypairFromSeed(new Uint8Array(32).fill(2));
    expect(toHex(backend.scalarMult(a.secretKey, b.publicKey))).toBe(toHex(nobleBackend.scalarMult(a.secretKey, b.publicKey)));
    expect(buildSodiumBackend(throwing)).toBe(buildSodiumBackend(throwing)); // cached: the checks ran once
  });

  it("a binding that answers differently on the same input is refused, never used", () => {
    const wrong: SodiumLike = { ...full, crypto_sign_detached: (m, sk) => full.crypto_sign_detached(m, sk).map((b) => b ^ 1) };
    expect(() => sodiumBackend(wrong)).toThrow(KavachError);
    const missing = { ...full, crypto_sign_seed_keypair: undefined } as unknown as SodiumLike; // a default import of react-native-libsodium
    expect(() => sodiumBackend(missing)).toThrow(/signKeypairFromSeed/);
  });
});

describe("sodiumBackend over an injected libsodium", () => {
  it("signs, verifies, hashes and seals interchangeably with the portable backend", () => {
    const s = sodiumBackend(full);
    const seed = new Uint8Array(32).fill(7);
    const kpS = s.signKeypairFromSeed(seed);
    const kpN = nobleBackend.signKeypairFromSeed(seed);
    expect(toHex(kpS.publicKey)).toBe(toHex(kpN.publicKey));
    const msg = new TextEncoder().encode("the same bytes on both backends");
    const sigS = s.signDetached(msg, kpS.secretKey);
    expect(toHex(sigS)).toBe(toHex(nobleBackend.signDetached(msg, kpN.secretKey)));
    expect([nobleBackend.verifyDetached(sigS, msg, kpS.publicKey), s.verifyDetached(sigS, msg, kpS.publicKey)]).toEqual([true, true]);
    expect(toHex(s.blake2b(msg, 32))).toBe(toHex(nobleBackend.blake2b(msg, 32)));
    const box = s.boxKeypairFromSeed(seed);
    expect(toHex(box.publicKey)).toBe(toHex(nobleBackend.boxKeypairFromSeed(seed).publicKey));
    const eph = nobleBackend.boxKeypair();
    const nonce = new Uint8Array(24).fill(3);
    const sealed = nobleBackend.boxEasy(msg, nonce, box.publicKey, eph.secretKey);
    expect(toHex(s.boxOpenEasy(sealed, nonce, eph.publicKey, box.secretKey))).toBe(toHex(msg));
    const key = new Uint8Array(32).fill(9);
    const aead = s.aeadEncrypt(msg, new Uint8Array([1, 2]), nonce, key);
    expect(toHex(nobleBackend.aeadDecrypt(aead, new Uint8Array([1, 2]), nonce, key))).toBe(toHex(msg));
  });

  it("verifies the fixture's signed documents and rejects the low-order key, with and without the native validity check", () => {
    const alice = fixture.documents["alice_account"];
    if (!alice) throw new Error("fixture");
    const wire = hex(alice.wire);
    const body = wire.subarray(0, wire.length - 64);
    const signature = wire.subarray(wire.length - 64);
    const prefix = C("account-sig");
    const message = new Uint8Array(prefix.length + body.length);
    message.set(prefix);
    message.set(body, prefix.length);
    const publicKey = hex(fixture.identities[0]?.account_public ?? "");
    for (const backend of [sodiumBackend(full), sodiumBackend(partial)]) {
      expect(backend.verifyDetached(signature, message, publicKey)).toBe(true);
      expect(backend.isValidSignPoint(publicKey)).toBe(true);
      expect(backend.isValidSignPoint(new Uint8Array(32))).toBe(false); // the identity, a low-order point
      expect(backend.isValidSignPoint(new Uint8Array(31))).toBe(false);
    }
    expect(sodiumBackend(partial).memzero).toBeDefined();
  });
});
