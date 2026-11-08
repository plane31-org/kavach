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
import { sodiumBackend, type SodiumLike } from "../src/crypto/sodiumLike.js";
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
