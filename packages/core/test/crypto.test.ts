import { beforeAll, describe, expect, it } from "vitest";
import { concat, equalBytes, toHex, u32 } from "../src/bytes.js";
import {
  C,
  D,
  H,
  LABEL_PREFIX,
  accountKeypair,
  aeadOpen,
  aeadSeal,
  assertValidBoxKey,
  backendName,
  bodyHash,
  boxKeypairFromSeed,
  deviceBoxKeypair,
  deviceSigningKeypair,
  identityId,
  keyCommitment,
  openSealedBox,
  randomBytes,
  ready,
  recordId,
  sealBox,
  sealBoxWith,
  sealedBoxNonce,
  sign,
  streamId,
  verify,
  wrapHash,
  type Label
} from "../src/crypto.js";
import { isKavachError } from "../src/errors.js";
import { fixture, hex, str } from "./fixture.js";

beforeAll(() => ready());

const LABEL_BY_TYPE: Record<number, Label> = {
  1: "account-sig",
  2: "snapshot-sig",
  3: "epoch-sig",
  4: "record-sig",
  7: "reset-sig",
  8: "reset-keys-sig"
};

function split(wire: Uint8Array): { type: number; body: Uint8Array; sig: Uint8Array } {
  return { type: wire[1] ?? 0, body: wire.subarray(0, wire.length - 64), sig: wire.subarray(wire.length - 64) };
}

describe("backend", () => {
  it("reports which backend is under test", () => {
    expect(["noble", "sodium"]).toContain(backendName());
  });
});

describe("labels and hashes", () => {
  it("builds C(label) with the fixed prefix and a trailing zero byte", () => {
    const c = C("identity");
    expect(new TextDecoder().decode(c.subarray(0, c.length - 1))).toBe(LABEL_PREFIX + "identity");
    expect(c[c.length - 1]).toBe(0);
  });

  it("H is unkeyed BLAKE2b-256", () => {
    expect(toHex(H(new Uint8Array(0)))).toBe("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
  });
});

describe("Vector A: derived keys, identity ids and stream ids", () => {
  const seeds: Record<string, { account: string; device: string }> = {
    alice: { account: str(fixture.inputs["alice_account_seed"] ?? ""), device: str(fixture.inputs["alice_device_seed"] ?? "") },
    bob: { account: str(fixture.inputs["bob_account_seed"] ?? ""), device: str(fixture.inputs["bob_device_seed"] ?? "") }
  };

  for (const who of fixture.identities) {
    it(`reproduces ${who.account}`, () => {
      const s = seeds[who.account];
      if (!s) throw new Error("unknown identity");
      const accountSeed = hex(s.account);
      const deviceSeed = hex(s.device);
      const ak = accountKeypair(accountSeed);
      expect(toHex(ak.publicKey)).toBe(who.account_public);
      expect(toHex(D(deviceSeed, "device-sign"))).toBe(who.device_sign_seed);
      expect(toHex(deviceSigningKeypair(deviceSeed).publicKey)).toBe(who.device_sign_public);
      expect(toHex(D(deviceSeed, "device-box"))).toBe(who.device_box_seed);
      const dek = deviceBoxKeypair(deviceSeed);
      expect(toHex(dek.publicKey)).toBe(who.device_box_public);
      expect(toHex(dek.secretKey)).toBe(who.device_box_secret);
      const iid = identityId(who.account, ak.publicKey);
      expect(toHex(iid)).toBe(who.identity_id);
      expect(toHex(streamId(iid, hex(who.device_id)))).toBe(who.stream_id);
      // The secret is SHA-512(seed)[0..32] and the public key its X25519 base multiple, as the fixture's OpenSSL cross-check did.
      expect(toHex(boxKeypairFromSeed(hex(who.device_box_seed)).publicKey)).toBe(who.device_box_public);
    });
  }

  it("derives different DEKs for two devices of one account", () => {
    const a = deviceBoxKeypair(hex(str(fixture.inputs["alice_device_seed"] ?? "")));
    const b = deviceBoxKeypair(hex(fixture.phone_replacement.new_device_seed));
    expect(equalBytes(a.publicKey, b.publicKey)).toBe(false);
    const cert = hex(fixture.phone_replacement.new_certificate);
    const epk = cert.subarray(cert.length - 64 - 32, cert.length - 64);
    expect(toHex(b.publicKey)).toBe(toHex(epk));
    // Same account, same identity id.
    expect(toHex(identityId("alice", accountKeypair(hex(str(fixture.inputs["alice_account_seed"] ?? ""))).publicKey))).toBe(
      fixture.phone_replacement.stable_identity_id
    );
  });

  it("nothing but AK derives from the account seed", () => {
    const accountSeed = hex(str(fixture.inputs["alice_account_seed"] ?? ""));
    const deviceSeed = hex(str(fixture.inputs["alice_device_seed"] ?? ""));
    expect(equalBytes(deviceSigningKeypair(accountSeed).publicKey, accountKeypair(accountSeed).publicKey)).toBe(false);
    expect(equalBytes(deviceBoxKeypair(accountSeed).publicKey, deviceBoxKeypair(deviceSeed).publicKey)).toBe(false);
  });
});

describe("signatures", () => {
  it("verifies every fixture document and reproduces its signature", () => {
    const alice = fixture.identities[0];
    const bob = fixture.identities[1];
    if (!alice || !bob) throw new Error("fixture");
    const secret: Record<string, Uint8Array> = {
      alice_account: accountKeypair(hex(str(fixture.inputs["alice_account_seed"] ?? ""))).secretKey,
      bob_account: accountKeypair(hex(str(fixture.inputs["bob_account_seed"] ?? ""))).secretKey,
      snapshot: accountKeypair(hex(str(fixture.inputs["alice_account_seed"] ?? ""))).secretKey,
      manifest: deviceSigningKeypair(hex(str(fixture.inputs["alice_device_seed"] ?? ""))).secretKey,
      record: deviceSigningKeypair(hex(str(fixture.inputs["alice_device_seed"] ?? ""))).secretKey
    };
    expect(Object.keys(fixture.documents).sort()).toEqual(["alice_account", "bob_account", "manifest", "record", "snapshot"]);
    for (const [name, doc] of Object.entries(fixture.documents)) {
      const wire = hex(doc.wire);
      const { type, body, sig } = split(wire);
      const label = LABEL_BY_TYPE[type];
      if (!label) throw new Error(`no label for type ${type}`);
      expect(() => verify(hex(doc.verification_key), label, body, sig)).not.toThrow();
      expect(toHex(bodyHash(body))).toBe(doc.body_hash);
      const sk = secret[name];
      if (!sk) throw new Error(name);
      expect(toHex(sign(sk, label, body))).toBe(doc.signature);
    }
  });

  it("N13: rejects a non-canonical signature scalar as BAD_SIGNATURE", () => {
    const n13 = fixture.negative_vectors.find((n) => n.name === "N13_noncanonical_signature");
    if (!n13) throw new Error("N13 missing");
    const { body, sig } = split(hex(n13.wire));
    try {
      verify(hex(n13.verification_key), "record-sig", body, sig);
      throw new Error("accepted");
    } catch (e) {
      expect(isKavachError(e, "BAD_SIGNATURE")).toBe(true);
    }
  });

  it("N07: a valid signature under the wrong key is BAD_SIGNATURE", () => {
    const n07 = fixture.negative_vectors.find((n) => n.name === "N07_wrong_signer");
    if (!n07) throw new Error("N07 missing");
    const { body, sig } = split(hex(n07.wire));
    expect(() => verify(hex(n07.verification_key), "record-sig", body, sig)).toThrow(expect.objectContaining({ code: "BAD_SIGNATURE" }));
  });

  it("rejects an invalid Ed25519 public key as INVALID_KEY", () => {
    const doc = fixture.documents["record"];
    if (!doc) throw new Error("fixture");
    const { body, sig } = split(hex(doc.wire));
    expect(() => verify(new Uint8Array(32), "record-sig", body, sig)).toThrow(expect.objectContaining({ code: "INVALID_KEY" }));
    expect(() => verify(new Uint8Array(32).fill(0xff), "record-sig", body, sig)).toThrow(expect.objectContaining({ code: "INVALID_KEY" }));
  });

  it("N16: rejects an all-zero X25519 key as INVALID_KEY", () => {
    const n16 = fixture.negative_vectors.find((n) => n.name === "N16_low_order_box_key");
    if (!n16) throw new Error("N16 missing");
    const wire = hex(n16.wire);
    const epk = wire.subarray(wire.length - 64 - 32, wire.length - 64);
    expect(() => assertValidBoxKey(epk)).toThrow(expect.objectContaining({ code: "INVALID_KEY" }));
    // The signature on that certificate is fine; the key check is what rejects it.
    const { body, sig } = split(wire);
    const ak = body.subarray(2 + 1 + 3, 2 + 1 + 3 + 32);
    expect(() => verify(ak, "account-sig", body, sig)).not.toThrow();
  });
});

describe("record AEAD and ids", () => {
  it("reproduces the record ciphertext, tag and id", () => {
    const key = hex(str(fixture.inputs["epoch_key"] ?? ""));
    const nonce = hex(str(fixture.inputs["record_nonce"] ?? ""));
    const aad = hex(fixture.record.aad);
    const plaintext = hex(fixture.record.plaintext);
    expect(toHex(aeadSeal(key, nonce, aad, plaintext))).toBe(fixture.record.ciphertext_and_tag);
    expect(toHex(aeadOpen(key, nonce, aad, hex(fixture.record.ciphertext_and_tag)))).toBe(fixture.record.plaintext);
    const alice = fixture.identities[0];
    if (!alice) throw new Error("fixture");
    expect(toHex(recordId(hex(alice.stream_id), 1, 0))).toBe(fixture.record.record_id);
    expect(toHex(aad.subarray(0, C("record-aad").length))).toBe(toHex(C("record-aad")));
  });

  it("fails closed on a changed tag or AAD", () => {
    const key = hex(str(fixture.inputs["epoch_key"] ?? ""));
    const nonce = hex(str(fixture.inputs["record_nonce"] ?? ""));
    const aad = hex(fixture.record.aad);
    const ct = hex(fixture.record.ciphertext_and_tag);
    const bad = Uint8Array.from(ct);
    bad[bad.length - 1] ^= 1;
    expect(() => aeadOpen(key, nonce, aad, bad)).toThrow(expect.objectContaining({ code: "DECRYPT_FAILED" }));
    const aad2 = Uint8Array.from(aad);
    aad2[aad2.length - 1] ^= 1;
    expect(() => aeadOpen(key, nonce, aad2, ct)).toThrow(expect.objectContaining({ code: "DECRYPT_FAILED" }));
  });
});

describe("sealed boxes and the key commitment", () => {
  it("reproduces the fixture wraps with their ephemeral seeds and opens them", () => {
    const key = hex(str(fixture.inputs["epoch_key"] ?? ""));
    for (const [i, w] of fixture.wraps.entries()) {
      const who = fixture.identities[i];
      if (!who) throw new Error("fixture");
      expect(w.recipient_identity).toBe(who.identity_id);
      const eph = boxKeypairFromSeed(hex(w.ephemeral_seed));
      expect(toHex(eph.publicKey)).toBe(w.ephemeral_public);
      expect(toHex(sealedBoxNonce(eph.publicKey, hex(who.device_box_public)))).toBe(w.nonce);
      const box = sealBoxWith(key, hex(who.device_box_public), eph);
      expect(toHex(box)).toBe(w.sealed_box);
      expect(toHex(wrapHash(box))).toBe(w.wrap_hash);
      const opened = openSealedBox(box, { publicKey: hex(who.device_box_public), secretKey: hex(who.device_box_secret) });
      expect(toHex(opened)).toBe(toHex(key));
    }
  });

  it("seals 80-byte boxes that only the recipient opens", () => {
    const alice = fixture.identities[0];
    const bob = fixture.identities[1];
    if (!alice || !bob) throw new Error("fixture");
    const key = randomBytes(32);
    const box = sealBox(key, hex(alice.device_box_public));
    expect(box.length).toBe(80);
    expect(toHex(openSealedBox(box, { publicKey: hex(alice.device_box_public), secretKey: hex(alice.device_box_secret) }))).toBe(toHex(key));
    expect(() => openSealedBox(box, { publicKey: hex(bob.device_box_public), secretKey: hex(bob.device_box_secret) })).toThrow(
      expect.objectContaining({ code: "DECRYPT_FAILED" })
    );
    const tampered = Uint8Array.from(box);
    tampered[79] ^= 1;
    expect(() => openSealedBox(tampered, { publicKey: hex(alice.device_box_public), secretKey: hex(alice.device_box_secret) })).toThrow(
      expect.objectContaining({ code: "DECRYPT_FAILED" })
    );
    expect(() => sealBox(key, new Uint8Array(32))).toThrow(expect.objectContaining({ code: "INVALID_KEY" }));
  });

  it("matches the manifest's key commitment and rejects the wrong epoch", () => {
    const manifest = fixture.documents["manifest"];
    const alice = fixture.identities[0];
    if (!manifest || !alice) throw new Error("fixture");
    const wire = hex(manifest.wire);
    const commit = wire.subarray(2 + 32 + 32 + 32 + 4 + 8, 2 + 32 + 32 + 32 + 4 + 8 + 32);
    const key = hex(str(fixture.inputs["epoch_key"] ?? ""));
    expect(toHex(keyCommitment(hex(alice.stream_id), 1, key))).toBe(toHex(commit));
    expect(toHex(keyCommitment(hex(alice.stream_id), 2, key))).not.toBe(toHex(commit));
    expect(toHex(u32(1))).toBe(toHex(wire.subarray(2 + 96, 2 + 100)));
  });
});

describe("boundary fixture seed rule", () => {
  it("derives member001 from the documented rule and matches its certificate", () => {
    // accountSeed = H(C("fixture-account") || u32(i)); deviceSeed = H(C("fixture-device") || u32(i)).
    // Fixture-only labels are built the same way as protocol labels.
    const fixtureLabel = (name: string): Uint8Array => concat(new TextEncoder().encode(LABEL_PREFIX + name), Uint8Array.of(0));
    const accountSeed = H(concat(fixtureLabel("fixture-account"), u32(1)));
    const deviceSeed = H(concat(fixtureLabel("fixture-device"), u32(1)));
    const cert = hex(fixture.boundary_100.accounts[1] ?? "");
    const ak = accountKeypair(accountSeed).publicKey;
    expect(toHex(cert.subarray(2 + 1 + 9, 2 + 1 + 9 + 32))).toBe(toHex(ak));
    const epk = cert.subarray(cert.length - 96, cert.length - 64);
    expect(toHex(deviceBoxKeypair(deviceSeed).publicKey)).toBe(toHex(epk));
    const dpk = cert.subarray(cert.length - 128, cert.length - 96);
    expect(toHex(deviceSigningKeypair(deviceSeed).publicKey)).toBe(toHex(dpk));
  });
});
