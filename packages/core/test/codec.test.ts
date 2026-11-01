import { beforeAll, describe, expect, it } from "vitest";
import { compareBytes, concat, fromHex, toHex } from "../src/bytes.js";
import {
  DocumentType,
  buildAccountDevice,
  buildCircleSnapshot,
  buildEncryptedRecord,
  buildEpochManifest,
  buildResetKeyList,
  buildResetReceipt,
  decodeLocation,
  decodeRecoveryCode,
  encodeLocation,
  encodeRecoveryCode,
  expectType,
  openRecord,
  openVault,
  parseDocument,
  sealVault,
  verifyDocument,
  type AccountDevice,
  type CircleSnapshot,
  type EncryptedRecord,
  type EpochManifest,
  type ResetKeyList,
  type AccountResetReceipt, decodeEnvelope, encodeRecordHeader, type HeaderClass } from "../src/codec.js";
import { accountKeypair, deviceSigningKeypair, identityId, ready, signingKeypairFromSeed, wrapHash, keyCommitment, type SigningKeypair } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { fixture, hex, str } from "./fixture.js";
import { decodeLocation, encodeLocation } from "./location.js";


interface Extra {
  reset_key_management: {
    management_public: string;
    management_seed: string;
    standby_public: string;
    standby_seed: string;
    standby_id: string;
    list_v1_wire: string;
    list_v2_wire: string;
    empty_list_wire: string;
    reattested_receipt_wire: string;
    rejected_wires: Record<string, string>;
    expected_sizes: number[];
  };
  account_reset: { authority_seed: string; authority_public: string; authority_key_id: string; new_account_certificate: string; receipt_wire: string };
  recovery_vault: { recovery_code: string; empty_vault: string; sharing_disabled_vault: string; recovery_key: string; nonce: string; plaintext: string; aad: string; wire: string };
  durable_events: { checkin_wire: string; following_location_wire: string };
  record: { payload: string; kind: number; event_time_ms: number; header_class: number; decoded: { latitude_e7: number; longitude_e7: number; accuracy_mm: number; captured_at_ms: number; status: number } };
  status_record: { wire: string; record_id: string; epoch_key: string; payload: string; plaintext: string; expected: { kind: number; header_class: number; flags: number; epoch: number; counter: number; event_time_ms: number | null } };
  boundary_100: { epoch_key: string; snapshot_wire: string; manifest_wire: string; wraps: Record<string, string>; maximum_record_wire: string; accounts: string[] };
  phone_replacement: { device_rejections: { wire: string; expected: string }[]; new_certificate: string; next_owner_snapshot: string; new_manifest: string; new_record: string };
}
const fx = fixture as unknown as typeof fixture & Extra;

const alice = fixture.identities[0];
const bob = fixture.identities[1];
if (!alice || !bob) throw new Error("fixture");
// Key material is derived after libsodium is ready, not at module load.
let aliceAccount: SigningKeypair;
let bobAccount: SigningKeypair;
let aliceDsk: SigningKeypair;
let management: SigningKeypair;
beforeAll(async () => {
  await ready();
  aliceAccount = accountKeypair(hex(str(fixture.inputs["alice_account_seed"] ?? "")));
  bobAccount = accountKeypair(hex(str(fixture.inputs["bob_account_seed"] ?? "")));
  aliceDsk = deviceSigningKeypair(hex(str(fixture.inputs["alice_device_seed"] ?? "")));
  management = signingKeypairFromSeed(hex(fx.reset_key_management.management_seed));
});
const epochKey = hex(str(fixture.inputs["epoch_key"] ?? ""));
const now = BigInt(str(fixture.inputs["time_ms"] ?? "0"));
const circleId = hex(str(fixture.inputs["circle_id"] ?? ""));

function code(fn: () => unknown): string {
  try {
    fn();
    return "ACCEPTED";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

describe("Vectors B to E rebuild byte for byte", () => {
  it("B: AccountDevice", () => {
    const doc = expectType<AccountDevice>(verifyDocument(hex(fixture.documents["alice_account"]?.wire ?? "")), DocumentType.AccountDevice);
    expect(doc.accountName).toBe("alice");
    expect(toHex(doc.accountKey)).toBe(alice.account_public);
    expect(doc.generation).toBe(1n);
    expect(toHex(doc.deviceId)).toBe(alice.device_id);
    expect(toHex(doc.signingKey)).toBe(alice.device_sign_public);
    expect(toHex(doc.boxKey)).toBe(alice.device_box_public);
    expect(toHex(doc.bodyHash)).toBe(alice.certificate_hash);
    const rebuilt = buildAccountDevice(doc, aliceAccount.secretKey);
    expect(toHex(rebuilt)).toBe(fixture.documents["alice_account"]?.wire);
    expect(rebuilt.length).toBe(187 + 5);
  });

  it("C: CircleSnapshot", () => {
    const wire = hex(fixture.documents["snapshot"]?.wire ?? "");
    const doc = expectType<CircleSnapshot>(verifyDocument(wire, aliceAccount.publicKey), DocumentType.CircleSnapshot);
    expect(toHex(doc.circleId)).toBe(toHex(circleId));
    expect(toHex(doc.ownerIdentityId)).toBe(alice.identity_id);
    expect(doc.revision).toBe(1n);
    expect(doc.members.map(toHex)).toEqual([alice.identity_id, bob.identity_id].sort());
    // Members given out of order are sorted by the builder.
    const rebuilt = buildCircleSnapshot({ ...doc, members: [...doc.members].reverse() }, aliceAccount.secretKey);
    expect(toHex(rebuilt)).toBe(toHex(wire));
    expect(wire.length).toBe(124 + 32 * 2);
  });

  it("D: EpochManifest", () => {
    const wire = hex(fixture.documents["manifest"]?.wire ?? "");
    const doc = expectType<EpochManifest>(verifyDocument(wire, aliceDsk.publicKey), DocumentType.EpochManifest);
    expect(toHex(doc.streamId)).toBe(alice.stream_id);
    expect(toHex(doc.authorIdentityId)).toBe(alice.identity_id);
    expect(toHex(doc.authorCertificateHash)).toBe(alice.certificate_hash);
    expect(doc.epoch).toBe(1);
    expect(doc.createdAt).toBe(now);
    expect(toHex(doc.keyCommitment)).toBe(toHex(keyCommitment(hex(alice.stream_id), 1, epochKey)));
    expect(doc.audience.length).toBe(2);
    for (const row of doc.audience) {
      const who = fixture.identities.find((i) => i.identity_id === toHex(row.identityId));
      const wrap = fixture.wraps.find((w) => w.recipient_identity === toHex(row.identityId));
      expect(who && toHex(row.certificateHash)).toBe(who?.certificate_hash);
      expect(wrap && toHex(row.wrapHash)).toBe(wrap?.wrap_hash);
      expect(wrap && toHex(wrapHash(hex(wrap.sealed_box)))).toBe(wrap?.wrap_hash);
    }
    expect(toHex(buildEpochManifest(doc, aliceDsk.secretKey))).toBe(toHex(wire));
    expect(wire.length).toBe(208 + 96 * 2);
  });

  it("E: EncryptedRecord", () => {
    const wire = hex(fixture.documents["record"]?.wire ?? "");
    const doc = expectType<EncryptedRecord>(verifyDocument(wire, aliceDsk.publicKey), DocumentType.EncryptedRecord);
    expect(toHex(doc.streamId)).toBe(alice.stream_id);
    expect(doc.epoch).toBe(1);
    expect(doc.counter).toBe(0);
    expect(doc.sentAt).toBe(now);
    expect(doc.flags).toBe(0);
    expect(doc.headerClass).toBe(0);
    expect(doc.header.length).toBe(51);
    expect(toHex(concat(hex("5365616c656453747265616d2f352f7265636f72642d61616400"), doc.header))).toBe(fixture.record.aad);
    expect(toHex(doc.ciphertext)).toBe(fixture.record.ciphertext_and_tag);
    const plaintext = openRecord(doc, epochKey);
    expect(toHex(plaintext)).toBe(fixture.record.plaintext);
    // The envelope: version 1, the kind, the event time (the fix time), then the payload.
    const envelope = decodeEnvelope(plaintext);
    expect([envelope.kind, envelope.eventTime, toHex(envelope.payload)]).toEqual([fx.record.kind, BigInt(fx.record.event_time_ms), fx.record.payload]);
    const rebuilt = buildEncryptedRecord(doc, plaintext, epochKey, hex(str(fixture.inputs["record_nonce"] ?? "")), aliceDsk.secretKey);
    expect(toHex(rebuilt)).toBe(toHex(wire));
    expect(wire.length).toBe(159 + 10 + 22);
    expect(() => openRecord(doc, new Uint8Array(32))).toThrow(expect.objectContaining({ code: "DECRYPT_FAILED" }));
  });
});

describe("slot-only records and header classes (revisions 6 and 8)", () => {
  it("S: the status vector shows header class 2, opens to kind 2 with no event time and the profile payload, and rebuilds byte for byte", () => {
    const v = fx.status_record;
    const wire = hex(v.wire);
    const doc = expectType<EncryptedRecord>(verifyDocument(wire, aliceDsk.publicKey), DocumentType.EncryptedRecord);
    expect([doc.headerClass, doc.flags, doc.epoch, doc.counter]).toEqual([v.expected.header_class, v.expected.flags, v.expected.epoch, v.expected.counter]);
    const plaintext = openRecord(doc, hex(v.epoch_key));
    expect(toHex(plaintext)).toBe(v.plaintext);
    const envelope = decodeEnvelope(plaintext);
    expect([envelope.kind, envelope.eventTime, toHex(envelope.payload)]).toEqual([v.expected.kind, undefined, v.payload]);
    const rebuilt = buildEncryptedRecord(doc, plaintext, hex(v.epoch_key), doc.nonce, aliceDsk.secretKey);
    expect(toHex(rebuilt)).toBe(v.wire);
  });

  it("the header carries a class of 0 to 3 in bits 1 and 2, nothing else, and the kind only inside the envelope", () => {
    const base = { streamId: hex(alice.stream_id), epoch: 1, counter: 0, sentAt: now };
    expect([0, 1, 2, 3].map((c) => encodeRecordHeader({ ...base, headerClass: c as HeaderClass })[50])).toEqual([0, 2, 4, 6]);
    const both = hex(fx.status_record.wire);
    both[50] = 6;
    expect(code(() => parseDocument(both))).toBe("ACCEPTED"); // class 3 is a legal declaration since revision 8
    both[50] = 8;
    expect(code(() => parseDocument(both))).toBe("MALFORMED");
    expect(code(() => decodeEnvelope(new Uint8Array(9)))).toBe("MALFORMED");
    expect(code(() => decodeEnvelope(concat(fromHex("02"), new Uint8Array(9))))).toBe("MALFORMED");
    expect(decodeEnvelope(concat(fromHex("01ff"), new Uint8Array(8))).kind).toBe(255);
  });
});

describe("all 22 negative vectors", () => {
  for (const n of fixture.negative_vectors) {
    it(`${n.name} -> ${n.expected}`, () => {
      const wire = hex(n.wire);
      const key = n.verification_key ? hex(n.verification_key) : undefined;
      let actual: string;
      if (n.operation === "verify") actual = code(() => verifyDocument(wire, key));
      else if (n.operation === "decrypt") {
        actual = code(() => openRecord(expectType<EncryptedRecord>(verifyDocument(wire, key), DocumentType.EncryptedRecord), epochKey));
      } else if (n.operation === "open") {
        actual = code(() => decodeEnvelope(openRecord(expectType<EncryptedRecord>(verifyDocument(wire, key), DocumentType.EncryptedRecord), epochKey)));
      } else if (n.operation === "payload") actual = code(() => decodeLocation(wire));
      else throw new Error(n.operation);
      expect(actual).toBe(n.expected);
    });
  }

  it("rejects the vault type and the retired type on the signed path", () => {
    expect(code(() => parseDocument(hex(fx.recovery_vault.wire)))).toBe("UNSUPPORTED_TYPE");
    const t5 = fixture.negative_vectors.find((n) => n.name === "N20_retired_type5");
    expect(t5 && code(() => parseDocument(hex(t5.wire)))).toBe("UNSUPPORTED_TYPE");
  });

  it("needs a verification key for every type but the certificate", () => {
    expect(code(() => verifyDocument(hex(fixture.documents["snapshot"]?.wire ?? "")))).toBe("METADATA_REQUIRED");
  });
});

describe("100-account boundary", () => {
  it("parses the snapshot, the manifest, the wraps and the maximum record at the expected sizes", () => {
    const snapshot = hex(fx.boundary_100.snapshot_wire);
    const manifest = hex(fx.boundary_100.manifest_wire);
    expect(snapshot.length).toBe(3324);
    expect(manifest.length).toBe(9808);
    const s = expectType<CircleSnapshot>(verifyDocument(snapshot, aliceAccount.publicKey), DocumentType.CircleSnapshot);
    expect(s.members.length).toBe(100);
    expect(s.revision).toBe(2n);
    const m = expectType<EpochManifest>(verifyDocument(manifest, aliceDsk.publicKey), DocumentType.EpochManifest);
    expect(m.audience.length).toBe(100);
    expect(m.epoch).toBe(2);
    const wraps = Object.entries(fx.boundary_100.wraps);
    expect(wraps.reduce((n, [, w]) => n + w.length / 2, 0)).toBe(8000);
    for (const [iid, w] of wraps) {
      const row = m.audience.find((r) => toHex(r.identityId) === iid);
      expect(row && toHex(row.wrapHash)).toBe(toHex(wrapHash(hex(w))));
    }
    const max = hex(fx.boundary_100.maximum_record_wire);
    expect(max.length).toBe(4265);
    const r = expectType<EncryptedRecord>(verifyDocument(max, aliceDsk.publicKey), DocumentType.EncryptedRecord);
    expect([r.headerClass, r.flags, r.counter]).toEqual([1, 2, 0xffffffff]);
    const opened = decodeEnvelope(openRecord(r, hex(fx.boundary_100.epoch_key)));
    expect([opened.kind, opened.payload.length]).toEqual([1, 4096]);
    // Every one of the 100 certificates is self-contained and verifies under the key it carries.
    for (const a of fx.boundary_100.accounts) verifyDocument(hex(a));
    // The audience rows are in strict identity order.
    for (let i = 1; i < m.audience.length; i++) {
      const prev = m.audience[i - 1];
      const cur = m.audience[i];
      expect(prev && cur && compareBytes(prev.identityId, cur.identityId)).toBeLessThan(0);
    }
  });
});

describe("reset key lists and receipts", () => {
  const rkm = fx.reset_key_management;

  it("parses the three key lists at 187, 139 and 91 bytes and rebuilds them", () => {
    const wires = [rkm.list_v1_wire, rkm.list_v2_wire, rkm.empty_list_wire].map(hex);
    expect(wires.map((w) => w.length)).toEqual(rkm.expected_sizes);
    expect(toHex(management.publicKey)).toBe(rkm.management_public);
    const parsed = wires.map((w) => expectType<ResetKeyList>(verifyDocument(w, management.publicKey), DocumentType.ResetKeyList));
    expect(parsed.map((p) => p.version)).toEqual([1n, 2n, 3n]);
    expect(parsed.map((p) => p.keys.length)).toEqual([2, 1, 0]);
    expect(parsed.map((p) => p.expiresAt - p.issuedAt)).toEqual([86_400_000n, 86_380_000n, 86_380_000n]);
    for (const [i, p] of parsed.entries()) expect(toHex(buildResetKeyList(p, management.secretKey))).toBe(toHex(wires[i] ?? new Uint8Array()));
  });

  it("rejects the rejected wires for the codec's reasons", () => {
    const rw = rkm.rejected_wires;
    expect(code(() => verifyDocument(hex(rw["excess_lifetime"] ?? ""), management.publicKey))).toBe("MALFORMED");
    expect(code(() => verifyDocument(hex(rw["duplicate_keys"] ?? ""), management.publicKey))).toBe("MALFORMED");
    expect(code(() => verifyDocument(hex(rw["operational_self_signed"] ?? ""), management.publicKey))).toBe("BAD_SIGNATURE");
    // These parse; their rejection belongs to the trust model of step 12.
    expect(code(() => verifyDocument(hex(rw["equal_version_conflict"] ?? ""), management.publicKey))).toBe("ACCEPTED");
    expect(code(() => verifyDocument(hex(rw["root_as_operational"] ?? ""), management.publicKey))).toBe("ACCEPTED");
    // A 30-day lifetime is the maximum; one millisecond more is MALFORMED.
    const base = expectType<ResetKeyList>(parseDocument(hex(rkm.list_v1_wire)), DocumentType.ResetKeyList);
    const ok = buildResetKeyList({ ...base, expiresAt: base.issuedAt + 2_592_000_000n }, management.secretKey);
    const over = buildResetKeyList({ ...base, expiresAt: base.issuedAt + 2_592_000_001n }, management.secretKey);
    expect(code(() => verifyDocument(ok, management.publicKey))).toBe("ACCEPTED");
    expect(code(() => verifyDocument(over, management.publicKey))).toBe("MALFORMED");
  });

  it("parses and rebuilds the reset receipt and its re-attestation", () => {
    const ar = fx.account_reset;
    const authority = signingKeypairFromSeed(hex(ar.authority_seed));
    const receipt = hex(ar.receipt_wire);
    const doc = expectType<AccountResetReceipt>(verifyDocument(receipt, authority.publicKey), DocumentType.AccountResetReceipt);
    expect(doc.accountName).toBe("alice");
    expect(toHex(doc.oldIdentityId)).toBe(alice.identity_id);
    const newCert = expectType<AccountDevice>(verifyDocument(hex(ar.new_account_certificate)), DocumentType.AccountDevice);
    expect(toHex(doc.newIdentityId)).toBe(toHex(identityId(newCert.accountName, newCert.accountKey)));
    expect(toHex(doc.authorityKeyId)).toBe(ar.authority_key_id);
    expect(receipt.length).toBe(171 + 5);
    expect(toHex(buildResetReceipt(doc, authority.secretKey))).toBe(toHex(receipt));
    expect(code(() => verifyDocument(receipt, aliceAccount.publicKey))).toBe("BAD_SIGNATURE");
    const standby = signingKeypairFromSeed(hex(rkm.standby_seed));
    const re = expectType<AccountResetReceipt>(verifyDocument(hex(rkm.reattested_receipt_wire), standby.publicKey), DocumentType.AccountResetReceipt);
    expect(toHex(re.authorityKeyId)).toBe(rkm.standby_id);
    expect(toHex(re.resetId)).toBe(toHex(doc.resetId));
  });
});

describe("phone replacement documents", () => {
  it("parses the new certificate, the continued snapshot, the new manifest and record", () => {
    const pr = fx.phone_replacement;
    const cert = expectType<AccountDevice>(verifyDocument(hex(pr.new_certificate)), DocumentType.AccountDevice);
    expect(cert.generation).toBe(2n);
    expect(toHex(identityId(cert.accountName, cert.accountKey))).toBe(alice.identity_id);
    const next = expectType<CircleSnapshot>(verifyDocument(hex(pr.next_owner_snapshot), aliceAccount.publicKey), DocumentType.CircleSnapshot);
    expect(next.revision).toBe(2n);
    const newDsk = deviceSigningKeypair(hex(fixture.phone_replacement.new_device_seed));
    const m = expectType<EpochManifest>(verifyDocument(hex(pr.new_manifest), newDsk.publicKey), DocumentType.EpochManifest);
    expect(toHex(m.authorCertificateHash)).toBe(toHex(cert.bodyHash));
    expect(m.epoch).toBe(1);
    const r = expectType<EncryptedRecord>(verifyDocument(hex(pr.new_record), newDsk.publicKey), DocumentType.EncryptedRecord);
    expect(toHex(r.streamId)).toBe(toHex(m.streamId));
    expect(toHex(r.streamId)).not.toBe(alice.stream_id);
    for (const d of pr.device_rejections) parseDocument(hex(d.wire));
  });
});

describe("durable events", () => {
  it("a check-in is kind 1 and a later location is kind 0, on one counter", () => {
    const c = expectType<EncryptedRecord>(verifyDocument(hex(fx.durable_events.checkin_wire), aliceDsk.publicKey), DocumentType.EncryptedRecord);
    const l = expectType<EncryptedRecord>(verifyDocument(hex(fx.durable_events.following_location_wire), aliceDsk.publicKey), DocumentType.EncryptedRecord);
    expect([c.headerClass, c.counter, l.headerClass, l.counter]).toEqual([1, 1, 0, 2]);
    expect([decodeEnvelope(openRecord(c, epochKey)).kind, decodeEnvelope(openRecord(l, epochKey)).kind]).toEqual([1, 0]);
  });
});

describe("location codec", () => {
  it("decodes the fixture plaintext and round-trips", () => {
    const l = decodeLocation(hex(fx.record.payload));
    const d = fx.record.decoded;
    expect(l).toEqual({ latitudeE7: d.latitude_e7, longitudeE7: d.longitude_e7, accuracyMm: d.accuracy_mm, capturedAt: BigInt(d.captured_at_ms), status: d.status });
    expect(toHex(encodeLocation(l))).toBe(fx.record.payload);
    expect(encodeLocation({ latitudeE7: 0, longitudeE7: 0, accuracyMm: 0, capturedAt: 0n, status: 2 }).length).toBe(22);
  });

  it("rejects out-of-range and inconsistent values", () => {
    const base = decodeLocation(hex(fx.record.payload));
    expect(code(() => encodeLocation({ ...base, latitudeE7: 900_000_001 }))).toBe("BAD_PAYLOAD");
    expect(code(() => encodeLocation({ ...base, longitudeE7: -1_800_000_001 }))).toBe("BAD_PAYLOAD");
    expect(code(() => encodeLocation({ ...base, accuracyMm: 100_000_001 }))).toBe("BAD_PAYLOAD");
    expect(code(() => encodeLocation({ ...base, status: 2 }))).toBe("BAD_PAYLOAD");
    expect(code(() => decodeLocation(concat(fromHex("02"), hex(fx.record.payload).subarray(1))))).toBe("BAD_PAYLOAD");
    expect(code(() => decodeLocation(hex(fx.record.payload).subarray(0, 21)))).toBe("BAD_PAYLOAD");
  });
});

describe("account vault and recovery code", () => {
  const rv = fx.recovery_vault;
  const rk = hex(rv.recovery_key);

  it("opens the fixture vault and rebuilds it byte for byte", () => {
    const v = openVault(hex(rv.wire), rk, "alice", aliceAccount.publicKey);
    expect(toHex(v.accountSeed)).toBe(str(fixture.inputs["alice_account_seed"] ?? ""));
    expect(v.lastDeviceGeneration).toBe(1n);
    expect(toHex(v.lastCertificateHash)).toBe(alice.certificate_hash);
    expect(v.header.vaultRevision).toBe(1n);
    expect(v.entries.length).toBe(1);
    expect(toHex(v.entries[0]?.circleId ?? new Uint8Array())).toBe(toHex(circleId));
    expect(toHex(v.entries[0]?.ownerIdentityId ?? new Uint8Array())).toBe(alice.identity_id);
    expect(v.entries[0]?.sharingEnabled).toBe(true);
    expect(toHex(sealVault(v.header, v, rk, hex(rv.nonce)))).toBe(rv.wire);
    expect(hex(rv.wire).length).toBe(43 + 5 + 24 + 4 + 90 + 49);
  });

  it("opens the empty and sharing-disabled vaults", () => {
    expect(openVault(hex(rv.empty_vault), rk, "alice", aliceAccount.publicKey).entries).toEqual([]);
    expect(openVault(hex(rv.sharing_disabled_vault), rk, "alice", aliceAccount.publicKey).entries[0]?.sharingEnabled).toBe(false);
  });

  it("fails closed on the wrong key, name or account key", () => {
    expect(code(() => openVault(hex(rv.wire), new Uint8Array(32), "alice", aliceAccount.publicKey))).toBe("DECRYPT_FAILED");
    expect(code(() => openVault(hex(rv.wire), rk, "bob", aliceAccount.publicKey))).toBe("VAULT_BINDING");
    expect(code(() => openVault(hex(rv.wire), rk, "alice", bobAccount.publicKey))).toBe("VAULT_BINDING");
    const trailing = concat(hex(rv.wire), fromHex("00"));
    expect(code(() => openVault(trailing, rk, "alice", aliceAccount.publicKey))).toBe("MALFORMED");
  });

  it("encodes the 48-character recovery code and decodes it strictly", () => {
    expect(encodeRecoveryCode(rk)).toBe(rv.recovery_code);
    expect(rv.recovery_code.length).toBe(48);
    expect(toHex(decodeRecoveryCode(rv.recovery_code))).toBe(rv.recovery_key);
    expect(code(() => decodeRecoveryCode("SS5T-" + rv.recovery_code.slice(5)))).toBe("MALFORMED");
    expect(code(() => decodeRecoveryCode(rv.recovery_code + "A"))).toBe("MALFORMED");
    expect(code(() => decodeRecoveryCode(rv.recovery_code.slice(0, -1) + "+"))).toBe("MALFORMED");
    expect(code(() => decodeRecoveryCode(rv.recovery_code.slice(0, -1) + (rv.recovery_code.endsWith("A") ? "B" : "A")))).not.toBe("ACCEPTED_WRONG");
  });
});
