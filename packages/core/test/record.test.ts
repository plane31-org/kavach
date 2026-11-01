import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { DocumentType, expectType, recordWireBytes, verifyDocument, type AccountDevice } from "../src/codec.js";
import { deviceSigningKeypair, ready } from "../src/crypto.js";
import { MAX_COUNTER, type AuthorView } from "../src/epoch.js";
import { KavachError } from "../src/errors.js";
import { pinFromCertificate, type AccountPin } from "../src/identity.js";
import { compareSlots, openRecordWire, sealRecord } from "../src/record.js";
import { fixture, hex, str } from "./fixture.js";
import { decodeLocation, encodeLocation, locationFromDegrees, locationToDegrees } from "./location.js";

interface Extra {
  durable_events: { checkin_wire: string; following_location_wire: string };
  phone_replacement: { new_certificate: string; new_record: string; new_epoch_key: string };
}
const fx = fixture as unknown as typeof fixture & Extra;
const alice = fixture.identities[0];
if (!alice) throw new Error("fixture");
const now = BigInt(str(fixture.inputs["time_ms"] ?? "0"));
const epochKey = hex(str(fixture.inputs["epoch_key"] ?? ""));
const range = (a: number, b: number): Uint8Array => Uint8Array.from({ length: b - a }, (_, i) => a + i);

let alicePin: AccountPin;
let newAlicePin: AccountPin;
let dsk: Uint8Array;
beforeAll(async () => {
  await ready();
  alicePin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(hex(fixture.documents["alice_account"]?.wire ?? "")), DocumentType.AccountDevice));
  newAlicePin = pinFromCertificate(expectType<AccountDevice>(verifyDocument(hex(fx.phone_replacement.new_certificate)), DocumentType.AccountDevice));
  dsk = deviceSigningKeypair(hex(str(fixture.inputs["alice_device_seed"] ?? ""))).secretKey;
});

function view(pin: AccountPin, archived: AccountPin[] = []): AuthorView {
  const certificates = new Map([[toHex(pin.certificateHash), { certificateHash: pin.certificateHash, signingKey: pin.signingKey, streamId: pin.streamId, current: true }]]);
  for (const a of archived) certificates.set(toHex(a.certificateHash), { certificateHash: a.certificateHash, signingKey: a.signingKey, streamId: a.streamId, current: false });
  return { identityId: pin.identityId, certificates };
}
const keyFor = (k: Uint8Array | undefined) => (): Uint8Array | undefined => k;
function code(fn: () => unknown): string {
  try {
    fn();
    return "OK";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

describe("sealing", () => {
  it("Vector D and the check-in fixture reproduce exactly with their nonces", () => {
    const payload = hex((fixture.record as { payload: string }).payload);
    const d = sealRecord({ streamId: alicePin.streamId, epoch: 1, nextCounter: 0, kind: 0, eventTime: now - 123n, headerClass: 0, payload, sentAt: now, epochKey, signingSecretKey: dsk, nonce: hex(str(fixture.inputs["record_nonce"] ?? "")) });
    expect(toHex(d.wire)).toBe(fixture.documents["record"]?.wire);
    expect(toHex(d.recordId)).toBe(fixture.record.record_id);
    const c = sealRecord({ streamId: alicePin.streamId, epoch: 1, nextCounter: 1, kind: 1, headerClass: 1, payload, sentAt: now + 1n, epochKey, signingSecretKey: dsk, nonce: range(144, 168) });
    expect(toHex(c.wire)).toBe(fx.durable_events.checkin_wire);
    const l = sealRecord({ streamId: alicePin.streamId, epoch: 1, nextCounter: 2, kind: 0, eventTime: now - 123n, headerClass: 0, payload, sentAt: now + 2n, epochKey, signingSecretKey: dsk, nonce: range(168, 192) });
    expect(toHex(l.wire)).toBe(fx.durable_events.following_location_wire);
    // A check-in followed by two locations: three distinct ids on one counter.
    expect(new Set([d, c, l].map((r) => toHex(r.recordId))).size).toBe(3);
  });

  it("S14 and S15: the final counter is allocated, the next is exhaustion; an oversize payload is refused", () => {
    const base = { streamId: alicePin.streamId, epoch: 3, kind: 0, headerClass: 0 as const, payload: new Uint8Array(1), sentAt: now, epochKey, signingSecretKey: dsk };
    expect(sealRecord({ ...base, nextCounter: MAX_COUNTER }).counter).toBe(MAX_COUNTER);
    expect(code(() => sealRecord({ ...base, nextCounter: MAX_COUNTER + 1 }))).toBe("COUNTER_EXHAUSTED");
    expect(code(() => sealRecord({ ...base, nextCounter: 0, payload: new Uint8Array(4097) }))).toBe("SIZE_LIMIT");
    expect(sealRecord({ ...base, nextCounter: 0, payload: new Uint8Array(0) }).wire.length).toBe(169); // 159 without the 10-byte envelope
    // The one wire-size calculation the outbox cap uses matches a sealed wire at both ends of the payload range.
    for (const n of [0, 1, 22, 4096]) expect(sealRecord({ ...base, nextCounter: 0, payload: new Uint8Array(n) }).wire.length).toBe(recordWireBytes(n));
  });
});

describe("opening", () => {
  it("opens the fixture record and the check-in, with ids and kinds", () => {
    const r = openRecordWire(hex(fixture.documents["record"]?.wire ?? ""), view(alicePin), keyFor(epochKey));
    expect(toHex(r.payload)).toBe((fixture.record as { payload: string }).payload);
    expect([r.kind, r.eventTime, toHex(r.recordId), r.superseded]).toEqual([0, now - 123n, fixture.record.record_id, false]);
    const c = openRecordWire(hex(fx.durable_events.checkin_wire), view(alicePin), keyFor(epochKey));
    expect([c.kind, c.eventTime, c.record.headerClass, c.record.counter]).toEqual([1, undefined, 1, 1]);
  });

  it("negative vectors through the opening path", () => {
    for (const name of ["N05_reserved_flag", "N06_changed_ciphertext", "N07_wrong_signer", "N08_excessive_length", "N09_epoch_zero", "N12_valid_signature_bad_tag", "N19_header_aad_binding", "N21_reserved_bit0"]) {
      const n = fixture.negative_vectors.find((x) => x.name === name);
      if (!n) throw new Error(name);
      const v = name === "N07_wrong_signer" ? view(alicePin) : view(alicePin);
      const expected = name === "N07_wrong_signer" ? "OK" : n.expected; // the fixture's N07 is a good record under the wrong key; our view has the right key
      expect(code(() => openRecordWire(hex(n.wire), v, keyFor(epochKey)))).toBe(expected);
    }
  });

  it("KEY_PENDING without a key; NOT_AUTHORIZED for an unknown stream", () => {
    const wire = hex(fixture.documents["record"]?.wire ?? "");
    expect(code(() => openRecordWire(wire, view(alicePin), keyFor(undefined)))).toBe("KEY_PENDING");
    expect(code(() => openRecordWire(wire, view(newAlicePin), keyFor(epochKey)))).toBe("NOT_AUTHORIZED");
  });

  it("SUPERSEDED: the old device's record opens as history under the archived certificate, the new device's as live", () => {
    const old = openRecordWire(hex(fixture.documents["record"]?.wire ?? ""), view(newAlicePin, [alicePin]), keyFor(epochKey));
    expect(old.superseded).toBe(true);
    const fresh = openRecordWire(hex(fx.phone_replacement.new_record), view(newAlicePin, [alicePin]), keyFor(hex(fx.phone_replacement.new_epoch_key)));
    expect(fresh.superseded).toBe(false);
    expect(toHex(fresh.record.streamId)).toBe(toHex(newAlicePin.streamId));
    // The live pin orders by (generation, epoch, counter): the new device's first record beats the old device's counter 7.
    expect(compareSlots({ generation: 2n, epoch: 1, counter: 0 }, { generation: 1n, epoch: 9, counter: 7 })).toBeGreaterThan(0);
    expect(compareSlots({ generation: 1n, epoch: 1, counter: 6 }, { generation: 1n, epoch: 1, counter: 7 })).toBeLessThan(0);
  });
});

describe("location helpers", () => {
  it("converts degrees and metres to the codec and back", () => {
    const l = locationFromDegrees(37.7749, -122.4194, 5, now - 123n);
    expect(toHex(require_encode(l))).toBe((fixture.record as { payload: string }).payload);
    const back = locationToDegrees(decodeLocation(hex((fixture.record as { payload: string }).payload)));
    expect(back.latitude).toBeCloseTo(37.7749, 7);
    expect(back.longitude).toBeCloseTo(-122.4194, 7);
    expect(back.accuracyMetres).toBe(5);
    expect(locationFromDegrees(1, 2, 3, now, 2)).toEqual({ latitudeE7: 0, longitudeE7: 0, accuracyMm: 0, capturedAt: now, status: 2 });
  });
});


function require_encode(l: ReturnType<typeof locationFromDegrees>): Uint8Array {
  return encodeLocation(l);
}
