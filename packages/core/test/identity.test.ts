import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { DocumentType, expectType, parseDocument, verifyDocument, type AccountDevice } from "../src/codec.js";
import { ready } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { acceptCertificate, certify, deviceFromSeed, newDevice, openAccount, pinFromCertificate, type AccountPin } from "../src/identity.js";
import { fixture, hex, str } from "./fixture.js";

beforeAll(() => ready());

function code(fn: () => unknown): string {
  try {
    fn();
    return "ACCEPTED";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

const pr = fixture.phone_replacement as typeof fixture.phone_replacement & { device_rejections: { wire: string; expected: string }[] };

describe("certificates and generation rules", () => {
  it("pins Alice at first contact with the directory's expected key, and refuses another key", () => {
    const wire = hex(fixture.documents["alice_account"]?.wire ?? "");
    const alice = fixture.identities[0];
    if (!alice) throw new Error("fixture");
    const first = acceptCertificate(undefined, wire, { accountName: "alice", accountKey: hex(alice.account_public) });
    expect(first.outcome).toBe("ACCEPTED");
    if (first.outcome !== "ACCEPTED") return;
    expect(first.rotate).toBe(false);
    expect(toHex(first.pin.identityId)).toBe(alice.identity_id);
    expect(toHex(first.pin.streamId)).toBe(alice.stream_id);
    expect(toHex(first.pin.certificateHash)).toBe(alice.certificate_hash);
    expect(first.pin.deviceIds.length).toBe(1);
    const bob = fixture.identities[1];
    if (!bob) throw new Error("fixture");
    expect(code(() => acceptCertificate(undefined, wire, { accountName: "alice", accountKey: hex(bob.account_public) }))).toBe("ACCOUNT_KEY_CHANGED");
    expect(code(() => acceptCertificate(undefined, wire, { accountName: "alicia", accountKey: hex(alice.account_public) }))).toBe("ACCOUNT_KEY_CHANGED");
  });

  it("Vector E: the new phone is accepted with a rotation, then the three rejections", () => {
    const gen1 = acceptCertificate(undefined, hex(fixture.documents["alice_account"]?.wire ?? ""));
    if (gen1.outcome !== "ACCEPTED") throw new Error("gen1");
    const gen2 = acceptCertificate(gen1.pin, hex(pr.new_certificate));
    expect(gen2.outcome).toBe("ACCEPTED");
    if (gen2.outcome !== "ACCEPTED") return;
    expect(gen2.rotate).toBe(true);
    expect(gen2.pin.generation).toBe(2n);
    expect(toHex(gen2.pin.identityId)).toBe(pr.stable_identity_id);
    expect(toHex(gen2.pin.deviceId)).toBe(pr.new_device_id);
    expect(gen2.pin.deviceIds.length).toBe(2);
    expect(toHex(gen2.pin.streamId)).not.toBe(toHex(gen1.pin.streamId));
    expect(code(() => acceptCertificate(gen2.pin, hex(fixture.documents["alice_account"]?.wire ?? "")))).toBe("DEVICE_ROLLBACK");
    for (const d of pr.device_rejections) {
      expect(code(() => acceptCertificate(gen2.pin, hex(d.wire)))).toBe(d.expected);
    }
    expect(acceptCertificate(gen2.pin, hex(pr.new_certificate)).outcome).toBe("DUPLICATE");
  });

  it("accepts generation 3 after 2 with a rotation, and a gap from 2 to 5, but never a reused device id", () => {
    const account = openAccount("alice", hex(str(fixture.inputs["alice_account_seed"] ?? "")));
    const current = acceptCertificate(undefined, hex(pr.new_certificate));
    if (current.outcome !== "ACCEPTED") throw new Error("pin");
    const d3 = newDevice();
    const gen3 = acceptCertificate(current.pin, certify(account, d3, 3n));
    expect(gen3.outcome === "ACCEPTED" && gen3.rotate).toBe(true);
    if (gen3.outcome !== "ACCEPTED") return;
    const gen5 = acceptCertificate(gen3.pin, certify(account, newDevice(), 5n));
    expect(gen5.outcome).toBe("ACCEPTED");
    if (gen5.outcome !== "ACCEPTED") return;
    expect(gen5.pin.generation).toBe(5n);
    expect(code(() => acceptCertificate(gen5.pin, certify(account, newDevice(), 4n)))).toBe("DEVICE_ROLLBACK");
    // Generation 6 that reuses device 3's id is refused even though 3 is no longer current.
    expect(code(() => acceptCertificate(gen5.pin, certify(account, deviceFromSeed(newDevice().deviceSeed, d3.deviceId), 6n)))).toBe("DEVICE_ID_REUSED");
    // Same generation, different body: EQUIVOCATION.
    expect(code(() => acceptCertificate(gen5.pin, certify(account, newDevice(), 5n)))).toBe("EQUIVOCATION");
  });

  it("a changed account key is reported and leaves the pin untouched", () => {
    const current = acceptCertificate(undefined, hex(fixture.documents["alice_account"]?.wire ?? ""));
    if (current.outcome !== "ACCEPTED") throw new Error("pin");
    const impostor = pr.device_rejections.find((d) => d.expected === "ACCOUNT_KEY_CHANGED");
    if (!impostor) throw new Error("fixture");
    const before = JSON.stringify(current.pin, (_, v: unknown) => (v instanceof Uint8Array ? toHex(v) : typeof v === "bigint" ? v.toString() : v));
    expect(code(() => acceptCertificate(current.pin, hex(impostor.wire)))).toBe("ACCOUNT_KEY_CHANGED");
    const after = JSON.stringify(current.pin, (_, v: unknown) => (v instanceof Uint8Array ? toHex(v) : typeof v === "bigint" ? v.toString() : v));
    expect(after).toBe(before);
  });

  it("certify reproduces the fixture certificates from the seeds", () => {
    const account = openAccount("alice", hex(str(fixture.inputs["alice_account_seed"] ?? "")));
    const alice = fixture.identities[0];
    if (!alice) throw new Error("fixture");
    const device = deviceFromSeed(hex(str(fixture.inputs["alice_device_seed"] ?? "")), hex(alice.device_id));
    expect(toHex(certify(account, device, 1n))).toBe(fixture.documents["alice_account"]?.wire);
    const newPhone = deviceFromSeed(hex(pr.new_device_seed), hex(pr.new_device_id));
    expect(toHex(certify(account, newPhone, 2n))).toBe(pr.new_certificate);
    const doc = expectType<AccountDevice>(verifyDocument(hex(pr.new_certificate)), DocumentType.AccountDevice);
    const pin: AccountPin = pinFromCertificate(doc);
    expect(toHex(pin.certificate)).toBe(pr.new_certificate);
    expect(parseDocument(pin.certificate).type).toBe(DocumentType.AccountDevice);
  });
});
