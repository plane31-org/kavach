import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { DocumentType, expectType, verifyDocument, type AccountDevice } from "../src/codec.js";
import { ready } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { acceptSnapshot, pinCircle, type CircleState } from "../src/circle.js";
import { acceptCertificate, pinFromCertificate, type AccountPin } from "../src/identity.js";
import { applyAudienceEvent, initialRevisionState, isEligible, resolveAudience } from "../src/audience.js";
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

interface Extra {
  boundary_100: { snapshot_wire: string; accounts: string[] };
  phone_replacement: { new_certificate: string };
}
const fx = fixture as unknown as typeof fixture & Extra;
const alice = fixture.identities[0];
const bob = fixture.identities[1];
if (!alice || !bob) throw new Error("fixture");
const circleId = hex(str(fixture.inputs["circle_id"] ?? ""));
const now = 1_700_000_000_000n;

function pinOf(wire: string): AccountPin {
  return pinFromCertificate(expectType<AccountDevice>(verifyDocument(hex(wire)), DocumentType.AccountDevice));
}

function memberCircle(self: Uint8Array): CircleState {
  const r = acceptSnapshot(pinCircle(circleId, hex(alice.identity_id), true, "member"), hex(fixture.documents["snapshot"]?.wire ?? ""), hex(alice.account_public), self, now);
  if (r.outcome !== "ACCEPTED") throw new Error("snapshot");
  return r.state;
}

describe("audience resolution", () => {
  const alicePin = pinOf(fixture.documents["alice_account"]?.wire ?? "");
  const bobPin = pinOf(fixture.documents["bob_account"]?.wire ?? "");

  it("resolves self plus the members of eligible circles, sorted, at their current certificates", () => {
    const pins = new Map([[bob.identity_id, bobPin]]);
    const a = resolveAudience(alicePin, [memberCircle(alicePin.identityId)], pins);
    expect(a.recipientCount).toBe(1);
    expect(a.rows.map((r) => toHex(r.identityId))).toEqual([alice.identity_id, bob.identity_id].sort());
    const bobRow = a.rows.find((r) => toHex(r.identityId) === bob.identity_id);
    expect(bobRow && toHex(bobRow.certificateHash)).toBe(bob.certificate_hash);
    expect(bobRow && toHex(bobRow.boxKey)).toBe(bob.device_box_public);
  });

  it("a disabled, requested, quarantined or closed circle contributes nothing; self alone is valid", () => {
    const pins = new Map([[bob.identity_id, bobPin]]);
    const c = memberCircle(alicePin.identityId);
    for (const variant of [{ ...c, enabled: false }, { ...c, status: "requested" as const }, { ...c, status: "quarantined" as const }, { ...c, status: "closed" as const }]) {
      expect(isEligible(variant, alicePin.identityId)).toBe(false);
      expect(resolveAudience(alicePin, [variant], pins).recipientCount).toBe(0);
    }
    const selfOnly = resolveAudience(alicePin, [], pins);
    expect(selfOnly.rows.length).toBe(1);
    expect(selfOnly.recipientCount).toBe(0);
  });

  it("a member without a certificate is METADATA_REQUIRED, never omitted", () => {
    expect(code(() => resolveAudience(alicePin, [memberCircle(alicePin.identityId)], new Map()))).toBe("METADATA_REQUIRED");
  });

  it("a replaced recipient device changes the row; the pin is what counts", () => {
    const newAlice = pinOf(fx.phone_replacement.new_certificate);
    const pins = new Map([[alice.identity_id, newAlice]]);
    const a = resolveAudience(bobPin, [memberCircle(bobPin.identityId)], pins);
    const row = a.rows.find((r) => toHex(r.identityId) === alice.identity_id);
    expect(row && toHex(row.certificateHash)).toBe(toHex(newAlice.certificateHash));
    expect(row && toHex(row.boxKey)).not.toBe(alice.device_box_public);
  });

  it("100 distinct accounts is the limit; 101 pauses with RECIPIENT_LIMIT, nothing truncated", () => {
    const pins = new Map<string, AccountPin>();
    for (const w of fx.boundary_100.accounts) {
      const p = pinOf(w);
      pins.set(toHex(p.identityId), p);
    }
    const big = acceptSnapshot({ ...pinCircle(circleId, hex(alice.identity_id), true, "member"), revision: 1n }, hex(fx.boundary_100.snapshot_wire), hex(alice.account_public), alicePin.identityId, now);
    if (big.outcome !== "ACCEPTED") throw new Error("big");
    const hundred = resolveAudience(alicePin, [big.state], pins);
    expect(hundred.rows.length).toBe(100);
    expect(hundred.recipientCount).toBe(99);
    // A second circle adds Bob: the union is 101 distinct accounts.
    pins.set(bob.identity_id, bobPin);
    const second: CircleState = { ...memberCircle(alicePin.identityId), circleId: new Uint8Array(16).fill(5) };
    expect(code(() => resolveAudience(alicePin, [big.state, second], pins))).toBe("RECIPIENT_LIMIT");
    // The same account in two circles is counted once.
    const dupe: CircleState = { ...big.state, circleId: new Uint8Array(16).fill(6) };
    expect(resolveAudience(alicePin, [big.state, dupe], pins).rows.length).toBe(100);
  });
});

describe("desired revision", () => {
  it("increments on a new snapshot revision even with an unchanged member set, and not on reprocessing", () => {
    let s = initialRevisionState;
    let r = applyAudienceEvent(s, { kind: "snapshot", circleId, revision: 12n });
    expect(r.changed).toBe(true);
    s = r.state;
    r = applyAudienceEvent(s, { kind: "snapshot", circleId, revision: 12n });
    expect(r.changed).toBe(false);
    r = applyAudienceEvent(s, { kind: "snapshot", circleId, revision: 11n });
    expect(r.changed).toBe(false);
    // Remove then rejoin between two syncs arrives as revision 14 with the old member set: still a rotation.
    r = applyAudienceEvent(s, { kind: "snapshot", circleId, revision: 14n });
    expect(r.changed).toBe(true);
    expect(r.state.desiredRevision).toBe(3n);
  });

  it("increments on a recipient's device change once per certificate, and on every own change", () => {
    let s = initialRevisionState;
    const ev = { kind: "deviceChanged" as const, identityId: hex(alice.identity_id), certificateHash: new Uint8Array(32).fill(1) };
    let r = applyAudienceEvent(s, ev);
    expect(r.changed).toBe(true);
    s = r.state;
    expect(applyAudienceEvent(s, ev).changed).toBe(false);
    r = applyAudienceEvent(s, { ...ev, certificateHash: new Uint8Array(32).fill(2) });
    expect(r.changed).toBe(true);
    s = r.state;
    for (const kind of ["ownActivation", "join", "leave", "enable", "disable", "counterExhausted", "hygiene", "clockReversal"] as const) {
      const e = kind === "ownActivation" || kind === "counterExhausted" || kind === "hygiene" || kind === "clockReversal" ? { kind } : { kind, circleId };
      r = applyAudienceEvent(s, e as Parameters<typeof applyAudienceEvent>[1]);
      expect(r.changed).toBe(true);
      s = r.state;
    }
    expect(s.desiredRevision).toBe(11n);
  });

  it("an accepted higher certificate is what the pin layer reports as a rotation", () => {
    const first = acceptCertificate(undefined, hex(fixture.documents["alice_account"]?.wire ?? ""));
    if (first.outcome !== "ACCEPTED") throw new Error("pin");
    const next = acceptCertificate(first.pin, hex(fx.phone_replacement.new_certificate));
    expect(next.outcome === "ACCEPTED" && next.rotate).toBe(true);
  });
});
