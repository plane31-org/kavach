import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { resolveAudience } from "../src/audience.js";
import { acceptSnapshot, pinCircle } from "../src/circle.js";
import { DocumentType, buildEpochManifest, expectType, verifyDocument, type AccountDevice } from "../src/codec.js";
import { deviceBoxKeypair, deviceSigningKeypair, keyCommitment, openSealedBox, ready, sealBox, wrapHash } from "../src/crypto.js";
import { MAX_COUNTER, openEpoch, prepareEpoch, promote, resolvePublish, rotationReason, type AuthorView, type PreparedEpoch, type SelfView } from "../src/epoch.js";
import { KavachError } from "../src/errors.js";
import { pinFromCertificate, type AccountPin } from "../src/identity.js";
import { fixture, hex, str } from "./fixture.js";

interface Extra {
  phone_replacement: { new_certificate: string; new_manifest: string; new_wraps: Record<string, string>; new_epoch_key: string; new_device_seed: string };
}
const fx = fixture as unknown as typeof fixture & Extra;
const alice = fixture.identities[0];
const bob = fixture.identities[1];
if (!alice || !bob) throw new Error("fixture");
const now = BigInt(str(fixture.inputs["time_ms"] ?? "0"));
const epochKey = hex(str(fixture.inputs["epoch_key"] ?? ""));

let alicePin: AccountPin;
let bobPin: AccountPin;
let newAlicePin: AccountPin;
beforeAll(async () => {
  await ready();
  alicePin = pinOf(fixture.documents["alice_account"]?.wire ?? "");
  bobPin = pinOf(fixture.documents["bob_account"]?.wire ?? "");
  newAlicePin = pinOf(fx.phone_replacement.new_certificate);
});

function pinOf(wire: string): AccountPin {
  return pinFromCertificate(expectType<AccountDevice>(verifyDocument(hex(wire)), DocumentType.AccountDevice));
}
function authorView(pin: AccountPin, archived: AccountPin[] = []): AuthorView {
  const certificates = new Map([[toHex(pin.certificateHash), { certificateHash: pin.certificateHash, signingKey: pin.signingKey, streamId: pin.streamId, current: true }]]);
  for (const a of archived) certificates.set(toHex(a.certificateHash), { certificateHash: a.certificateHash, signingKey: a.signingKey, streamId: a.streamId, current: false });
  return { identityId: pin.identityId, certificates };
}
function selfView(pin: AccountPin, deviceSeed: string): SelfView {
  return { identityId: pin.identityId, certificateHash: pin.certificateHash, box: deviceBoxKeypair(hex(deviceSeed)) };
}
function code(fn: () => unknown): string {
  try {
    fn();
    return "OK";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}
const wrapFor = (iid: string): Uint8Array => hex(fixture.wraps.find((w) => w.recipient_identity === iid)?.sealed_box ?? "");

describe("Vector C: opening the fixture epoch", () => {
  it("opens for Alice and for Bob with every check passing", () => {
    const manifest = hex(fixture.documents["manifest"]?.wire ?? "");
    const a = openEpoch(manifest, authorView(alicePin), selfView(alicePin, str(fixture.inputs["alice_device_seed"] ?? "")), wrapFor(alice.identity_id));
    const b = openEpoch(manifest, authorView(alicePin), selfView(bobPin, str(fixture.inputs["bob_device_seed"] ?? "")), wrapFor(bob.identity_id));
    expect(toHex(a.epochKey)).toBe(toHex(epochKey));
    expect(toHex(b.epochKey)).toBe(toHex(epochKey));
    expect(a.superseded).toBe(false);
    expect(a.manifest.epoch).toBe(1);
  });

  it("W01 to W03 and the other rejections", () => {
    const manifest = hex(fixture.documents["manifest"]?.wire ?? "");
    const bobSelf = selfView(bobPin, str(fixture.inputs["bob_device_seed"] ?? ""));
    // W01: Alice's wrap handed to Bob fails the wrap-hash check before any decryption.
    expect(code(() => openEpoch(manifest, authorView(alicePin), bobSelf, wrapFor(alice.identity_id)))).toBe("WRAP_HASH_MISMATCH");
    // W02: a tampered box fails the same way; the box itself also fails to open.
    const tampered = Uint8Array.from(wrapFor(bob.identity_id));
    tampered[79] ^= 1;
    expect(code(() => openEpoch(manifest, authorView(alicePin), bobSelf, tampered))).toBe("WRAP_HASH_MISMATCH");
    expect(code(() => openSealedBox(tampered, bobSelf.box))).toBe("DECRYPT_FAILED");
    // Not addressed: a stranger, and Bob's row under another certificate.
    expect(code(() => openEpoch(manifest, authorView(alicePin), { ...bobSelf, identityId: new Uint8Array(32).fill(9) }, wrapFor(bob.identity_id)))).toBe("NOT_AUTHORIZED");
    expect(code(() => openEpoch(manifest, authorView(alicePin), { ...bobSelf, certificateHash: new Uint8Array(32) }, wrapFor(bob.identity_id)))).toBe("NOT_AUTHORIZED");
    // Wrong author key.
    expect(code(() => openEpoch(manifest, authorView(bobPin), bobSelf, wrapFor(bob.identity_id)))).toBe("SUPERSEDED_DEVICE");
    const wrongKey: AuthorView = { identityId: alicePin.identityId, certificates: new Map([[toHex(alicePin.certificateHash), { certificateHash: alicePin.certificateHash, signingKey: bobPin.signingKey, streamId: alicePin.streamId, current: true }]]) };
    expect(code(() => openEpoch(manifest, wrongKey, bobSelf, wrapFor(bob.identity_id)))).toBe("BAD_SIGNATURE");
  });

  it("W03: a manifest whose commitment does not match the sealed key is KEY_COMMITMENT_MISMATCH", () => {
    const keyA = new Uint8Array(32).fill(0x33);
    const keyB = new Uint8Array(32).fill(0x44);
    const dsk = deviceSigningKeypair(hex(str(fixture.inputs["alice_device_seed"] ?? ""))).secretKey;
    const bobWrap = sealBox(keyA, bobPin.boxKey);
    const aliceWrap = sealBox(keyA, alicePin.boxKey);
    const rows = [
      { identityId: alicePin.identityId, certificateHash: alicePin.certificateHash, wrapHash: wrapHash(aliceWrap) },
      { identityId: bobPin.identityId, certificateHash: bobPin.certificateHash, wrapHash: wrapHash(bobWrap) }
    ];
    const base = { streamId: alicePin.streamId, authorIdentityId: alicePin.identityId, authorCertificateHash: alicePin.certificateHash, epoch: 5, createdAt: now, audience: rows };
    const bobSelf = selfView(bobPin, str(fixture.inputs["bob_device_seed"] ?? ""));
    const forged = buildEpochManifest({ ...base, keyCommitment: keyCommitment(alicePin.streamId, 5, keyB) }, dsk);
    expect(code(() => openEpoch(forged, authorView(alicePin), bobSelf, bobWrap))).toBe("KEY_COMMITMENT_MISMATCH");
    const honest = buildEpochManifest({ ...base, keyCommitment: keyCommitment(alicePin.streamId, 5, keyA) }, dsk);
    expect(toHex(openEpoch(honest, authorView(alicePin), bobSelf, bobWrap).epochKey)).toBe(toHex(keyA));
    // A box sealed to someone else under the right hash cannot exist; a box that fails to open is DECRYPT_FAILED.
    const foreign = sealBox(keyA, alicePin.boxKey);
    const rowsForeign = [rows[0] as (typeof rows)[0], { ...(rows[1] as (typeof rows)[1]), wrapHash: wrapHash(foreign) }];
    const misaddressed = buildEpochManifest({ ...base, audience: rowsForeign, keyCommitment: keyCommitment(alicePin.streamId, 5, keyA) }, dsk);
    expect(code(() => openEpoch(misaddressed, authorView(alicePin), bobSelf, foreign))).toBe("DECRYPT_FAILED");
  });
});

function circleOf(self: AccountPin) {
  const r = acceptSnapshot(pinCircle(hex(str(fixture.inputs["circle_id"] ?? "")), hex(alice.identity_id), true, "member"), hex(fixture.documents["snapshot"]?.wire ?? ""), hex(alice.account_public), self.identityId, now);
  if (r.outcome !== "ACCEPTED") throw new Error("circle");
  return r.state;
}

describe("Vector E: the replacement device", () => {
  it("the old phone cannot open the new wrap, and the new manifest is not addressed to it", () => {
    const newManifest = hex(fx.phone_replacement.new_manifest);
    const newWrap = hex(fx.phone_replacement.new_wraps[alice.identity_id] ?? "");
    const oldSelf = selfView(alicePin, str(fixture.inputs["alice_device_seed"] ?? ""));
    expect(code(() => openSealedBox(newWrap, oldSelf.box))).toBe("DECRYPT_FAILED");
    expect(code(() => openEpoch(newManifest, authorView(newAlicePin), oldSelf, newWrap))).toBe("NOT_AUTHORIZED");
    const newSelf = selfView(newAlicePin, fx.phone_replacement.new_device_seed);
    expect(toHex(openEpoch(newManifest, authorView(newAlicePin), newSelf, newWrap).epochKey)).toBe(fx.phone_replacement.new_epoch_key);
    // Bob opens the new epoch with his wrap under the new author certificate.
    const bobSelf = selfView(bobPin, str(fixture.inputs["bob_device_seed"] ?? ""));
    expect(toHex(openEpoch(newManifest, authorView(newAlicePin), bobSelf, hex(fx.phone_replacement.new_wraps[bob.identity_id] ?? "")).epochKey)).toBe(fx.phone_replacement.new_epoch_key);
  });

  it("the superseded manifest is refused for a live key once the author's new certificate is current, and opens as history with the archived one", () => {
    const old = hex(fixture.documents["manifest"]?.wire ?? "");
    const bobSelf = selfView(bobPin, str(fixture.inputs["bob_device_seed"] ?? ""));
    expect(code(() => openEpoch(old, authorView(newAlicePin), bobSelf, wrapFor(bob.identity_id)))).toBe("SUPERSEDED_DEVICE");
    const archived = openEpoch(old, authorView(newAlicePin, [alicePin]), bobSelf, wrapFor(bob.identity_id));
    expect(archived.superseded).toBe(true);
  });
});

describe("prepare, publish, promote (S01 to S06)", () => {
  function prep(desiredRevision: bigint, epoch: number): PreparedEpoch {
    const aud = resolveAudience(alicePin, [circleOf(alicePin)], new Map([[bob.identity_id, bobPin]]));
    const author = { identityId: alicePin.identityId, certificateHash: alicePin.certificateHash, streamId: alicePin.streamId, signingSecretKey: deviceSigningKeypair(hex(str(fixture.inputs["alice_device_seed"] ?? ""))).secretKey };
    return prepareEpoch({ author, epoch, createdAt: now, audience: aud, desiredRevision });
  }

  it("prepares the fixture manifest exactly when given the fixture key and wraps are reproducible per recipient", () => {
    const aud = resolveAudience(alicePin, [circleOf(alicePin)], new Map([[bob.identity_id, bobPin]]));
    const author = { identityId: alicePin.identityId, certificateHash: alicePin.certificateHash, streamId: alicePin.streamId, signingSecretKey: deviceSigningKeypair(hex(str(fixture.inputs["alice_device_seed"] ?? ""))).secretKey };
    const p = prepareEpoch({ author, epoch: 1, createdAt: now, audience: aud, desiredRevision: 1n, epochKey });
    // Sealed boxes use fresh ephemeral keys, so the wraps differ from the fixture's; everything else matches.
    const mine = expectType<import("../src/codec.js").EpochManifest>(verifyDocument(p.manifest, alicePin.signingKey), DocumentType.EpochManifest);
    const theirs = expectType<import("../src/codec.js").EpochManifest>(verifyDocument(hex(fixture.documents["manifest"]?.wire ?? ""), alicePin.signingKey), DocumentType.EpochManifest);
    expect(toHex(mine.keyCommitment)).toBe(toHex(theirs.keyCommitment));
    expect(mine.audience.map((r) => toHex(r.certificateHash))).toEqual(theirs.audience.map((r) => toHex(r.certificateHash)));
    for (const who of [alicePin, bobPin]) {
      const wrap = p.wraps.get(toHex(who.identityId));
      const self = selfView(who, who === alicePin ? str(fixture.inputs["alice_device_seed"] ?? "") : str(fixture.inputs["bob_device_seed"] ?? ""));
      expect(wrap && toHex(openEpoch(p.manifest, authorView(alicePin), self, wrap).epochKey)).toBe(toHex(epochKey));
    }
  });

  it("S01: a prepared epoch is retried with identical bytes; S02 to S06 follow the model", () => {
    // S01: the prepared bytes are what gets published, before and after a lost response.
    const prepared = prep(1n, 1);
    expect(resolvePublish(prepared, { status: "RETRYABLE" })).toBe("RETRY");
    expect(resolvePublish(prepared, { status: "CONFLICT", currentEpoch: 1, currentManifest: prepared.manifest })).toBe("COMMITTED");
    expect(resolvePublish(prepared, { status: "COMMITTED" })).toBe("COMMITTED");
    // S02: membership changed (desired revision 2) while epoch 1 was in flight: commits obsolete.
    expect(promote(prepared, 2n, prepared.audienceKey)).toBe("OBSOLETE");
    // S03: nothing may be sealed with an obsolete epoch; the client reports ROTATION_REQUIRED (tested in the outbox).
    // S04: the next epoch prepared under revision 2 promotes.
    const next = prep(2n, 2);
    expect(resolvePublish(next, { status: "COMMITTED" })).toBe("COMMITTED");
    expect(promote(next, 2n, next.audienceKey)).toBe("PROMOTED");
    // An audience change alone (same revision number but different certificate set) also makes it obsolete.
    expect(promote(next, 2n, next.audienceKey + ",x")).toBe("OBSOLETE");
    // S05 and S06 concern counters and the queue and live in the outbox tests.
  });

  it("a different valid body at the published epoch is EQUIVOCATION; a higher host epoch means the stream was lost", () => {
    const a = prep(1n, 1);
    const b = prep(1n, 1); // fresh key and wraps: a different valid body at the same slot
    expect(code(() => resolvePublish(a, { status: "CONFLICT", currentEpoch: 1, currentManifest: b.manifest }))).toBe("EQUIVOCATION");
    expect(code(() => resolvePublish(a, { status: "CONFLICT", currentEpoch: 7, currentManifest: undefined }))).toBe("RECOVERY_REQUIRED");
    expect(resolvePublish(prep(1n, 3), { status: "CONFLICT", currentEpoch: 1, currentManifest: a.manifest })).toBe("RETRY");
    expect(code(() => resolvePublish(a, { status: "UNAUTHORIZED" }))).toBe("NOT_AUTHORIZED");
  });

  it("rotation triggers: hygiene interval, clock reversal, counter exhaustion", () => {
    const day = 86_400_000n;
    const active = { createdAt: now, nextCounter: 0, lastSentAt: undefined };
    expect(rotationReason(active, now + day, 30n * day)).toBeUndefined();
    expect(rotationReason(active, now + 31n * day, 30n * day)).toBe("hygiene");
    expect(rotationReason({ ...active, lastSentAt: now + 10n }, now + 5n, 30n * day)).toBe("clockReversal");
    expect(rotationReason({ ...active, nextCounter: MAX_COUNTER }, now, 30n * day)).toBeUndefined();
    expect(rotationReason({ ...active, nextCounter: MAX_COUNTER + 1 }, now, 30n * day)).toBe("counterExhausted");
  });
});
