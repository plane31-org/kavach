import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { DocumentType, expectType, parseDocument, verifyDocument, type CircleSnapshot } from "../src/codec.js";
import { accountKeypair, identityId, ready } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { acceptSnapshot, checkMemberResolution, createCircleSnapshot, newCircleId, pinCircle, successorSnapshot, type CircleState } from "../src/circle.js";
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
  boundary_100: { snapshot_wire: string };
  phone_replacement: { next_owner_snapshot: string; same_circle_snapshot: string };
}
const fx = fixture as unknown as typeof fixture & Extra;
const alice = fixture.identities[0];
const bob = fixture.identities[1];
if (!alice || !bob) throw new Error("fixture");
const circleId = hex(str(fixture.inputs["circle_id"] ?? ""));
const snapshot1 = hex(fixture.documents["snapshot"]?.wire ?? "");
const now = 1_700_000_000_000n;

describe("accepting snapshots (S07 to S10)", () => {
  it("S07: a new revision is accepted and membership comes from the snapshot", () => {
    const ak = hex(alice.account_public);
    const bobView = pinCircle(circleId, hex(alice.identity_id), true, "requested");
    const r = acceptSnapshot(bobView, snapshot1, ak, hex(bob.identity_id), now);
    expect(r.outcome).toBe("ACCEPTED");
    if (r.outcome !== "ACCEPTED") return;
    expect(r.state.status).toBe("member");
    expect(r.state.revision).toBe(1n);
    expect(r.state.verifiedAt).toBe(now);
    // A stranger sees the same snapshot and stays waiting.
    const stranger = acceptSnapshot(bobView, snapshot1, ak, new Uint8Array(32).fill(7), now);
    expect(stranger.outcome === "ACCEPTED" && stranger.state.status).toBe("requested");
  });

  it("S08 to S10: rollback, duplicate and equivocation", () => {
    const ak = hex(alice.account_public);
    let state: CircleState = pinCircle(circleId, hex(alice.identity_id), true, "requested");
    const two = acceptSnapshot(state, hex(fx.phone_replacement.next_owner_snapshot), ak, hex(bob.identity_id), now);
    if (two.outcome !== "ACCEPTED") throw new Error("rev2");
    state = two.state;
    expect(state.revision).toBe(2n);
    expect(code(() => acceptSnapshot(state, snapshot1, ak, hex(bob.identity_id), now))).toBe("ROLLBACK");
    expect(acceptSnapshot(state, hex(fx.phone_replacement.next_owner_snapshot), ak, hex(bob.identity_id), now).outcome).toBe("DUPLICATE");
    // The 100-member boundary snapshot is also revision 2 of the same circle by the same owner.
    expect(code(() => acceptSnapshot(state, hex(fx.boundary_100.snapshot_wire), ak, hex(bob.identity_id), now))).toBe("EQUIVOCATION");
    // Wrong owner key, wrong circle.
    expect(code(() => acceptSnapshot(state, hex(fx.boundary_100.snapshot_wire), hex(bob.account_public), hex(bob.identity_id), now))).toBe("BAD_SIGNATURE");
    const otherCircle = pinCircle(newCircleId(), hex(alice.identity_id), true);
    expect(code(() => acceptSnapshot(otherCircle, snapshot1, ak, hex(bob.identity_id), now))).toBe("MALFORMED");
  });

  it("a higher snapshot may skip revisions, and removal or closure is read from it", () => {
    const ak = hex(alice.account_public);
    const bobView = acceptSnapshot(pinCircle(circleId, hex(alice.identity_id), true), snapshot1, ak, hex(bob.identity_id), now);
    if (bobView.outcome !== "ACCEPTED") throw new Error("rev1");
    const owner = { identityId: hex(alice.identity_id), accountSecretKey: accountKeypair(hex(str(fixture.inputs["alice_account_seed"] ?? ""))).secretKey };
    const removed = successorSnapshot({ ...bobView.state, revision: 6n }, { remove: hex(bob.identity_id) }, owner);
    if (!removed) throw new Error("no successor");
    const after = acceptSnapshot(bobView.state, removed, ak, hex(bob.identity_id), now + 1n);
    expect(after.outcome === "ACCEPTED" && after.state.status).toBe("left");
    expect(after.outcome === "ACCEPTED" && after.state.revision).toBe(7n);
    // A closure is an owner-only snapshot; to a member it reads exactly like a removal.
    const three = { ...bobView.state, members: [...bobView.state.members, new Uint8Array(32).fill(9)].sort((a, b) => toHex(a).localeCompare(toHex(b))) };
    const closed = successorSnapshot(three, { close: true }, owner);
    if (!closed) throw new Error("no closure");
    const seen = acceptSnapshot(bobView.state, closed, ak, hex(bob.identity_id), now + 2n);
    expect(seen.outcome === "ACCEPTED" && seen.state.status).toBe("left");
  });

  it("a quarantined circle stays quarantined", () => {
    const ak = hex(alice.account_public);
    const q = { ...pinCircle(circleId, hex(alice.identity_id), true), status: "quarantined" as const };
    const r = acceptSnapshot(q, snapshot1, ak, hex(bob.identity_id), now);
    expect(r.outcome === "ACCEPTED" && r.state.status).toBe("quarantined");
  });
});

describe("owner side", () => {
  const aliceSecret = accountKeypair(hex(str(fixture.inputs["alice_account_seed"] ?? ""))).secretKey;
  const owner = { identityId: hex(alice.identity_id), accountSecretKey: aliceSecret };

  it("creates revision 1 with the owner alone and admits Bob to reproduce the fixture snapshot", () => {
    const genesis = createCircleSnapshot(owner, circleId);
    const parsed = expectType<CircleSnapshot>(verifyDocument(genesis, hex(alice.account_public)), DocumentType.CircleSnapshot);
    expect(parsed.revision).toBe(1n);
    expect(parsed.members.map(toHex)).toEqual([alice.identity_id]);
    // The fixture's revision 1 already has Bob: build it from a zero-revision state with the admit change.
    const empty: CircleState = { ...pinCircle(circleId, hex(alice.identity_id), true, "member"), members: [hex(alice.identity_id)] };
    const admitted = successorSnapshot(empty, { admit: hex(bob.identity_id) }, owner);
    expect(admitted && toHex(admitted)).toBe(fixture.documents["snapshot"]?.wire);
  });

  it("approval of an admitted account is idempotent and the revision never resets on a device change", () => {
    const state = acceptSnapshot(pinCircle(circleId, hex(alice.identity_id), true, "member"), snapshot1, hex(alice.account_public), hex(alice.identity_id), now);
    if (state.outcome !== "ACCEPTED") throw new Error("rev1");
    expect(successorSnapshot(state.state, { admit: hex(bob.identity_id) }, owner)).toBeUndefined();
    expect(successorSnapshot(state.state, { remove: new Uint8Array(32).fill(3) }, owner)).toBeUndefined();
    // The owner's new phone signs revision 2 over the same members: exactly the fixture's continued snapshot.
    const continued = successorSnapshot(state.state, { admit: hex(bob.identity_id) }, owner);
    expect(continued).toBeUndefined();
    const samePhoneOrNew = parseDocument(hex(fx.phone_replacement.next_owner_snapshot));
    expect(samePhoneOrNew.type === DocumentType.CircleSnapshot && samePhoneOrNew.revision).toBe(2n);
    expect(toHex(hex(fx.phone_replacement.same_circle_snapshot))).toBe(fixture.documents["snapshot"]?.wire);
  });

  it("only the owner signs, the owner cannot leave, and a closed circle takes no change", () => {
    const state = acceptSnapshot(pinCircle(circleId, hex(alice.identity_id), true, "member"), snapshot1, hex(alice.account_public), hex(alice.identity_id), now);
    if (state.outcome !== "ACCEPTED") throw new Error("rev1");
    const bobKeys = { identityId: hex(bob.identity_id), accountSecretKey: accountKeypair(hex(str(fixture.inputs["bob_account_seed"] ?? ""))).secretKey };
    expect(code(() => successorSnapshot(state.state, { admit: new Uint8Array(32).fill(1) }, bobKeys))).toBe("NOT_AUTHORIZED");
    expect(code(() => successorSnapshot(state.state, { remove: hex(alice.identity_id) }, owner))).toBe("NOT_AUTHORIZED");
    expect(code(() => successorSnapshot({ ...state.state, status: "closed" }, { admit: new Uint8Array(32).fill(1) }, owner))).toBe("NOT_AUTHORIZED");
    const closing = successorSnapshot(state.state, { close: true }, owner);
    const parsed = closing && expectType<CircleSnapshot>(verifyDocument(closing, hex(alice.account_public)), DocumentType.CircleSnapshot);
    expect(parsed && parsed.members.length).toBe(1);
  });

  it("rejects two account keys for one account name among resolved members", () => {
    const resolved = new Map<string, { accountName: string; accountKey: Uint8Array }>();
    resolved.set(alice.identity_id, { accountName: "alice", accountKey: hex(alice.account_public) });
    resolved.set(bob.identity_id, { accountName: "bob", accountKey: hex(bob.account_public) });
    expect(code(() => checkMemberResolution(resolved))).toBe("ACCEPTED");
    const impostorKey = hex(bob.account_public);
    resolved.set(toHex(identityId("alice", impostorKey)), { accountName: "alice", accountKey: impostorKey });
    expect(code(() => checkMemberResolution(resolved))).toBe("EQUIVOCATION");
  });
});
