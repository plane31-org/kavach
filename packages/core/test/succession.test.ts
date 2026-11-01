/** The succession verifier against the fixture's ten cases and the deployment-model rules (revision 9). */
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { DocumentType, buildSuccession, expectType, parseDocument, type AccountDevice, type AccountSuccession } from "../src/codec.js";
import { identityId, ready, signingKeypairFromSeed } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { pinFromCertificate } from "../src/identity.js";
import { ResetTrust } from "../src/reset.js";
import { pinToRow } from "../src/rows.js";
import { MemoryStore } from "../src/store.js";
import { applySuccession, retiredIdentities } from "../src/succession.js";
import { testPolicy } from "../src/testing/clock.js";
import { fixture, hex, str } from "./fixture.js";

interface Extra {
  reset_key_management: { management_public: string; list_v1_wire: string; list_v2_wire: string };
  account_reset: { authority_seed: string };
  account_succession: {
    authority_public: string;
    account_id: string;
    successor_certificate: string;
    succession_wire: string;
    reattested_wire: string;
    forked_wire: string;
    other_certificate: string;
    back_to_a_wire: string;
    back_to_a_certificate: string;
    gap_wire: string;
    gap_certificate: string;
    cases: { name: string; expected: string }[];
  };
}
const fx = fixture as unknown as typeof fixture & Extra;
const v = fx.account_succession;
const now = BigInt(str(fixture.inputs["time_ms"] ?? "0"));
const alice = fixture.identities[0];
if (!alice) throw new Error("fixture");

beforeAll(() => ready());

/** A store where Alice is pinned at her enrollment certificate (generation 1), as a peer would have her. */
async function pinnedAlice(generation = 1n): Promise<{ store: MemoryStore; trust: ResetTrust }> {
  const store = new MemoryStore();
  const aliceCert = hex(fixture.documents["alice_account"]?.wire ?? "");
  const doc = expectType<AccountDevice>(parseDocument(aliceCert), DocumentType.AccountDevice);
  const pin = { ...pinFromCertificate(doc), generation };
  await store.transaction((tx) => {
    tx.put("pins", toHex(pin.identityId), { ...pinToRow(pin), accountId: toHex(pin.identityId) });
    tx.put("identities", toHex(pin.identityId), { accountId: toHex(pin.identityId), accountName: "alice", sinceGeneration: "1", retired: false });
    tx.put("certificates", toHex(pin.certificateHash), { identityId: toHex(pin.identityId), certificateHash: toHex(pin.certificateHash), signingKey: toHex(pin.signingKey), boxKey: toHex(pin.boxKey), streamId: toHex(pin.streamId), generation: generation.toString(), wire: toHex(aliceCert), current: true });
  });
  const trust = new ResetTrust({ managementKey: hex(fx.reset_key_management.management_public), minimumVersion: 1n });
  trust.install(hex(fx.reset_key_management.list_v1_wire), now);
  return { store, trust };
}

async function run(store: MemoryStore, trust: ResetTrust, wire: Uint8Array, cert: Uint8Array, at = now + 30_000n, policy = testPolicy): Promise<string> {
  try {
    return (await store.transaction((tx) => applySuccession(tx, { wire, newCertificate: cert, policy, trust, now: at }))).outcome;
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

describe("the succession verifier replays the fixture's cases", () => {
  it("C01 to C10 in the fixture's order, with the same outcomes", async () => {
    const expected = new Map(v.cases.map((c) => [c.name, c.expected]));
    const results = new Map<string, string>();
    const succ = hex(v.succession_wire);
    const successor = hex(v.successor_certificate);
    const { store, trust } = await pinnedAlice();
    results.set("C01_succession_accepted", await run(store, trust, succ, successor));
    results.set("C02_same_attestation_duplicate", await run(store, trust, succ, successor));
    results.set("C03_reattestation_is_the_same_succession", await run(store, trust, hex(v.reattested_wire), successor));
    results.set("C04_two_successors_for_one_state", await run(store, trust, hex(v.forked_wire), hex(v.other_certificate)));
    results.set("C05_back_to_a_retired_identity", await run(store, trust, hex(v.back_to_a_wire), hex(v.back_to_a_certificate)));
    const gapped = await pinnedAlice();
    results.set("C06_continuity_activations_between_successions", await run(gapped.store, gapped.trust, hex(v.gap_wire), hex(v.gap_certificate)));
    // C07: the current identity (after the gap succession) with a generation below the pinned one.
    const authority = signingKeypairFromSeed(hex(fx.account_reset.authority_seed));
    const gapDoc = expectType<AccountSuccession>(parseDocument(hex(v.gap_wire)), DocumentType.AccountSuccession);
    const other = expectType<AccountDevice>(parseDocument(hex(v.other_certificate)), DocumentType.AccountDevice);
    const low = buildSuccession({ accountName: "alice", accountId: gapDoc.accountId, previousIdentityId: gapDoc.newIdentityId, newIdentityId: identityId("alice", other.accountKey), previousGeneration: 3n, newGeneration: 4n, newCertificateHash: other.bodyHash, successionId: new Uint8Array(16).fill(9), issuedAt: now, authorityKeyId: gapDoc.authorityKeyId }, authority.secretKey);
    results.set("C07_rollback_below_pinned_generation", await run(gapped.store, gapped.trust, low, hex(v.other_certificate)));
    const wrongCert = await pinnedAlice();
    results.set("C08_certificate_binding", await run(wrongCert.store, wrongCert.trust, succ, hex(v.other_certificate)));
    const removed = await pinnedAlice();
    removed.trust.install(hex(fx.reset_key_management.list_v2_wire), now + 20_000n);
    results.set("C09_new_attestation_under_removed_key", await run(removed.store, removed.trust, succ, successor));
    const removedAfter = await pinnedAlice();
    await run(removedAfter.store, removedAfter.trust, succ, successor);
    removedAfter.trust.install(hex(fx.reset_key_management.list_v2_wire), now + 20_000n);
    results.set("C10_accepted_transition_recognised_after_key_removal", await run(removedAfter.store, removedAfter.trust, hex(v.reattested_wire), successor));
    for (const [name, exp] of expected) expect(`${name}=${results.get(name)}`).toBe(`${name}=${exp}`);
    expect(results.size).toBe(expected.size);
  });

  it("an accepted succession moves the pin, retires the previous identity, records the transition and writes the durable notice", async () => {
    const { store, trust } = await pinnedAlice();
    await run(store, trust, hex(v.succession_wire), hex(v.successor_certificate));
    const succ = expectType<AccountSuccession>(parseDocument(hex(v.succession_wire)), DocumentType.AccountSuccession);
    const after = await store.read((tx) => ({
      pin: tx.get("pins", v.account_id),
      previous: tx.get("identities", toHex(succ.previousIdentityId)),
      next: tx.get("identities", toHex(succ.newIdentityId)),
      successions: tx.list("successions", v.account_id + ":").length,
      notices: tx.list("keyChanges").map(([, r]) => [r.reason, r.generation, r.accountId]),
      retired: [...retiredIdentities(tx)],
      revision: tx.get("revision", "revision")?.desiredRevision
    }));
    expect([after.pin?.identityId, after.pin?.generation, after.pin?.accountId]).toEqual([toHex(succ.newIdentityId), "2", v.account_id]);
    expect([after.previous?.retired, after.next?.retired, after.next?.sinceGeneration]).toEqual([true, false, "2"]);
    expect([after.successions, after.notices, after.retired]).toEqual([1, [["succession", "2", v.account_id]], [toHex(succ.previousIdentityId)]]);
    expect(after.revision).toBe("2"); // T3 rotated the audience to the new key
  });

  it("an obsolete attestation of an accepted transition, under a removed key, is dropped and changes nothing", async () => {
    const { store, trust } = await pinnedAlice();
    await run(store, trust, hex(v.succession_wire), hex(v.successor_certificate));
    const before = await store.read((tx) => JSON.stringify([tx.get("pins", v.account_id), tx.list("identities"), tx.list("successions")]));
    trust.install(hex(fx.reset_key_management.list_v2_wire), now + 20_000n);
    expect(await run(store, trust, hex(v.succession_wire), hex(v.successor_certificate), now + 30_000n)).toBe("RESET_KEY_REVOKED");
    const after = await store.read((tx) => JSON.stringify([tx.get("pins", v.account_id), tx.list("identities"), tx.list("successions")]));
    expect(after).toBe(before);
  });

  it("a deployment on identity continuity rejects every succession, whoever signed it; no key list is needed to say so", async () => {
    const { store, trust } = await pinnedAlice();
    const continuity = { ...testPolicy, replacement: "continuity" as const };
    expect(await run(store, trust, hex(v.succession_wire), hex(v.successor_certificate), now + 30_000n, continuity)).toBe("UNSUPPORTED_TYPE");
    expect(await store.read((tx) => tx.get("pins", v.account_id)?.generation)).toBe("1");
    expect(await run(store, trust, hex(v.succession_wire), hex(v.successor_certificate), now + 30_000n, { ...testPolicy, replacement: "recovery" })).toBe("ACCEPTED");
  });

  it("an unseen succession without a fresh key list or a trusted clock is deferred, not refused", async () => {
    const { store, trust } = await pinnedAlice();
    expect(await run(store, trust, hex(v.succession_wire), hex(v.successor_certificate), now + 86_400_000n)).toBe("RESET_KEYS_REQUIRED");
    expect(await run(store, trust, hex(v.succession_wire), hex(v.successor_certificate), now - 1n)).toBe("RESET_CLOCK_UNTRUSTED");
  });
});
