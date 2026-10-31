import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.js";
import { ready, signingKeypairFromSeed } from "../src/crypto.js";
import { KavachError } from "../src/errors.js";
import { ResetTrust, emptyResetTrust } from "../src/reset.js";
import { fixture, hex, str } from "./fixture.js";

beforeAll(() => ready());

interface Extra {
  reset_key_management: {
    management_public: string;
    standby_public: string;
    list_v1_wire: string;
    list_v2_wire: string;
    empty_list_wire: string;
    reattested_receipt_wire: string;
    rejected_wires: Record<string, string>;
    cases: { name: string; expected: string }[];
  };
  account_reset: { authority_public: string; new_account_certificate: string; receipt_wire: string };
}
const fx = fixture as unknown as typeof fixture & Extra;
const rkm = fx.reset_key_management;
const alice = fixture.identities[0];
if (!alice) throw new Error("fixture");
const now = BigInt(str(fixture.inputs["time_ms"] ?? "0"));
const root = hex(rkm.management_public);
const kl1 = hex(rkm.list_v1_wire);
const kl2 = hex(rkm.list_v2_wire);
const kill = hex(rkm.empty_list_wire);
const receipt = hex(fx.account_reset.receipt_wire);
const newCert = hex(fx.account_reset.new_account_certificate);
const reissued = hex(rkm.reattested_receipt_wire);
const aliceIid = hex(alice.identity_id);
import * as cryptoMod from "../src/crypto.js";
import * as codecMod from "../src/codec.js";
const resetIid = (): Uint8Array => {
  const c = codecMod.expectType<codecMod.AccountDevice>(codecMod.verifyDocument(newCert), codecMod.DocumentType.AccountDevice);
  return cryptoMod.identityId(c.accountName, c.accountKey);
};

function run(fn: () => unknown): string {
  try {
    const r = fn();
    return typeof r === "string" ? r : typeof r === "object" && r !== null && "outcome" in r ? String((r as { outcome: string }).outcome) : "OK";
  } catch (e) {
    if (e instanceof KavachError) return e.code;
    throw e;
  }
}

describe("K01 to K22 against the fixture, with K19 at 30 days", () => {
  it("replays the 22 reset-key management cases in order", () => {
    const expected = new Map(rkm.cases.map((c) => [c.name, c.expected]));
    const results = new Map<string, string>();
    const trust = new ResetTrust({ managementKey: root, minimumVersion: 1n });
    results.set("K01_initial_list", run(() => trust.install(kl1, now)));
    results.set("K02_list_duplicate", run(() => trust.install(kl1, now)));
    results.set("K03_active_reset", run(() => trust.apply(receipt, newCert, "alice", aliceIid, now + 10_000n)));
    results.set("K04_remove_active_key", run(() => trust.install(kl2, now + 20_000n)));
    results.set("K05_list_rollback", run(() => trust.install(kl1, now + 20_000n)));
    results.set("K06_equal_version_conflict", run(() => trust.install(hex(rkm.rejected_wires["equal_version_conflict"] ?? ""), now + 20_000n)));
    const unseen = new ResetTrust({ managementKey: root, minimumVersion: 1n });
    unseen.install(kl2, now + 20_000n);
    results.set("K07_unseen_backdated_revoked_receipt", run(() => unseen.apply(receipt, newCert, "alice", aliceIid, now + 20_000n)));
    results.set("K08_previously_committed_reset_stays", run(() => trust.apply(receipt, newCert, "alice", resetIid(), now + 20_000n)));
    results.set("K09_current_key_reattests_old_event", run(() => unseen.apply(reissued, newCert, "alice", aliceIid, now + 20_000n)));
    results.set("K10_reattest_applied_event", run(() => trust.apply(reissued, newCert, "alice", resetIid(), now + 20_000n)));
    const fresh = new ResetTrust({ managementKey: root, minimumVersion: 1n });
    fresh.install(kl2, now + 20_000n);
    results.set("K11_expired_list_defers_reset", run(() => fresh.apply(reissued, newCert, "alice", aliceIid, now + 86_400_000n)));
    results.set("K12_unknown_clock", run(() => fresh.apply(reissued, newCert, "alice", aliceIid, undefined)));
    results.set("K13_clock_rollback", run(() => fresh.install(kl2, now + 19_999n)));
    results.set("K14_operational_key_cannot_manage", run(() => fresh.install(hex(rkm.rejected_wires["operational_self_signed"] ?? ""), now + 20_000n)));
    results.set("K15_missing_list", run(() => new ResetTrust({ managementKey: root, minimumVersion: 1n }).apply(receipt, newCert, "alice", aliceIid, now)));
    results.set("K16_packaged_minimum", run(() => new ResetTrust({ managementKey: root, minimumVersion: 2n }).install(kl1, now)));
    results.set("K17_empty_list", run(() => fresh.install(kill, now + 20_000n)));
    results.set("K18_all_resets_disabled", run(() => fresh.apply(reissued, newCert, "alice", aliceIid, now + 20_000n)));
    results.set("K19_lifetime_limit", run(() => fresh.install(hex(rkm.rejected_wires["excess_lifetime"] ?? ""), now + 20_000n)));
    results.set("K20_duplicate_keys", run(() => fresh.install(hex(rkm.rejected_wires["duplicate_keys"] ?? ""), now + 20_000n)));
    results.set("K21_root_is_not_operational", run(() => fresh.install(hex(rkm.rejected_wires["root_as_operational"] ?? ""), now + 20_000n)));
    results.set("K22_reset_id_binding", run(() => trust.apply(hex(rkm.rejected_wires["reset_binding_conflict"] ?? ""), newCert, "alice", resetIid(), now + 20_000n)));
    expect(results.size).toBe(22);
    for (const [name, exp] of expected) expect(`${name}=${results.get(name)}`).toBe(`${name}=${exp}`);
  });

  it("the receipt is signed by the authority the fixture names, and a 30-day list installs while a 31-day one does not", () => {
    const authority = hex(fx.account_reset.authority_public);
    expect(toHex(authority)).toBe(fx.account_reset.authority_public);
    const { buildResetKeyList, expectType, parseDocument, DocumentType } = codecMod;
    const management = signingKeypairFromSeed(hex((fixture as unknown as { reset_key_management: { management_seed: string } }).reset_key_management.management_seed));
    const base = expectType<codecMod.ResetKeyList>(parseDocument(kl1), DocumentType.ResetKeyList);
    const thirty = buildResetKeyList({ ...base, version: 9n, issuedAt: now, expiresAt: now + 2_592_000_000n }, management.secretKey);
    const trust = new ResetTrust({ managementKey: root, minimumVersion: 1n });
    expect(trust.install(thirty, now + 1n)).toBe("INSTALLED");
    expect(trust.fresh(now + 2_591_999_999n)).toBe(true);
    expect(trust.fresh(now + 2_592_000_000n)).toBe(false);
  });

  it("persists and restores its state through rows", () => {
    const trust = new ResetTrust({ managementKey: root, minimumVersion: 1n });
    trust.install(kl1, now);
    trust.apply(receipt, newCert, "alice", aliceIid, now + 10_000n);
    const rows = trust.toRows();
    const restored = ResetTrust.fromRows({ managementKey: root, minimumVersion: 1n }, rows);
    expect(restored.state.timeHighWater).toBe(now + 10_000n);
    expect(restored.state.retired.has(alice.identity_id)).toBe(true);
    expect(run(() => restored.apply(receipt, newCert, "alice", resetIid(), now + 10_000n))).toBe("DUPLICATE");
    expect(run(() => restored.install(kl1, now + 9_999n))).toBe("RESET_CLOCK_UNTRUSTED");
    expect(new ResetTrust({ managementKey: root, minimumVersion: 1n }, emptyResetTrust).fresh(now)).toBe(false);
  });
});
