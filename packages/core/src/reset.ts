/**
 * Last-resort account reset and the reset keys (protocol section 12).
 *
 * `ResetTrust` is the acceptance model for management-signed key lists (type 8) and reset
 * receipts (type 7): version rules, the 30-day lifetime, the trusted-clock rules with a durable
 * time high-water mark, revocation by list, and immutable reset bindings. It is pure state with
 * row conversions; the client persists it in T9. Nothing here pauses sharing.
 */
import { equalBytes, fromHex, toHex } from "./bytes.js";
import {
  DocumentType,
  expectType,
  parseDocument,
  verifyDocument,
  type AccountDevice,
  type AccountResetReceipt,
  type Parsed,
  type ResetKeyList
} from "./codec.js";
import { H, identityId } from "./crypto.js";
import { KavachError } from "./errors.js";
import { big, unbig } from "./rows.js";

export interface ResetTrustConfig {
  /** The deployment's pinned management public key. */
  readonly managementKey: Uint8Array;
  /** The packaged minimum list version. */
  readonly minimumVersion: bigint;
}

export interface ResetBinding {
  readonly accountName: string;
  readonly oldIdentityId: string;
  readonly newIdentityId: string;
}

export interface ResetTrustState {
  readonly current: { wire: Uint8Array; list: Parsed<ResetKeyList> } | undefined;
  /** The greatest trusted time seen: a durable high-water mark. */
  readonly timeHighWater: bigint;
  readonly acceptedReceipts: ReadonlySet<string>;
  readonly events: ReadonlyMap<string, ResetBinding>;
  readonly retired: ReadonlySet<string>;
}

export const emptyResetTrust: ResetTrustState = { current: undefined, timeHighWater: 0n, acceptedReceipts: new Set(), events: new Map(), retired: new Set() };

export type InstallOutcome = "INSTALLED" | "DUPLICATE";
export type ApplyOutcome = "ACCOUNT_KEY_CHANGED" | "DUPLICATE";

/** A peer's view of an accepted reset: who to stop sharing with, and whose circles close. */
export interface ResetEffect {
  readonly outcome: ApplyOutcome;
  readonly oldIdentityId: Uint8Array;
  readonly newIdentityId: Uint8Array;
  readonly receipt: Parsed<AccountResetReceipt>;
}

export class ResetTrust {
  constructor(
    readonly config: ResetTrustConfig,
    public state: ResetTrustState = emptyResetTrust
  ) {}

  /** The platform clock under the accurate-clock assumption, checked against the high-water mark. */
  private clock(now: bigint | undefined, stage: string): bigint {
    if (now === undefined || now < this.state.timeHighWater) throw new KavachError("RESET_CLOCK_UNTRUSTED", stage);
    return now;
  }

  /** Is the current list usable at `now`? */
  fresh(now: bigint): boolean {
    const c = this.state.current;
    return !!c && c.list.issuedAt <= now && now < c.list.expiresAt;
  }

  /**
   * Install a key list: verified under the pinned management key, version at least the packaged
   * minimum and the durable highest, equal version only with an equal body, fresh at `now`.
   */
  install(wire: Uint8Array, now: bigint | undefined): InstallOutcome {
    const stage = "resetKeyList";
    const list = expectType<ResetKeyList>(verifyDocument(wire, this.config.managementKey), DocumentType.ResetKeyList, stage);
    if (list.keys.some((k) => equalBytes(k.publicKey, this.config.managementKey))) {
      throw new KavachError("INVALID_KEY", stage, "the management key cannot be an operational key");
    }
    const current = this.state.current;
    if (list.version < this.config.minimumVersion || (current && list.version < current.list.version)) throw new KavachError("ROLLBACK", stage);
    if (current && list.version === current.list.version && !equalBytes(list.bodyHash, current.list.bodyHash)) {
      throw new KavachError("EQUIVOCATION", stage, "two key lists at one version");
    }
    const t = this.clock(now, stage);
    if (!(list.issuedAt <= t && t < list.expiresAt)) throw new KavachError("RESET_KEYS_REQUIRED", stage, "list not fresh");
    const outcome: InstallOutcome = current && list.version === current.list.version ? "DUPLICATE" : "INSTALLED";
    this.state = { ...this.state, current: { wire, list }, timeHighWater: t };
    return outcome;
  }

  /**
   * Apply a reset receipt for an account whose current pinned identity is `currentIdentityId`.
   * Requires a fresh list, an allowed signer, a verified new certificate and consistent bindings.
   */
  apply(receiptWire: Uint8Array, newCertificate: Uint8Array, accountName: string, currentIdentityId: Uint8Array, now: bigint | undefined): ResetEffect {
    const stage = "resetReceipt";
    const parsed = expectType<AccountResetReceipt>(parseDocument(receiptWire), DocumentType.AccountResetReceipt, stage);
    const receiptHash = toHex(H(receiptWire));
    if (this.state.acceptedReceipts.has(receiptHash)) {
      return { outcome: "DUPLICATE", oldIdentityId: parsed.oldIdentityId, newIdentityId: parsed.newIdentityId, receipt: parsed };
    }
    const t = this.clock(now, stage);
    if (!this.fresh(t)) throw new KavachError("RESET_KEYS_REQUIRED", stage, "no fresh key list");
    const current = this.state.current;
    if (!current) throw new KavachError("RESET_KEYS_REQUIRED", stage);
    const signer = current.list.keys.find((k) => equalBytes(k.keyId, parsed.authorityKeyId));
    if (!signer) throw new KavachError("RESET_KEY_REVOKED", stage, "the signing key is not in the current list");
    const receipt = expectType<AccountResetReceipt>(verifyDocument(receiptWire, signer.publicKey), DocumentType.AccountResetReceipt, stage);
    const cert = expectType<AccountDevice>(verifyDocument(newCertificate), DocumentType.AccountDevice, stage);
    const binding: ResetBinding = { accountName: receipt.accountName, oldIdentityId: toHex(receipt.oldIdentityId), newIdentityId: toHex(receipt.newIdentityId) };
    if (receipt.accountName !== accountName || cert.accountName !== accountName || !equalBytes(identityId(accountName, cert.accountKey), receipt.newIdentityId)) {
      throw new KavachError("RESET_BINDING", stage, "receipt, account and certificate do not bind");
    }
    const resetId = toHex(receipt.resetId);
    const known = this.state.events.get(resetId);
    let outcome: ApplyOutcome;
    if (known) {
      if (known.accountName !== binding.accountName || known.oldIdentityId !== binding.oldIdentityId || known.newIdentityId !== binding.newIdentityId) {
        throw new KavachError("RESET_BINDING", stage, "a conflicting binding for a known reset id");
      }
      outcome = "DUPLICATE";
    } else {
      if (!equalBytes(receipt.oldIdentityId, currentIdentityId) || this.state.retired.has(binding.newIdentityId)) {
        throw new KavachError("RESET_BINDING", stage, "old identity is not the current pin, or the new one is retired");
      }
      outcome = "ACCOUNT_KEY_CHANGED";
    }
    const accepted = new Set(this.state.acceptedReceipts);
    accepted.add(receiptHash);
    const events = new Map(this.state.events);
    events.set(resetId, binding);
    const retired = new Set(this.state.retired);
    retired.add(binding.oldIdentityId);
    this.state = { ...this.state, acceptedReceipts: accepted, events, retired, timeHighWater: t };
    return { outcome, oldIdentityId: receipt.oldIdentityId, newIdentityId: receipt.newIdentityId, receipt };
  }

  // Persistence ----------------------------------------------------------------------------------

  toRows(): ResetTrustRows {
    return {
      list: this.state.current ? { wire: toHex(this.state.current.wire), version: big(this.state.current.list.version), hash: toHex(this.state.current.list.bodyHash), checkedAt: big(this.state.timeHighWater) } : undefined,
      clock: { highWater: big(this.state.timeHighWater) },
      accepted: [...this.state.acceptedReceipts],
      events: [...this.state.events.entries()].map(([resetId, b]) => ({ resetId, ...b })),
      retired: [...this.state.retired]
    };
  }

  static fromRows(config: ResetTrustConfig, rows: ResetTrustRows): ResetTrust {
    const current = rows.list ? { wire: fromHex(rows.list.wire), list: expectType<ResetKeyList>(parseDocument(fromHex(rows.list.wire)), DocumentType.ResetKeyList) } : undefined;
    return new ResetTrust(config, {
      current,
      timeHighWater: unbig(rows.clock.highWater),
      acceptedReceipts: new Set(rows.accepted),
      events: new Map(rows.events.map((e) => [e.resetId, { accountName: e.accountName, oldIdentityId: e.oldIdentityId, newIdentityId: e.newIdentityId }])),
      retired: new Set(rows.retired)
    });
  }
}

export interface ResetTrustRows {
  list: { wire: string; version: string; hash: string; checkedAt: string } | undefined;
  clock: { highWater: string };
  accepted: string[];
  events: { resetId: string; accountName: string; oldIdentityId: string; newIdentityId: string }[];
  retired: string[];
}
