/**
 * Account succession (protocol section 4, revision 9; amendment A1): the host's authority binds
 * an account to new keys with continuity of its relationships. This module is the verifier a
 * peer runs on a type 9 document and the chain it keeps per account, in the order the
 * specification gives: an accepted transition stays trusted; a received document is
 * authenticated under the current key list; its transition is compared with the recorded ones;
 * only a new transition meets the pin, generation, retirement and certificate checks.
 */
import { equalBytes, toHex } from "./bytes.js";
import { DocumentType, expectType, parseDocument, verifyDocument, type AccountDevice, type AccountSuccession, type Parsed } from "./codec.js";
import { identityId } from "./crypto.js";
import { KavachError } from "./errors.js";
import { pinFromCertificate, type AccountPin } from "./identity.js";
import { acceptsSuccession, type RetentionPolicy } from "./policy.js";
import type { ResetTrust } from "./reset.js";
import { big, pinToRow, rowToPin, unbig } from "./rows.js";
import { t3ApplyChange } from "./transactions.js";
import type { KeyChangeRow, SuccessionRow, Tx } from "./store.js";

/** The immutable part of a succession: what happened to the account. Two documents with one transition are one succession. */
export interface SuccessionTransition {
  readonly accountName: string;
  readonly accountId: string;
  readonly successionId: string;
  readonly previousIdentityId: string;
  readonly newIdentityId: string;
  readonly previousGeneration: bigint;
  readonly newGeneration: bigint;
  readonly newCertificateHash: string;
}

export function transitionOf(doc: AccountSuccession): SuccessionTransition {
  return {
    accountName: doc.accountName,
    accountId: toHex(doc.accountId),
    successionId: toHex(doc.successionId),
    previousIdentityId: toHex(doc.previousIdentityId),
    newIdentityId: toHex(doc.newIdentityId),
    previousGeneration: doc.previousGeneration,
    newGeneration: doc.newGeneration,
    newCertificateHash: toHex(doc.newCertificateHash)
  };
}

export function sameTransition(a: SuccessionTransition, b: SuccessionTransition): boolean {
  return (
    a.accountName === b.accountName &&
    a.accountId === b.accountId &&
    a.successionId === b.successionId &&
    a.previousIdentityId === b.previousIdentityId &&
    a.newIdentityId === b.newIdentityId &&
    a.previousGeneration === b.previousGeneration &&
    a.newGeneration === b.newGeneration &&
    a.newCertificateHash === b.newCertificateHash
  );
}

function rowTransition(r: SuccessionRow): SuccessionTransition {
  return { accountName: r.accountName, accountId: r.accountId, successionId: r.successionId, previousIdentityId: r.previousIdentityId, newIdentityId: r.newIdentityId, previousGeneration: unbig(r.previousGeneration), newGeneration: unbig(r.newGeneration), newCertificateHash: r.newCertificateHash };
}

export function successionKey(accountId: string, previousGeneration: bigint): string {
  return `${accountId}:${previousGeneration.toString().padStart(20, "0")}`;
}

/**
 * The state a chain is validated against, the same for a pinned contact, a first contact and a
 * restoring device: where the account stands and what it has used up. Advancing it is pure, so
 * the state after a verified prefix is recomputed from the prefix and never persisted separately.
 */
export interface ChainState {
  readonly accountId: string;
  readonly accountName: string;
  /** The identity a transition must leave from. */
  readonly identityId: string;
  /** The generation a transition may not fall below (0 at a root nobody has pinned). */
  readonly generation: bigint;
  /** Identities no transition may leave from or arrive at: retired by successions or by resets. */
  readonly retired: ReadonlySet<string>;
  /** Device ids the account has used, hex. */
  readonly deviceIds: ReadonlySet<string>;
}

/** The state of an account nobody has pinned yet: its root, with what the reset trust already retired. */
export function rootState(accountId: Uint8Array, accountName: string, trust: ResetTrust): ChainState {
  return { accountId: toHex(accountId), accountName, identityId: toHex(accountId), generation: 0n, retired: new Set(trust.state.retired), deviceIds: new Set() };
}

/** The state at a pin: its current identity and generation, the identities this store retired, and its device ids. */
export function pinnedState(tx: Pick<Tx, "get" | "list">, pin: AccountPin, trust: ResetTrust): ChainState {
  const accountId = toHex(pin.accountId);
  const retired = new Set(trust.state.retired);
  for (const [k, r] of tx.list("identities")) if (r.accountId === accountId && r.retired) retired.add(k);
  return { accountId, accountName: pin.accountName, identityId: toHex(pin.identityId), generation: pin.generation, retired, deviceIds: new Set(pin.deviceIds.map(toHex)) };
}

/**
 * The transition rules (section 4, order four), applied to one parsed succession and the
 * certificate served with it against a state. Throws the protocol code; returns the next state.
 * Authentication (order two) and the comparison with recorded transitions (orders one and three)
 * are the caller's, since only a store knows what it recorded.
 */
export function validateTransition(doc: AccountSuccession, certificate: Uint8Array, state: ChainState): { next: ChainState; cert: Parsed<AccountDevice> } {
  const stage = "succession";
  const t = transitionOf(doc);
  if (t.accountName !== state.accountName || t.accountId !== state.accountId) throw new KavachError("SUCCESSION_BINDING", stage, "account name or id does not match");
  if (t.previousIdentityId !== state.identityId) throw new KavachError("SUCCESSION_BINDING", stage, "previous identity is not the account's current identity");
  if (t.previousGeneration < state.generation) throw new KavachError("ROLLBACK", stage, "previous generation below the current one");
  if (state.retired.has(t.previousIdentityId) || state.retired.has(t.newIdentityId)) throw new KavachError("SUPERSEDED_IDENTITY", stage, "a retired identity cannot be previous or new");
  const cert = expectType<AccountDevice>(verifyDocument(certificate), DocumentType.AccountDevice, stage);
  if (toHex(cert.bodyHash) !== t.newCertificateHash || cert.accountName !== t.accountName || cert.generation !== t.newGeneration || toHex(identityId(cert.accountName, cert.accountKey)) !== t.newIdentityId) {
    throw new KavachError("SUCCESSION_BINDING", stage, "the certificate does not bind to the succession");
  }
  if (state.deviceIds.has(toHex(cert.deviceId))) throw new KavachError("DEVICE_ID_REUSED", stage);
  const retired = new Set(state.retired);
  retired.add(t.previousIdentityId);
  const deviceIds = new Set(state.deviceIds);
  deviceIds.add(toHex(cert.deviceId));
  return { next: { ...state, identityId: t.newIdentityId, generation: t.newGeneration, retired, deviceIds }, cert };
}

/** Authenticate an attestation under the current list (order two). Returns the verified document. */
export function authenticateSuccession(wire: Uint8Array, trust: ResetTrust, now: bigint | undefined): AccountSuccession {
  const stage = "succession";
  const parsed = expectType<AccountSuccession>(parseDocument(wire), DocumentType.AccountSuccession, stage);
  if (now === undefined || now < trust.state.timeHighWater) throw new KavachError("RESET_CLOCK_UNTRUSTED", stage);
  const list = trust.state.current;
  if (!list || !trust.fresh(now)) throw new KavachError("RESET_KEYS_REQUIRED", stage, "no fresh key list");
  const signer = list.list.keys.find((k) => equalBytes(k.keyId, parsed.authorityKeyId));
  if (!signer) throw new KavachError("RESET_KEY_REVOKED", stage, "the signing key is not in the current list");
  return expectType<AccountSuccession>(verifyDocument(wire, signer.publicKey), DocumentType.AccountSuccession, stage);
}

export interface SuccessionEffect {
  readonly outcome: "ACCEPTED" | "DUPLICATE";
  readonly accountId: Uint8Array;
  readonly accountName: string;
  readonly previousIdentityId: Uint8Array;
  readonly newIdentityId: Uint8Array;
  readonly generation: bigint;
  readonly transition: SuccessionTransition;
  /** The pin after the succession (the new one, or the current one for a duplicate). */
  readonly pin: AccountPin;
}

export interface SuccessionInput {
  readonly wire: Uint8Array;
  /** The successor's certificate, fetched by `newCertificateHash`. */
  readonly newCertificate: Uint8Array;
  readonly policy: RetentionPolicy;
  readonly trust: ResetTrust;
  /** The trusted clock reading, or `undefined` when the clock cannot be trusted. */
  readonly now: bigint | undefined;
}

/** The account id an identity belongs to, as the chain knows it; an identity with no row is its own account (a root never succeeded, or one pinned before revision 9). */
export function accountIdOf(tx: Pick<Tx, "get">, identityHex: string): string {
  return tx.get("identities", identityHex)?.accountId ?? identityHex;
}

/** Every identity retired by a succession or a reset, as hex. */
export function retiredIdentities(tx: Pick<Tx, "list">): Set<string> {
  return new Set(tx.list("identities").filter(([, r]) => r.retired).map(([k]) => k));
}

/**
 * Apply one succession document inside the caller's transaction. Returns the effect for an
 * accepted or duplicate document; throws the protocol code for anything else, having written
 * nothing (an equivocation is recorded by the caller's quarantine).
 */
export interface VerifiedLink {
  readonly doc: AccountSuccession;
  readonly wire: Uint8Array;
  readonly certificate: Uint8Array;
}

/**
 * Verify links in order from a state, with the same rules a pinned contact applies: each
 * attested under the current list, each transition valid against the state the previous one
 * produced. Nothing is written; the caller records the links once the chain is complete.
 */
export function verifyChain(links: readonly { wire: Uint8Array; certificate: Uint8Array }[], input: { state: ChainState; trust: ResetTrust; now: bigint }): { links: VerifiedLink[]; state: ChainState } {
  const out: VerifiedLink[] = [];
  let state = input.state;
  for (const link of links) {
    const doc = authenticateSuccession(link.wire, input.trust, input.now);
    state = validateTransition(doc, link.certificate, state).next;
    out.push({ doc, wire: link.wire, certificate: link.certificate });
  }
  return { links: out, state };
}

/** Keep a verified chain as evidence: succession rows, identity rows (retired ones with the keys the chain shows) and key-change rows. */
export function recordChainIn(tx: Tx, chain: readonly VerifiedLink[], now: bigint): void {
  for (const { doc, wire, certificate } of chain) {
    const t = transitionOf(doc);
    const cert = expectType<AccountDevice>(parseDocument(certificate), DocumentType.AccountDevice, "chain");
    const row: SuccessionRow = { accountId: t.accountId, accountName: t.accountName, successionId: t.successionId, previousIdentityId: t.previousIdentityId, newIdentityId: t.newIdentityId, previousGeneration: big(t.previousGeneration), newGeneration: big(t.newGeneration), newCertificateHash: t.newCertificateHash, authorityKeyId: toHex(doc.authorityKeyId), wire: toHex(wire), acceptedAt: big(now) };
    tx.put("successions", successionKey(t.accountId, t.previousGeneration), row);
    const prev = tx.get("identities", t.previousIdentityId);
    tx.put("identities", t.previousIdentityId, { accountId: t.accountId, accountName: t.accountName, ...(prev?.accountKey ? { accountKey: prev.accountKey } : {}), sinceGeneration: prev?.sinceGeneration ?? big(1n), retired: true });
    const next = tx.get("identities", t.newIdentityId);
    tx.put("identities", t.newIdentityId, { accountId: t.accountId, accountName: t.accountName, accountKey: toHex(cert.accountKey), sinceGeneration: big(t.newGeneration), retired: next?.retired ?? false });
  }
}

/** The root identity's row with its key, from a certificate under the root key the host served, when it is one. */
export function rootIdentityIn(tx: Tx, accountId: Uint8Array, accountName: string, rootCertificate: Uint8Array | undefined): void {
  if (!rootCertificate) return;
  let cert: AccountDevice & { bodyHash: Uint8Array };
  try {
    cert = expectType<AccountDevice>(verifyDocument(rootCertificate), DocumentType.AccountDevice, "chain");
  } catch {
    return;
  }
  if (cert.accountName !== accountName || !equalBytes(identityId(cert.accountName, cert.accountKey), accountId)) return;
  const key = toHex(accountId);
  const row = tx.get("identities", key);
  tx.put("identities", key, { accountId: key, accountName, accountKey: toHex(cert.accountKey), sinceGeneration: row?.sinceGeneration ?? big(1n), retired: row?.retired ?? true, ...(row?.resetAt !== undefined ? { resetAt: row.resetAt } : {}) });
}

export function applySuccession(tx: Tx, input: SuccessionInput): SuccessionEffect {
  const stage = "succession";
  if (!acceptsSuccession(input.policy)) throw new KavachError("UNSUPPORTED_TYPE", stage, "this deployment does not accept successions");
  const parsed = expectType<AccountSuccession>(parseDocument(input.wire), DocumentType.AccountSuccession, stage);
  const t = transitionOf(parsed);

  // Order 1: authenticate the attestation under the current list. A failure here records nothing
  // and changes nothing, so an obsolete attestation of an accepted transition is merely dropped.
  const now = input.now;
  authenticateSuccession(input.wire, input.trust, now);
  if (now === undefined) throw new KavachError("RESET_CLOCK_UNTRUSTED", stage);

  // Order 2: compare the transition with the recorded ones for this account.
  const recorded = tx.list("successions", t.accountId + ":").map(([, r]) => r);
  const atState = recorded.find((r) => unbig(r.previousGeneration) === t.previousGeneration && r.previousIdentityId === t.previousIdentityId);
  const byId = recorded.find((r) => r.successionId === t.successionId);
  const pinRow = tx.get("pins", t.accountId);
  if (atState) {
    if (sameTransition(rowTransition(atState), t)) {
      if (!pinRow) throw new KavachError("STORAGE_FAILURE", stage, "a recorded succession without its pin");
      return { outcome: "DUPLICATE", accountId: parsed.accountId, accountName: t.accountName, previousIdentityId: parsed.previousIdentityId, newIdentityId: parsed.newIdentityId, generation: t.newGeneration, transition: t, pin: rowToPin(pinRow) };
    }
    throw new KavachError("EQUIVOCATION", stage, "two successors for one account state");
  }
  if (byId && !sameTransition(rowTransition(byId), t)) throw new KavachError("EQUIVOCATION", stage, "a known succession id with a different transition");

  // Order 3: a new transition against the pinned state, with the one validator every path uses.
  if (!pinRow) throw new KavachError("SUCCESSION_BINDING", stage, "no pin for the account");
  const pin = rowToPin(pinRow);
  const { cert } = validateTransition(parsed, input.newCertificate, pinnedState(tx, pin, input.trust));

  // Accept, all in this transaction: the pin, the certificates, the identities, the transition,
  // the durable notice, and the rotation (T3) that moves the audience to the new key.
  const next = pinFromCertificate(cert, pin);
  tx.put("pins", t.accountId, pinToRow(next));
  const previousCert = tx.get("certificates", toHex(pin.certificateHash));
  if (previousCert) tx.put("certificates", toHex(pin.certificateHash), { ...previousCert, current: false });
  tx.put("certificates", t.newCertificateHash, { identityId: t.accountId, certificateHash: t.newCertificateHash, signingKey: toHex(next.signingKey), boxKey: toHex(next.boxKey), streamId: toHex(next.streamId), generation: big(next.generation), wire: toHex(input.newCertificate), current: true });
  const previousIdentity = tx.get("identities", t.previousIdentityId);
  tx.put("identities", t.previousIdentityId, { accountId: t.accountId, accountName: t.accountName, accountKey: previousIdentity?.accountKey ?? toHex(pin.accountKey), sinceGeneration: previousIdentity?.sinceGeneration ?? big(1n), retired: true });
  tx.put("identities", t.newIdentityId, { accountId: t.accountId, accountName: t.accountName, accountKey: toHex(cert.accountKey), sinceGeneration: big(t.newGeneration), retired: false });
  tx.put("successions", successionKey(t.accountId, t.previousGeneration), { accountId: t.accountId, accountName: t.accountName, successionId: t.successionId, previousIdentityId: t.previousIdentityId, newIdentityId: t.newIdentityId, previousGeneration: big(t.previousGeneration), newGeneration: big(t.newGeneration), newCertificateHash: t.newCertificateHash, authorityKeyId: toHex(parsed.authorityKeyId), wire: toHex(input.wire), acceptedAt: big(now) });
  const notice: KeyChangeRow = { accountId: t.accountId, accountName: t.accountName, previousIdentityId: t.previousIdentityId, newIdentityId: t.newIdentityId, generation: big(t.newGeneration), reason: "succession", successionId: t.successionId, acceptedAt: big(now) };
  tx.put("keyChanges", `${now.toString().padStart(20, "0")}:${t.accountId}:${t.successionId}`, notice);
  t3ApplyChange(tx, { kind: "deviceChanged", identityId: parsed.accountId, certificateHash: cert.bodyHash });
  return { outcome: "ACCEPTED", accountId: parsed.accountId, accountName: t.accountName, previousIdentityId: parsed.previousIdentityId, newIdentityId: parsed.newIdentityId, generation: t.newGeneration, transition: t, pin: next };
}
