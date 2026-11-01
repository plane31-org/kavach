/**
 * Account succession (protocol section 4, revision 9; amendment A1): the host's authority binds
 * an account to new keys with continuity of its relationships. This module is the verifier a
 * peer runs on a type 9 document and the chain it keeps per account, in the order the
 * specification gives: an accepted transition stays trusted; a received document is
 * authenticated under the current key list; its transition is compared with the recorded ones;
 * only a new transition meets the pin, generation, retirement and certificate checks.
 */
import { equalBytes, toHex } from "./bytes.js";
import { DocumentType, expectType, parseDocument, verifyDocument, type AccountDevice, type AccountSuccession } from "./codec.js";
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
/**
 * Verify a whole chain for an account whose current key this device holds (identity continuity
 * after successions): every link attested under the current list, contiguous from the root to
 * `finalIdentityId`, each certificate bound by its link. Returns the parsed links in order.
 * Nothing is written; `recordChainIn` keeps the evidence once the header exists.
 */
export interface VerifiedLink {
  readonly doc: AccountSuccession;
  readonly wire: Uint8Array;
  readonly certificate: Uint8Array;
}

export function verifyChain(links: readonly { wire: Uint8Array; certificate: Uint8Array }[], input: { accountId: Uint8Array; finalIdentityId: Uint8Array; trust: ResetTrust; now: bigint }): VerifiedLink[] {
  const stage = "chain";
  const list = input.trust.state.current;
  if (!list || !input.trust.fresh(input.now)) throw new KavachError("RESET_KEYS_REQUIRED", stage, "no fresh key list");
  const out: VerifiedLink[] = [];
  let previous = input.accountId;
  for (const link of links) {
    const parsed = expectType<AccountSuccession>(parseDocument(link.wire), DocumentType.AccountSuccession, stage);
    const signer = list.list.keys.find((k) => equalBytes(k.keyId, parsed.authorityKeyId));
    if (!signer) throw new KavachError("RESET_KEY_REVOKED", stage, "a link is attested under a key the list no longer allows");
    const doc = expectType<AccountSuccession>(verifyDocument(link.wire, signer.publicKey), DocumentType.AccountSuccession, stage);
    const cert = expectType<AccountDevice>(verifyDocument(link.certificate), DocumentType.AccountDevice, stage);
    if (!equalBytes(doc.accountId, input.accountId) || !equalBytes(doc.previousIdentityId, previous) || doc.accountName !== cert.accountName) throw new KavachError("SUCCESSION_BINDING", stage, "the chain is not contiguous from the root");
    if (!equalBytes(doc.newCertificateHash, cert.bodyHash) || !equalBytes(identityId(cert.accountName, cert.accountKey), doc.newIdentityId) || cert.generation !== doc.newGeneration) throw new KavachError("SUCCESSION_BINDING", stage, "a link does not bind its certificate");
    out.push({ doc, wire: link.wire, certificate: link.certificate });
    previous = doc.newIdentityId;
  }
  if (!equalBytes(previous, input.finalIdentityId)) throw new KavachError("SUCCESSION_BINDING", stage, "the chain does not end at this key");
  return out;
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
  if (now === undefined || now < input.trust.state.timeHighWater) throw new KavachError("RESET_CLOCK_UNTRUSTED", stage);
  const list = input.trust.state.current;
  if (!list || !input.trust.fresh(now)) throw new KavachError("RESET_KEYS_REQUIRED", stage, "no fresh key list");
  const signer = list.list.keys.find((k) => equalBytes(k.keyId, parsed.authorityKeyId));
  if (!signer) throw new KavachError("RESET_KEY_REVOKED", stage, "the signing key is not in the current list");
  expectType<AccountSuccession>(verifyDocument(input.wire, signer.publicKey), DocumentType.AccountSuccession, stage);

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

  // Order 3: a new transition against the pin, the generation, the retired set and the certificate.
  if (!pinRow) throw new KavachError("SUCCESSION_BINDING", stage, "no pin for the account");
  const pin = rowToPin(pinRow);
  if (pin.accountName !== t.accountName || (pinRow.accountId ?? pinRow.identityId) !== t.accountId) throw new KavachError("SUCCESSION_BINDING", stage, "account name or id does not match the pin");
  if (toHex(pin.identityId) !== t.previousIdentityId) throw new KavachError("SUCCESSION_BINDING", stage, "previous identity is not the account's current identity");
  if (t.previousGeneration < pin.generation) throw new KavachError("ROLLBACK", stage, "previous generation below the pinned one");
  const retiredBySuccession = (hex: string): boolean => tx.get("identities", hex)?.retired === true;
  if (retiredBySuccession(t.previousIdentityId) || retiredBySuccession(t.newIdentityId) || input.trust.state.retired.has(t.previousIdentityId) || input.trust.state.retired.has(t.newIdentityId)) {
    throw new KavachError("SUPERSEDED_IDENTITY", stage, "a retired identity cannot be previous or new");
  }
  const cert = expectType<AccountDevice>(verifyDocument(input.newCertificate), DocumentType.AccountDevice, stage);
  const derived = identityId(cert.accountName, cert.accountKey);
  if (toHex(cert.bodyHash) !== t.newCertificateHash || cert.accountName !== t.accountName || cert.generation !== t.newGeneration || toHex(derived) !== t.newIdentityId) {
    throw new KavachError("SUCCESSION_BINDING", stage, "the certificate does not bind to the succession");
  }
  if (pin.deviceIds.some((d) => equalBytes(d, cert.deviceId))) throw new KavachError("DEVICE_ID_REUSED", stage);

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
