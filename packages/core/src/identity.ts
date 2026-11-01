/**
 * Accounts, devices, certificates and generation rules (protocol section 4).
 *
 * The pin is the local trust state for one account: (`accountName`, `AK`) at first contact, then
 * the greatest accepted device generation with its certificate hash and device keys. Everything
 * here is a pure decision over a pin and a candidate certificate; persistence is the store's job.
 */
import { concat, equalBytes, toHex } from "./bytes.js";
import {
  DocumentType,
  buildAccountDevice,
  expectType,
  verifyDocument,
  type AccountDevice,
  type Parsed
} from "./codec.js";
import {
  DEVICE_ID_BYTES,
  SEED_BYTES,
  accountKeypair,
  deviceBoxKeypair,
  deviceSigningKeypair,
  identityId,
  randomBytes,
  streamId,
  type BoxKeypair,
  type SigningKeypair
} from "./crypto.js";
import { KavachError } from "./errors.js";

/** What the SDK persists per known account. */
export interface AccountPin {
  readonly accountName: string;
  readonly accountKey: Uint8Array;
  /** The identity of the current key: `H(C("identity") || name || AK)`. Changes at a succession. */
  readonly identityId: Uint8Array;
  /** The account id: the identity at enrollment, what every document names. Constant across successions. */
  readonly accountId: Uint8Array;
  readonly generation: bigint;
  readonly certificateHash: Uint8Array;
  readonly certificate: Uint8Array;
  readonly deviceId: Uint8Array;
  readonly signingKey: Uint8Array;
  readonly boxKey: Uint8Array;
  readonly streamId: Uint8Array;
  /** Every device id this account has used, including the current one. */
  readonly deviceIds: readonly Uint8Array[];
}

export type CertificateOutcome =
  | { readonly outcome: "ACCEPTED"; readonly pin: AccountPin; readonly rotate: boolean; readonly previous: AccountPin | undefined }
  | { readonly outcome: "DUPLICATE"; readonly pin: AccountPin };

export function pinFromCertificate(doc: Parsed<AccountDevice>, previous?: AccountPin, accountId?: Uint8Array): AccountPin {
  const iid = identityId(doc.accountName, doc.accountKey);
  const ids = previous ? [...previous.deviceIds] : [];
  if (!ids.some((d) => equalBytes(d, doc.deviceId))) ids.push(doc.deviceId);
  return {
    accountName: doc.accountName,
    accountKey: doc.accountKey,
    identityId: iid,
    // The account id is carried from the previous pin (a succession keeps it) or given by the
    // caller who resolved the chain; a first contact is its own root.
    accountId: accountId ?? previous?.accountId ?? iid,
    generation: doc.generation,
    certificateHash: doc.bodyHash,
    certificate: concat(doc.body, doc.signature),
    deviceId: doc.deviceId,
    signingKey: doc.signingKey,
    boxKey: doc.boxKey,
    streamId: streamId(iid, doc.deviceId),
    deviceIds: ids
  };
}

/**
 * Accept or reject a certificate against the local pin for its account.
 *
 * - No pin yet: first contact. If `expected` names the account the directory resolved, the
 *   certificate must carry that name and key; the pin is created and nothing rotates.
 * - A pinned account: a different `AK` is `ACCOUNT_KEY_CHANGED` and the caller quarantines
 *   (never closing or re-admitting anything); a lower generation is `DEVICE_ROLLBACK`; the same
 *   generation is a duplicate or `EQUIVOCATION`; a higher one with a reused device id is
 *   `DEVICE_ID_REUSED`; otherwise it is accepted and the audience must rotate.
 */
export function acceptCertificate(
  current: AccountPin | undefined,
  wire: Uint8Array,
  expected?: { readonly accountName: string; readonly accountKey: Uint8Array }
): CertificateOutcome {
  const stage = "acceptCertificate";
  const doc = expectType<AccountDevice>(verifyDocument(wire), DocumentType.AccountDevice, stage);
  const anchor = current ?? expected;
  if (anchor && (anchor.accountName !== doc.accountName || !equalBytes(anchor.accountKey, doc.accountKey))) {
    throw new KavachError("ACCOUNT_KEY_CHANGED", stage, `certificate for ${doc.accountName} carries a different account key`);
  }
  if (!current) return { outcome: "ACCEPTED", pin: pinFromCertificate(doc), rotate: false, previous: undefined };
  if (doc.generation < current.generation) throw new KavachError("DEVICE_ROLLBACK", stage);
  if (doc.generation === current.generation) {
    if (equalBytes(doc.bodyHash, current.certificateHash)) return { outcome: "DUPLICATE", pin: current };
    throw new KavachError("EQUIVOCATION", stage, "two certificates at one generation");
  }
  if (current.deviceIds.some((d) => equalBytes(d, doc.deviceId))) throw new KavachError("DEVICE_ID_REUSED", stage);
  return { outcome: "ACCEPTED", pin: pinFromCertificate(doc, current), rotate: true, previous: current };
}

// Own account and device ---------------------------------------------------------------------

export interface DeviceKeys {
  readonly deviceSeed: Uint8Array;
  readonly deviceId: Uint8Array;
  readonly signing: SigningKeypair;
  readonly box: BoxKeypair;
}

export interface OwnAccount {
  readonly accountName: string;
  readonly accountSeed: Uint8Array;
  readonly account: SigningKeypair;
  /** The identity of this key. */
  readonly identityId: Uint8Array;
  /** The account id: this identity for an account enrolled under this key, the root of the chain otherwise. */
  readonly accountId: Uint8Array;
}

export function openAccount(accountName: string, accountSeed: Uint8Array, accountId?: Uint8Array): OwnAccount {
  if (accountSeed.length !== SEED_BYTES) throw new KavachError("INVALID_KEY", "openAccount");
  const account = accountKeypair(accountSeed);
  const iid = identityId(accountName, account.publicKey);
  return { accountName, accountSeed, account, identityId: iid, accountId: accountId ?? iid };
}

export function newAccountSeed(): Uint8Array {
  return randomBytes(SEED_BYTES);
}

/** A fresh installation: new device seed and a random nonzero device id. Never backed up. */
export function newDevice(): DeviceKeys {
  const deviceSeed = randomBytes(SEED_BYTES);
  let deviceId = randomBytes(DEVICE_ID_BYTES);
  while (deviceId.every((b) => b === 0)) deviceId = randomBytes(DEVICE_ID_BYTES);
  return deviceFromSeed(deviceSeed, deviceId);
}

export function deviceFromSeed(deviceSeed: Uint8Array, deviceId: Uint8Array): DeviceKeys {
  if (deviceId.length !== DEVICE_ID_BYTES || deviceId.every((b) => b === 0)) throw new KavachError("MALFORMED", "device", "device id");
  return { deviceSeed, deviceId, signing: deviceSigningKeypair(deviceSeed), box: deviceBoxKeypair(deviceSeed) };
}

/** Build and sign this account's certificate for a device at a generation. */
export function certify(account: OwnAccount, device: DeviceKeys, generation: bigint): Uint8Array {
  if (generation < 1n) throw new KavachError("MALFORMED", "certify", "generation");
  return buildAccountDevice(
    {
      accountName: account.accountName,
      accountKey: account.account.publicKey,
      generation,
      deviceId: device.deviceId,
      signingKey: device.signing.publicKey,
      boxKey: device.box.publicKey
    },
    account.account.secretKey
  );
}

export function pinKey(identity: Uint8Array): string {
  return toHex(identity);
}
