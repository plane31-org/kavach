/**
 * The wire documents of Kavach v1, protocol sections 3 to 12.
 *
 * Parse within bounds first (sizes, ranges, sort orders, counts, nonzero rules), then verify the
 * signature under the key the caller's trust state names, then anything else. Every parser here
 * refuses trailing bytes and never touches a signature. Type 5 is retired and rejected.
 */
import {
  MAX_DOCUMENT_BYTES,
  MAX_PAYLOAD_BYTES,
  Reader,
  Writer,
  compareBytes,
  concat,
  equalBytes,
  isAllZero,
  u32
} from "./bytes.js";
import {
  C,
  DEVICE_ID_BYTES,
  HASH_BYTES,
  KEY_BYTES,
  NONCE_BYTES,
  PUBLIC_KEY_BYTES,
  RECOVERY_CODE_PREFIX,
  SEED_BYTES,
  SIGNATURE_BYTES,
  TAG_BYTES,
  WIRE_VERSION,
  accountKeypair,
  aeadOpen,
  aeadSeal,
  assertValidBoxKey,
  assertValidSigningKey,
  bodyHash,
  sign,
  verify,
  type Label
} from "./crypto.js";
import { KavachError } from "./errors.js";

export const MAX_MEMBERS = 100;
export const MAX_RESET_KEYS = 8;
export const MAX_RESET_KEY_LIST_LIFETIME_MS = 2_592_000_000n; // 30 days
export const MIN_RECORD_CIPHERTEXT = TAG_BYTES;
export const MAX_RECORD_CIPHERTEXT = MAX_PAYLOAD_BYTES + TAG_BYTES;
export const MIN_VAULT_CIPHERTEXT = 90;
export const MAX_VAULT_CIPHERTEXT = 4_990;
export const VAULT_ENTRY_BYTES = 49;
export const RECORD_HEADER_BYTES = 51;
export const FLAG_KIND = 0x02;
const RESERVED_FLAGS = ~FLAG_KIND & 0xff;

export enum DocumentType {
  AccountDevice = 1,
  CircleSnapshot = 2,
  EpochManifest = 3,
  EncryptedRecord = 4,
  AccountVault = 6,
  AccountResetReceipt = 7,
  ResetKeyList = 8
}

export type RecordKind = 0 | 1; // 0 location, 1 check-in

export interface AccountDevice {
  readonly type: DocumentType.AccountDevice;
  readonly accountName: string;
  readonly accountKey: Uint8Array;
  readonly generation: bigint;
  readonly deviceId: Uint8Array;
  readonly signingKey: Uint8Array;
  readonly boxKey: Uint8Array;
}

export interface CircleSnapshot {
  readonly type: DocumentType.CircleSnapshot;
  readonly circleId: Uint8Array;
  readonly ownerIdentityId: Uint8Array;
  readonly revision: bigint;
  readonly members: readonly Uint8Array[];
}

export interface AudienceRow {
  readonly identityId: Uint8Array;
  readonly certificateHash: Uint8Array;
  readonly wrapHash: Uint8Array;
}

export interface EpochManifest {
  readonly type: DocumentType.EpochManifest;
  readonly streamId: Uint8Array;
  readonly authorIdentityId: Uint8Array;
  readonly authorCertificateHash: Uint8Array;
  readonly epoch: number;
  readonly createdAt: bigint;
  readonly keyCommitment: Uint8Array;
  readonly audience: readonly AudienceRow[];
}

export interface EncryptedRecord {
  readonly type: DocumentType.EncryptedRecord;
  readonly streamId: Uint8Array;
  readonly epoch: number;
  readonly counter: number;
  readonly sentAt: bigint;
  readonly flags: number;
  readonly kind: RecordKind;
  /** The 51-byte header, which the AEAD authenticates as `C("record-aad") || header`. */
  readonly header: Uint8Array;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export interface AccountResetReceipt {
  readonly type: DocumentType.AccountResetReceipt;
  readonly accountName: string;
  readonly oldIdentityId: Uint8Array;
  readonly newIdentityId: Uint8Array;
  readonly resetId: Uint8Array;
  readonly issuedAt: bigint;
  readonly authorityKeyId: Uint8Array;
}

export interface ResetKeyEntry {
  readonly keyId: Uint8Array;
  readonly publicKey: Uint8Array;
}

export interface ResetKeyList {
  readonly type: DocumentType.ResetKeyList;
  readonly version: bigint;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
  readonly keys: readonly ResetKeyEntry[];
}

export type SignedDocument = AccountDevice | CircleSnapshot | EpochManifest | EncryptedRecord | AccountResetReceipt | ResetKeyList;

/** A parsed signed document together with the exact body and signature bytes. */
export type Parsed<T extends SignedDocument = SignedDocument> = T & {
  readonly body: Uint8Array;
  readonly signature: Uint8Array;
  readonly bodyHash: Uint8Array;
};

export const LABEL_BY_TYPE: Readonly<Record<number, Label>> = {
  [DocumentType.AccountDevice]: "account-sig",
  [DocumentType.CircleSnapshot]: "snapshot-sig",
  [DocumentType.EpochManifest]: "epoch-sig",
  [DocumentType.EncryptedRecord]: "record-sig",
  [DocumentType.AccountResetReceipt]: "reset-sig",
  [DocumentType.ResetKeyList]: "reset-keys-sig"
};

// Parsing --------------------------------------------------------------------------------------

function strictlySortedUnique(items: readonly Uint8Array[]): boolean {
  for (let i = 1; i < items.length; i++) {
    const a = items[i - 1];
    const b = items[i];
    if (!a || !b || compareBytes(a, b) >= 0) return false;
  }
  return true;
}

function malformed(stage: string, why: string): KavachError {
  return new KavachError("MALFORMED", stage, why);
}

/**
 * Parse a signed document (types 1 to 4, 7, 8). The signature is split off but not checked;
 * call `verifyDocument` for that. Type 6 is not a signed document and type 5 is retired.
 */
export function parseDocument(wire: Uint8Array): Parsed {
  const stage = "parse";
  if (wire.length > MAX_DOCUMENT_BYTES) throw new KavachError("SIZE_LIMIT", stage, "document over 16,384 bytes");
  const r = new Reader(wire, stage);
  if (r.u8() !== WIRE_VERSION) throw new KavachError("UNSUPPORTED_VERSION", stage);
  const type = r.u8();
  let fields: SignedDocument;
  switch (type) {
    case DocumentType.AccountDevice: {
      const accountName = r.name();
      const accountKey = r.take(PUBLIC_KEY_BYTES);
      const generation = r.u64();
      const deviceId = r.take(DEVICE_ID_BYTES);
      const signingKey = r.take(PUBLIC_KEY_BYTES);
      const boxKey = r.take(PUBLIC_KEY_BYTES);
      if (generation === 0n) throw malformed(stage, "generation zero");
      if (isAllZero(deviceId)) throw malformed(stage, "device id zero");
      fields = { type, accountName, accountKey, generation, deviceId, signingKey, boxKey };
      break;
    }
    case DocumentType.CircleSnapshot: {
      const circleId = r.take(16);
      const ownerIdentityId = r.take(HASH_BYTES);
      const revision = r.u64();
      const count = r.u16();
      if (revision === 0n) throw malformed(stage, "revision zero");
      if (count < 1 || count > MAX_MEMBERS) throw malformed(stage, "member count");
      const members: Uint8Array[] = [];
      for (let i = 0; i < count; i++) members.push(r.take(HASH_BYTES));
      if (!strictlySortedUnique(members)) throw malformed(stage, "members not strictly sorted");
      if (!members.some((m) => equalBytes(m, ownerIdentityId))) throw malformed(stage, "owner missing");
      fields = { type, circleId, ownerIdentityId, revision, members };
      break;
    }
    case DocumentType.EpochManifest: {
      const streamId = r.take(HASH_BYTES);
      const authorIdentityId = r.take(HASH_BYTES);
      const authorCertificateHash = r.take(HASH_BYTES);
      const epoch = r.u32();
      const createdAt = r.u64();
      const keyCommitment = r.take(HASH_BYTES);
      const count = r.u16();
      if (epoch === 0) throw malformed(stage, "epoch zero");
      if (count < 1 || count > MAX_MEMBERS) throw malformed(stage, "audience count");
      const audience: AudienceRow[] = [];
      for (let i = 0; i < count; i++) {
        audience.push({ identityId: r.take(HASH_BYTES), certificateHash: r.take(HASH_BYTES), wrapHash: r.take(HASH_BYTES) });
      }
      if (!strictlySortedUnique(audience.map((a) => a.identityId))) throw malformed(stage, "audience not strictly sorted");
      if (!audience.some((a) => equalBytes(a.identityId, authorIdentityId))) throw malformed(stage, "author missing from audience");
      fields = { type, streamId, authorIdentityId, authorCertificateHash, epoch, createdAt, keyCommitment, audience };
      break;
    }
    case DocumentType.EncryptedRecord: {
      const streamId = r.take(HASH_BYTES);
      const epoch = r.u32();
      const counter = r.u32();
      const sentAt = r.u64();
      const flags = r.u8();
      if (epoch === 0) throw malformed(stage, "epoch zero");
      if ((flags & RESERVED_FLAGS) !== 0) throw malformed(stage, "reserved flag bit set");
      const header = r.consumed();
      const nonce = r.take(NONCE_BYTES);
      const length = r.u32();
      if (length < MIN_RECORD_CIPHERTEXT || length > MAX_RECORD_CIPHERTEXT) {
        throw new KavachError("SIZE_LIMIT", stage, "record ciphertext length");
      }
      const ciphertext = r.take(length);
      fields = { type, streamId, epoch, counter, sentAt, flags, kind: (flags & FLAG_KIND) === 0 ? 0 : 1, header, nonce, ciphertext };
      break;
    }
    case DocumentType.AccountResetReceipt: {
      const accountName = r.name();
      const oldIdentityId = r.take(HASH_BYTES);
      const newIdentityId = r.take(HASH_BYTES);
      const resetId = r.take(16);
      const issuedAt = r.u64();
      const authorityKeyId = r.take(16);
      if (equalBytes(oldIdentityId, newIdentityId)) throw malformed(stage, "old and new identity equal");
      fields = { type, accountName, oldIdentityId, newIdentityId, resetId, issuedAt, authorityKeyId };
      break;
    }
    case DocumentType.ResetKeyList: {
      const version = r.u64();
      const issuedAt = r.u64();
      const expiresAt = r.u64();
      const count = r.u8();
      if (version === 0n) throw malformed(stage, "version zero");
      if (count > MAX_RESET_KEYS) throw malformed(stage, "too many keys");
      const lifetime = expiresAt - issuedAt;
      if (lifetime <= 0n || lifetime > MAX_RESET_KEY_LIST_LIFETIME_MS) throw malformed(stage, "key-list lifetime");
      const keys: ResetKeyEntry[] = [];
      for (let i = 0; i < count; i++) keys.push({ keyId: r.take(16), publicKey: r.take(PUBLIC_KEY_BYTES) });
      if (!strictlySortedUnique(keys.map((k) => k.keyId))) throw malformed(stage, "key ids not strictly sorted");
      if (keys.some((k) => isAllZero(k.keyId))) throw malformed(stage, "zero key id");
      for (let i = 0; i < keys.length; i++) {
        for (let j = i + 1; j < keys.length; j++) {
          const a = keys[i];
          const b = keys[j];
          if (a && b && equalBytes(a.publicKey, b.publicKey)) throw malformed(stage, "duplicate key");
        }
      }
      for (const k of keys) assertValidSigningKey(k.publicKey, stage);
      fields = { type, version, issuedAt, expiresAt, keys };
      break;
    }
    default:
      // 5 is retired; 6 is not a signed document; everything else is unknown.
      throw new KavachError("UNSUPPORTED_TYPE", stage, `type ${type}`);
  }
  const body = r.consumed();
  const signature = r.take(SIGNATURE_BYTES);
  r.end();
  return { ...fields, body, signature, bodyHash: bodyHash(body) };
}

/**
 * Parse and verify. A type 1 certificate is verified under the key it carries, which establishes
 * key possession only. Every other type needs the key the caller's trust state names.
 */
export function verifyDocument(wire: Uint8Array, publicKey?: Uint8Array): Parsed {
  const doc = parseDocument(wire);
  const label = LABEL_BY_TYPE[doc.type];
  if (!label) throw new KavachError("UNSUPPORTED_TYPE", "verify");
  let key = publicKey;
  if (doc.type === DocumentType.AccountDevice) key = doc.accountKey;
  if (!key) throw new KavachError("METADATA_REQUIRED", "verify", "verification key required");
  verify(key, label, doc.body, doc.signature);
  if (doc.type === DocumentType.AccountDevice) {
    assertValidSigningKey(doc.signingKey);
    assertValidBoxKey(doc.boxKey);
  }
  return doc;
}

/** Narrow a parsed document to one type, or fail as MALFORMED. */
export function expectType<T extends SignedDocument>(doc: Parsed, type: T["type"], stage = "verify"): Parsed<T> {
  if (doc.type !== type) throw malformed(stage, `expected type ${type}, got ${doc.type}`);
  return doc as unknown as Parsed<T>;
}

// Building -------------------------------------------------------------------------------------

function signed(body: Uint8Array, label: Label, secretKey: Uint8Array): Uint8Array {
  return concat(body, sign(secretKey, label, body));
}

export function encodeAccountDeviceBody(f: Omit<AccountDevice, "type">): Uint8Array {
  return new Writer()
    .u8(WIRE_VERSION)
    .u8(DocumentType.AccountDevice)
    .name(f.accountName)
    .bytes(f.accountKey)
    .u64(f.generation)
    .bytes(f.deviceId)
    .bytes(f.signingKey)
    .bytes(f.boxKey)
    .finish();
}

export function buildAccountDevice(f: Omit<AccountDevice, "type">, accountSecretKey: Uint8Array): Uint8Array {
  return signed(encodeAccountDeviceBody(f), "account-sig", accountSecretKey);
}

export function encodeCircleSnapshotBody(f: Omit<CircleSnapshot, "type">): Uint8Array {
  const members = [...f.members].sort(compareBytes);
  const w = new Writer().u8(WIRE_VERSION).u8(DocumentType.CircleSnapshot).bytes(f.circleId).bytes(f.ownerIdentityId).u64(f.revision).u16(members.length);
  for (const m of members) w.bytes(m);
  return w.finish();
}

export function buildCircleSnapshot(f: Omit<CircleSnapshot, "type">, ownerAccountSecretKey: Uint8Array): Uint8Array {
  return signed(encodeCircleSnapshotBody(f), "snapshot-sig", ownerAccountSecretKey);
}

export function encodeEpochManifestBody(f: Omit<EpochManifest, "type">): Uint8Array {
  const rows = [...f.audience].sort((a, b) => compareBytes(a.identityId, b.identityId));
  const w = new Writer()
    .u8(WIRE_VERSION)
    .u8(DocumentType.EpochManifest)
    .bytes(f.streamId)
    .bytes(f.authorIdentityId)
    .bytes(f.authorCertificateHash)
    .u32(f.epoch)
    .u64(f.createdAt)
    .bytes(f.keyCommitment)
    .u16(rows.length);
  for (const row of rows) w.bytes(row.identityId).bytes(row.certificateHash).bytes(row.wrapHash);
  return w.finish();
}

export function buildEpochManifest(f: Omit<EpochManifest, "type">, deviceSigningSecretKey: Uint8Array): Uint8Array {
  return signed(encodeEpochManifestBody(f), "epoch-sig", deviceSigningSecretKey);
}

export function encodeRecordHeader(f: { streamId: Uint8Array; epoch: number; counter: number; sentAt: bigint; kind: RecordKind }): Uint8Array {
  if (f.epoch === 0) throw malformed("encode", "epoch zero");
  return new Writer()
    .u8(WIRE_VERSION)
    .u8(DocumentType.EncryptedRecord)
    .bytes(f.streamId)
    .u32(f.epoch)
    .u32(f.counter)
    .u64(f.sentAt)
    .u8(f.kind === 1 ? FLAG_KIND : 0)
    .finish();
}

export function recordAad(header: Uint8Array): Uint8Array {
  return concat(C("record-aad"), header);
}

/** Encrypt and sign one record. The caller supplies a fresh random nonce and never reuses it. */
export function buildEncryptedRecord(
  f: { streamId: Uint8Array; epoch: number; counter: number; sentAt: bigint; kind: RecordKind },
  plaintext: Uint8Array,
  epochKey: Uint8Array,
  nonce: Uint8Array,
  deviceSigningSecretKey: Uint8Array
): Uint8Array {
  if (plaintext.length > MAX_PAYLOAD_BYTES) throw new KavachError("SIZE_LIMIT", "encode", "payload over 4,096 bytes");
  const header = encodeRecordHeader(f);
  const ciphertext = aeadSeal(epochKey, nonce, recordAad(header), plaintext);
  const body = concat(header, nonce, u32(ciphertext.length), ciphertext);
  return signed(body, "record-sig", deviceSigningSecretKey);
}

/** Decrypt a parsed record under its epoch key. Verify the signature first; this does not. */
export function openRecord(record: EncryptedRecord, epochKey: Uint8Array): Uint8Array {
  return aeadOpen(epochKey, record.nonce, recordAad(record.header), record.ciphertext);
}

export function encodeResetReceiptBody(f: Omit<AccountResetReceipt, "type">): Uint8Array {
  return new Writer()
    .u8(WIRE_VERSION)
    .u8(DocumentType.AccountResetReceipt)
    .name(f.accountName)
    .bytes(f.oldIdentityId)
    .bytes(f.newIdentityId)
    .bytes(f.resetId)
    .u64(f.issuedAt)
    .bytes(f.authorityKeyId)
    .finish();
}

export function buildResetReceipt(f: Omit<AccountResetReceipt, "type">, resetSecretKey: Uint8Array): Uint8Array {
  return signed(encodeResetReceiptBody(f), "reset-sig", resetSecretKey);
}

export function encodeResetKeyListBody(f: Omit<ResetKeyList, "type">): Uint8Array {
  const keys = [...f.keys].sort((a, b) => compareBytes(a.keyId, b.keyId));
  const w = new Writer().u8(WIRE_VERSION).u8(DocumentType.ResetKeyList).u64(f.version).u64(f.issuedAt).u64(f.expiresAt).u8(keys.length);
  for (const k of keys) w.bytes(k.keyId).bytes(k.publicKey);
  return w.finish();
}

export function buildResetKeyList(f: Omit<ResetKeyList, "type">, managementSecretKey: Uint8Array): Uint8Array {
  return signed(encodeResetKeyListBody(f), "reset-keys-sig", managementSecretKey);
}

// Location codec -------------------------------------------------------------------------------

export const LOCATION_PAYLOAD_VERSION = 1;
export const LOCATION_PAYLOAD_BYTES = 22;
export type LocationStatus = 0 | 1 | 2; // normal, stale, unavailable

export interface Location {
  readonly latitudeE7: number;
  readonly longitudeE7: number;
  readonly accuracyMm: number;
  readonly capturedAt: bigint;
  readonly status: LocationStatus;
}

function checkLocation(l: Location, stage: string): void {
  const bad = (why: string): KavachError => new KavachError("BAD_PAYLOAD", stage, why);
  if (!Number.isInteger(l.latitudeE7) || l.latitudeE7 < -900_000_000 || l.latitudeE7 > 900_000_000) throw bad("latitude");
  if (!Number.isInteger(l.longitudeE7) || l.longitudeE7 < -1_800_000_000 || l.longitudeE7 > 1_800_000_000) throw bad("longitude");
  if (!Number.isInteger(l.accuracyMm) || l.accuracyMm < 0 || l.accuracyMm > 100_000_000) throw bad("accuracy");
  if (l.status !== 0 && l.status !== 1 && l.status !== 2) throw bad("status");
  if (l.status === 2 && (l.latitudeE7 !== 0 || l.longitudeE7 !== 0 || l.accuracyMm !== 0)) throw bad("unavailable with coordinates");
}

export function encodeLocation(l: Location): Uint8Array {
  checkLocation(l, "encodeLocation");
  return new Writer().u8(LOCATION_PAYLOAD_VERSION).i32(l.latitudeE7).i32(l.longitudeE7).u32(l.accuracyMm).u64(l.capturedAt).u8(l.status).finish();
}

export function decodeLocation(payload: Uint8Array): Location {
  const stage = "decodeLocation";
  if (payload.length !== LOCATION_PAYLOAD_BYTES) throw new KavachError("BAD_PAYLOAD", stage, "length");
  const r = new Reader(payload, stage);
  if (r.u8() !== LOCATION_PAYLOAD_VERSION) throw new KavachError("BAD_PAYLOAD", stage, "version");
  const l: Location = { latitudeE7: r.i32(), longitudeE7: r.i32(), accuracyMm: r.u32(), capturedAt: r.u64(), status: r.u8() as LocationStatus };
  r.end();
  checkLocation(l, stage);
  return l;
}

// Account vault (type 6) -----------------------------------------------------------------------

export interface VaultEntry {
  readonly circleId: Uint8Array;
  readonly ownerIdentityId: Uint8Array;
  readonly sharingEnabled: boolean;
}

export interface VaultContents {
  readonly accountSeed: Uint8Array;
  readonly lastDeviceGeneration: bigint;
  readonly lastCertificateHash: Uint8Array;
  readonly entries: readonly VaultEntry[];
}

export interface VaultHeader {
  readonly accountName: string;
  readonly accountKey: Uint8Array;
  readonly vaultRevision: bigint;
}

export function encodeVaultHeader(h: VaultHeader): Uint8Array {
  return new Writer().u8(WIRE_VERSION).u8(DocumentType.AccountVault).name(h.accountName).bytes(h.accountKey).u64(h.vaultRevision).finish();
}

export function encodeVaultPlaintext(v: VaultContents): Uint8Array {
  if (v.accountSeed.length !== SEED_BYTES) throw malformed("encodeVault", "seed length");
  if (v.entries.length > MAX_MEMBERS) throw malformed("encodeVault", "too many entries");
  const entries = [...v.entries].sort((a, b) => compareBytes(a.circleId, b.circleId));
  if (!strictlySortedUnique(entries.map((e) => e.circleId))) throw malformed("encodeVault", "duplicate circle");
  const w = new Writer().bytes(v.accountSeed).u64(v.lastDeviceGeneration).bytes(v.lastCertificateHash).u16(entries.length);
  for (const e of entries) w.bytes(e.circleId).bytes(e.ownerIdentityId).u8(e.sharingEnabled ? 1 : 0);
  return w.finish();
}

export function decodeVaultPlaintext(plain: Uint8Array): VaultContents {
  const stage = "decodeVault";
  const r = new Reader(plain, stage);
  const accountSeed = r.take(SEED_BYTES);
  const lastDeviceGeneration = r.u64();
  const lastCertificateHash = r.take(HASH_BYTES);
  const count = r.u16();
  if (lastDeviceGeneration === 0n) throw malformed(stage, "generation zero");
  if (count > MAX_MEMBERS) throw malformed(stage, "too many entries");
  const entries: VaultEntry[] = [];
  for (let i = 0; i < count; i++) {
    const circleId = r.take(16);
    const ownerIdentityId = r.take(HASH_BYTES);
    const flag = r.u8();
    if (flag !== 0 && flag !== 1) throw malformed(stage, "sharing flag");
    entries.push({ circleId, ownerIdentityId, sharingEnabled: flag === 1 });
  }
  r.end();
  if (!strictlySortedUnique(entries.map((e) => e.circleId))) throw malformed(stage, "entries not strictly sorted");
  return { accountSeed, lastDeviceGeneration, lastCertificateHash, entries };
}

/** Encrypt a vault. The caller supplies a fresh random nonce. */
export function sealVault(header: VaultHeader, contents: VaultContents, recoveryKey: Uint8Array, nonce: Uint8Array): Uint8Array {
  if (header.vaultRevision === 0n) throw malformed("sealVault", "revision zero");
  const h = encodeVaultHeader(header);
  const ciphertext = aeadSeal(recoveryKey, nonce, concat(C("vault-aad"), h), encodeVaultPlaintext(contents));
  return concat(h, nonce, u32(ciphertext.length), ciphertext);
}

/** Read a vault's public header without opening it (the host's compare-and-swap uses it). */
export function parseVaultHeader(wire: Uint8Array): VaultHeader & { readonly hash: Uint8Array } {
  const stage = "vaultHeader";
  if (wire.length > MAX_DOCUMENT_BYTES) throw new KavachError("SIZE_LIMIT", stage);
  const r = new Reader(wire, stage);
  if (r.u8() !== WIRE_VERSION) throw new KavachError("UNSUPPORTED_VERSION", stage);
  if (r.u8() !== DocumentType.AccountVault) throw new KavachError("UNSUPPORTED_TYPE", stage);
  const accountName = r.name();
  const accountKey = r.take(PUBLIC_KEY_BYTES);
  const vaultRevision = r.u64();
  if (vaultRevision === 0n) throw malformed(stage, "revision zero");
  return { accountName, accountKey, vaultRevision, hash: bodyHash(wire) };
}

export interface OpenedVault extends VaultContents {
  readonly header: VaultHeader;
}

/**
 * Open a vault under the recovery key. Binds the header to the expected account before decrypting
 * and checks that `AK` derives from the recovered seed before trusting the entries.
 */
export function openVault(wire: Uint8Array, recoveryKey: Uint8Array, expectedName: string, expectedAccountKey: Uint8Array): OpenedVault {
  const stage = "openVault";
  if (wire.length > MAX_DOCUMENT_BYTES) throw new KavachError("SIZE_LIMIT", stage);
  const r = new Reader(wire, stage);
  if (r.u8() !== WIRE_VERSION) throw new KavachError("UNSUPPORTED_VERSION", stage);
  if (r.u8() !== DocumentType.AccountVault) throw new KavachError("UNSUPPORTED_TYPE", stage);
  const accountName = r.name();
  const accountKey = r.take(PUBLIC_KEY_BYTES);
  const vaultRevision = r.u64();
  if (accountName !== expectedName || !equalBytes(accountKey, expectedAccountKey) || vaultRevision === 0n) {
    throw new KavachError("VAULT_BINDING", stage);
  }
  const header = r.consumed();
  const nonce = r.take(NONCE_BYTES);
  const length = r.u32();
  if (length < MIN_VAULT_CIPHERTEXT || length > MAX_VAULT_CIPHERTEXT) throw new KavachError("SIZE_LIMIT", stage, "vault ciphertext length");
  const ciphertext = r.take(length);
  r.end();
  if (recoveryKey.length !== KEY_BYTES) throw new KavachError("INVALID_KEY", stage);
  const plain = aeadOpen(recoveryKey, nonce, concat(C("vault-aad"), header), ciphertext, stage);
  const contents = decodeVaultPlaintext(plain);
  if (!equalBytes(accountKeypair(contents.accountSeed).publicKey, accountKey)) throw new KavachError("VAULT_BINDING", stage, "seed does not derive AK");
  return { ...contents, header: { accountName, accountKey, vaultRevision } };
}

// Recovery code --------------------------------------------------------------------------------

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function base64url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0;
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    out += B64URL[a >> 2];
    out += B64URL[((a & 3) << 4) | ((b ?? 0) >> 4)];
    if (b !== undefined) out += B64URL[((b & 15) << 2) | ((c ?? 0) >> 6)];
    if (c !== undefined) out += B64URL[c & 63];
  }
  return out;
}

function unbase64url(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) return undefined;
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of text) {
    buffer = (buffer << 6) | B64URL.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** `"SS5R-" || base64url(recoveryKey)`, 48 characters, no padding. */
export function encodeRecoveryCode(recoveryKey: Uint8Array): string {
  if (recoveryKey.length !== KEY_BYTES) throw new KavachError("INVALID_KEY", "recoveryCode");
  return RECOVERY_CODE_PREFIX + base64url(recoveryKey);
}

export function decodeRecoveryCode(text: string): Uint8Array {
  const stage = "recoveryCode";
  if (!text.startsWith(RECOVERY_CODE_PREFIX)) throw malformed(stage, "prefix");
  const value = text.slice(RECOVERY_CODE_PREFIX.length);
  const raw = unbase64url(value);
  if (!raw || raw.length !== KEY_BYTES || base64url(raw) !== value) throw malformed(stage, "not a recovery key");
  return raw;
}
