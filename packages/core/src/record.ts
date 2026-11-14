/**
 * Records: sealing with the active epoch, opening with certificate and manifest resolution
 * (protocol section 9).
 */
import { equalBytes, toHex } from "./bytes.js";
import {
  DocumentType,
  LABEL_BY_TYPE,
  buildRecordWire,
  decodeEnvelope,
  expectType,
  openRecord as openRecordBody,
  parseDocument,
  type EncryptedRecord,
  type HeaderClass,
  type Parsed,
  type RecordKind
} from "./codec.js";
import { NONCE_BYTES, randomBytes, recordId, verify } from "./crypto.js";
import type { AuthorView } from "./epoch.js";
import { MAX_COUNTER } from "./epoch.js";
import { KavachError } from "./errors.js";

export interface SealedRecord {
  readonly wire: Uint8Array;
  readonly recordId: Uint8Array;
  readonly counter: number;
  readonly kind: RecordKind;
}

/** Seal one record under the active epoch. The caller persists the result and the next counter (T6). */
export function sealRecord(input: {
  readonly streamId: Uint8Array;
  readonly epoch: number;
  readonly nextCounter: number;
  readonly kind: RecordKind;
  /** The product's event time for the record, carried in the envelope; absent when the kind has none. */
  readonly eventTime?: bigint | undefined;
  /** The declared header class of the kind, the one thing the relay sees of it. */
  readonly headerClass: HeaderClass;
  readonly payload: Uint8Array;
  readonly sentAt: bigint;
  readonly epochKey: Uint8Array;
  readonly signingSecretKey: Uint8Array;
  readonly nonce?: Uint8Array;
}): SealedRecord {
  if (input.nextCounter > MAX_COUNTER) throw new KavachError("COUNTER_EXHAUSTED", "sealRecord");
  const nonce = input.nonce ?? randomBytes(NONCE_BYTES);
  const wire = buildRecordWire(
    { streamId: input.streamId, epoch: input.epoch, counter: input.nextCounter, sentAt: input.sentAt, headerClass: input.headerClass, kind: input.kind, eventTime: input.eventTime },
    input.payload,
    input.epochKey,
    nonce,
    input.signingSecretKey
  );
  return { wire, recordId: recordId(input.streamId, input.epoch, input.nextCounter), counter: input.nextCounter, kind: input.kind };
}

export interface OpenedRecord {
  readonly record: Parsed<EncryptedRecord>;
  readonly recordId: Uint8Array;
  /** From the envelope: the kind, the event time if the sender gave one, and the payload. */
  readonly kind: RecordKind;
  readonly eventTime: bigint | undefined;
  readonly payload: Uint8Array;
  /** The record comes from a device of the author that is no longer current: history only. */
  readonly superseded: boolean;
}

/**
 * Verify and open a record. The author view supplies the certificate for the record's stream
 * (the current one, or an archived one for history); `epochKeyFor` returns the stored key for
 * (stream, epoch) or `undefined`, which is `KEY_PENDING`.
 */
export function openRecordWire(
  wire: Uint8Array,
  author: AuthorView,
  epochKeyFor: (streamId: Uint8Array, epoch: number) => Uint8Array | undefined
): OpenedRecord {
  return openParsedRecord(expectType<EncryptedRecord>(parseDocument(wire), DocumentType.EncryptedRecord, "openRecord"), author, epochKeyFor);
}

/**
 * The same opening from a record already parsed (the inbox parses once to route it): the stream's
 * certificate, the signature over the parsed body under that certificate's key, then the key and
 * the envelope. Verification before decryption, as in `verifyDocument`; the parse is not repeated
 * and the body hash is the one the parse computed. Internal to the package.
 */
export function openParsedRecord(
  record: Parsed<EncryptedRecord>,
  author: AuthorView,
  epochKeyFor: (streamId: Uint8Array, epoch: number) => Uint8Array | undefined
): OpenedRecord {
  const stage = "openRecord";
  const cert = [...author.certificates.values()].find((c) => equalBytes(c.streamId, record.streamId));
  if (!cert) throw new KavachError("NOT_AUTHORIZED", stage, "record stream belongs to no known device of the author");
  const label = LABEL_BY_TYPE[record.type];
  if (!label) throw new KavachError("UNSUPPORTED_TYPE", stage);
  verify(cert.signingKey, label, record.body, record.signature, stage);
  const key = epochKeyFor(record.streamId, record.epoch);
  if (!key) throw new KavachError("KEY_PENDING", stage, `no key for epoch ${record.epoch}`);
  const envelope = decodeEnvelope(openRecordBody(record, key));
  return { record, recordId: recordId(record.streamId, record.epoch, record.counter), kind: envelope.kind, eventTime: envelope.eventTime, payload: envelope.payload, superseded: !cert.current };
}

/** (generation, epoch, counter) ordering for the live pin. */
export interface PinSlot {
  readonly generation: bigint;
  readonly epoch: number;
  readonly counter: number;
}

export function compareSlots(a: PinSlot, b: PinSlot): number {
  if (a.generation !== b.generation) return a.generation < b.generation ? -1 : 1;
  if (a.epoch !== b.epoch) return a.epoch - b.epoch;
  return a.counter - b.counter;
}

export function slotKey(streamId: Uint8Array, epoch: number, counter: number): string {
  return `${toHex(streamId)}:${epoch}:${counter}`;
}
