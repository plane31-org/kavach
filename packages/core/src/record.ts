/**
 * Records: sealing with the active epoch, opening with certificate and manifest resolution
 * (protocol section 9).
 */
import { equalBytes, toHex } from "./bytes.js";
import {
  DocumentType,
  buildRecordWire,
  decodeEnvelope,
  decodeLocation,
  encodeLocation,
  expectType,
  openRecord as openRecordBody,
  parseDocument,
  verifyDocument,
  type EncryptedRecord,
  type HeaderClass,
  type Location,
  type LocationStatus,
  type Parsed,
  type RecordKind
} from "./codec.js";
import { NONCE_BYTES, randomBytes, recordId } from "./crypto.js";
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
  const stage = "openRecord";
  const parsed = expectType<EncryptedRecord>(parseDocument(wire), DocumentType.EncryptedRecord, stage);
  const cert = [...author.certificates.values()].find((c) => equalBytes(c.streamId, parsed.streamId));
  if (!cert) throw new KavachError("NOT_AUTHORIZED", stage, "record stream belongs to no known device of the author");
  const record = expectType<EncryptedRecord>(verifyDocument(wire, cert.signingKey), DocumentType.EncryptedRecord, stage);
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

// Location helpers -----------------------------------------------------------------------------

export { decodeLocation, encodeLocation };
export type { Location, LocationStatus };

/** Build a location payload from floating-point degrees and metres. */
export function locationFromDegrees(
  latitude: number,
  longitude: number,
  accuracyMetres: number,
  capturedAt: bigint,
  status: LocationStatus = 0
): Location {
  const e7 = (v: number): number => Math.round(v * 1e7);
  if (status === 2) return { latitudeE7: 0, longitudeE7: 0, accuracyMm: 0, capturedAt, status };
  return { latitudeE7: e7(latitude), longitudeE7: e7(longitude), accuracyMm: Math.round(accuracyMetres * 1000), capturedAt, status };
}

export function locationToDegrees(l: Location): { latitude: number; longitude: number; accuracyMetres: number } {
  return { latitude: l.latitudeE7 / 1e7, longitude: l.longitudeE7 / 1e7, accuracyMetres: l.accuracyMm / 1000 };
}

export function slotKey(streamId: Uint8Array, epoch: number, counter: number): string {
  return `${toHex(streamId)}:${epoch}:${counter}`;
}
