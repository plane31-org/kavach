/**
 * The first profile's 22-byte location payload and the typed calls built on the generic API,
 * kept as a test helper (a copy of packages/core/test/location.ts): the fixture's record payload is one, and the scenarios need distinct
 * payloads with an event time. Nothing here ships; a product keeps its own codec in its profile.
 */
import { KavachError, type Client, type EnqueueOptions, type EnqueueResult, type Newest } from "@plane31/blind-relay";

export type LocationStatus = 0 | 1 | 2; // normal, stale, unavailable

export interface Location {
  readonly latitudeE7: number;
  readonly longitudeE7: number;
  readonly accuracyMm: number;
  readonly capturedAt: bigint;
  readonly status: LocationStatus;
}

const LOCATION_PAYLOAD_VERSION = 1;
export const LOCATION_PAYLOAD_BYTES = 22;

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
  const out = new Uint8Array(LOCATION_PAYLOAD_BYTES);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, LOCATION_PAYLOAD_VERSION);
  dv.setInt32(1, l.latitudeE7);
  dv.setInt32(5, l.longitudeE7);
  dv.setUint32(9, l.accuracyMm);
  dv.setBigUint64(13, l.capturedAt);
  dv.setUint8(21, l.status);
  return out;
}

export function decodeLocation(payload: Uint8Array): Location {
  const stage = "decodeLocation";
  if (payload.length !== LOCATION_PAYLOAD_BYTES) throw new KavachError("BAD_PAYLOAD", stage, "length");
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  if (dv.getUint8(0) !== LOCATION_PAYLOAD_VERSION) throw new KavachError("BAD_PAYLOAD", stage, "version");
  const l: Location = { latitudeE7: dv.getInt32(1), longitudeE7: dv.getInt32(5), accuracyMm: dv.getUint32(9), capturedAt: dv.getBigUint64(13), status: dv.getUint8(21) as LocationStatus };
  checkLocation(l, stage);
  return l;
}

export function locationFromDegrees(latitude: number, longitude: number, accuracyMetres: number, capturedAt: bigint, status: LocationStatus = 0): Location {
  const e7 = (v: number): number => Math.round(v * 1e7);
  if (status === 2) return { latitudeE7: 0, longitudeE7: 0, accuracyMm: 0, capturedAt, status };
  return { latitudeE7: e7(latitude), longitudeE7: e7(longitude), accuracyMm: Math.round(accuracyMetres * 1000), capturedAt, status };
}

export function locationToDegrees(l: Location): { latitude: number; longitude: number; accuracyMetres: number } {
  return { latitude: l.latitudeE7 / 1e7, longitude: l.longitudeE7 / 1e7, accuracyMetres: l.accuracyMm / 1000 };
}

// The typed calls of the first profile, on top of the generic API: kind 0 a location with its fix
// time as the event time, kind 1 an event (a location or any bytes), kind 2 a state.

export function enqueueLocation(client: Client, location: Location, options?: EnqueueOptions): Promise<EnqueueResult> {
  return client.enqueue(0, encodeLocation(location), { eventTime: location.capturedAt, ...options });
}

export function enqueueCheckIn(client: Client, payload: Location | Uint8Array, options?: EnqueueOptions): Promise<EnqueueResult> {
  return payload instanceof Uint8Array ? client.enqueue(1, payload, options) : client.enqueue(1, encodeLocation(payload), { eventTime: payload.capturedAt, ...options });
}

export function enqueueStatus(client: Client, payload: Uint8Array, options?: EnqueueOptions): Promise<EnqueueResult> {
  return client.enqueue(2, payload, options);
}

export function latest(client: Client, identityId: Uint8Array): Promise<Newest | undefined> {
  return client.newest(identityId, 0);
}

export function latestStatus(client: Client, identityId: Uint8Array): Promise<Newest | undefined> {
  return client.newest(identityId, 2);
}
