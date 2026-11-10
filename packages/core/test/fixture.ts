import { readFileSync } from "node:fs";
import { fromHex } from "../src/bytes.js";

export interface Identity {
  account: string;
  account_public: string;
  device_sign_seed: string;
  device_sign_public: string;
  device_box_seed: string;
  device_box_public: string;
  device_box_secret: string;
  identity_id: string;
  device_id: string;
  generation: number;
  certificate_hash: string;
  stream_id: string;
}

export interface Fixture {
  profile: string;
  inputs: Record<string, string | number>;
  identities: Identity[];
  documents: Record<string, { wire: string; body_hash: string; signature: string; verification_key: string }>;
  wraps: { recipient_identity: string; ephemeral_seed: string; ephemeral_public: string; nonce: string; sealed_box: string; wrap_hash: string }[];
  record: { plaintext: string; aad: string; ciphertext_and_tag: string; record_id: string };
  negative_vectors: { name: string; wire: string; verification_key: string; operation: string; expected: string }[];
  phone_replacement: { new_device_seed: string; new_device_id: string; stable_identity_id: string; new_certificate: string };
  boundary_100: { seed_rule: string; accounts: string[] };
  status_record: { wire: string; record_id: string; epoch_key: string; payload: string; expected: { kind: number; flags: number; epoch: number; counter: number; pins: boolean; notifies: boolean } };
  /** Revision 11: a header class above 3 (bits 1 to 3). */
  wide_class_record: { wire: string; record_id: string; epoch_key: string; payload: string; expected: { kind: number; header_class: number; flags: number; epoch: number; counter: number } };
}

export const fixture: Fixture = JSON.parse(
  readFileSync(new URL("../../../spec/vectors.json", import.meta.url), "utf8")
) as Fixture;

export const hex = fromHex;
export const str = (s: string | number): string => String(s);
