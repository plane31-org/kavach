/**
 * Fixed-width big-endian encoding, protocol section 3.
 * u64 values are BigInt end to end; nothing is ever rounded through a double.
 */
import { KavachError } from "./errors.js";

export const MAX_DOCUMENT_BYTES = 16_384;
export const MAX_PAYLOAD_BYTES = 4_096;
const U32_MAX = 0xffff_ffff;
const U64_MAX = (1n << 64n) - 1n;
const NAME_RULE = /^[A-Za-z0-9_-]{1,64}$/;

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function u8(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new RangeError("u8 out of range");
  return Uint8Array.of(value);
}

export function u16(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new RangeError("u16 out of range");
  return Uint8Array.of(value >>> 8, value & 0xff);
}

export function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX) throw new RangeError("u32 out of range");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function u64(value: bigint): Uint8Array {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) throw new RangeError("u64 out of range");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

export function i32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < -0x8000_0000 || value > 0x7fff_ffff) throw new RangeError("i32 out of range");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setInt32(0, value, false);
  return out;
}

/** The `accountName` rule: 1 to 64 ASCII letters, digits, underscore or hyphen, case-sensitive. */
export function isValidName(name: string): boolean {
  return NAME_RULE.test(name);
}

/** `B(name)`: u8 byte length followed by the ASCII bytes. */
export function encodeName(name: string): Uint8Array {
  if (!isValidName(name)) throw new KavachError("MALFORMED", "encodeName", "account name violates the name rule");
  const bytes = new Uint8Array(name.length);
  for (let i = 0; i < name.length; i++) bytes[i] = name.charCodeAt(i);
  return concat(u8(bytes.length), bytes);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export function isAllZero(bytes: Uint8Array): boolean {
  let acc = 0;
  for (const b of bytes) acc |= b;
  return acc === 0;
}

const HEX = /^[0-9a-f]*$/i;

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !HEX.test(hex)) throw new RangeError("bad hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Compare two byte strings lexicographically, as the strict sort orders in section 3 require. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * A bounded reader. Every take is checked against the end; `end()` refuses trailing bytes.
 * All failures are `MALFORMED`, which is what the codec reports before any cryptography.
 */
export class Reader {
  private offset = 0;

  constructor(
    private readonly data: Uint8Array,
    private readonly stage = "parse"
  ) {}

  get position(): number {
    return this.offset;
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }

  take(n: number): Uint8Array {
    if (!Number.isInteger(n) || n < 0 || this.offset + n > this.data.length) {
      throw new KavachError("MALFORMED", this.stage, "truncated");
    }
    const out = this.data.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  u8(): number {
    return this.take(1)[0] ?? 0;
  }

  u16(): number {
    const b = this.take(2);
    return ((b[0] ?? 0) << 8) | (b[1] ?? 0);
  }

  u32(): number {
    const b = this.take(4);
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, false);
  }

  u64(): bigint {
    const b = this.take(8);
    return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, false);
  }

  i32(): number {
    const b = this.take(4);
    return new DataView(b.buffer, b.byteOffset, 4).getInt32(0, false);
  }

  /** `B(name)`, enforcing the name rule. */
  name(): string {
    const n = this.u8();
    const bytes = this.take(n);
    let text = "";
    for (const b of bytes) text += String.fromCharCode(b);
    if (!isValidName(text)) throw new KavachError("MALFORMED", this.stage, "bad account name");
    return text;
  }

  /** The bytes consumed so far, for AAD and body hashing. */
  consumed(): Uint8Array {
    return this.data.slice(0, this.offset);
  }

  end(): void {
    if (this.offset !== this.data.length) throw new KavachError("MALFORMED", this.stage, "trailing bytes");
  }
}

/** An append-only writer for building bodies. */
export class Writer {
  private readonly parts: Uint8Array[] = [];

  bytes(value: Uint8Array): this {
    this.parts.push(value);
    return this;
  }
  u8(value: number): this {
    return this.bytes(u8(value));
  }
  u16(value: number): this {
    return this.bytes(u16(value));
  }
  u32(value: number): this {
    return this.bytes(u32(value));
  }
  u64(value: bigint): this {
    return this.bytes(u64(value));
  }
  i32(value: number): this {
    return this.bytes(i32(value));
  }
  name(value: string): this {
    return this.bytes(encodeName(value));
  }
  finish(): Uint8Array {
    return concat(...this.parts);
  }
}
