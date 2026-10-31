import { describe, expect, it } from "vitest";
import { Reader, Writer, compareBytes, concat, encodeName, fromHex, isValidName, toHex, u16, u32, u64, u8 } from "../src/bytes.js";
import { isKavachError } from "../src/errors.js";

describe("fixed-width big-endian encoding", () => {
  it("writes u8, u16, u32 and u64 big-endian", () => {
    expect(toHex(u8(0xab))).toBe("ab");
    expect(toHex(u16(0x1234))).toBe("1234");
    expect(toHex(u32(0xdeadbeef))).toBe("deadbeef");
    expect(toHex(u64(1700000000000n))).toBe("0000018bcfe56800");
    expect(toHex(u64((1n << 64n) - 1n))).toBe("ffffffffffffffff");
  });

  it("refuses out-of-range values", () => {
    expect(() => u8(256)).toThrow(RangeError);
    expect(() => u32(-1)).toThrow(RangeError);
    expect(() => u64(1n << 64n)).toThrow(RangeError);
    expect(() => u64(-1n)).toThrow(RangeError);
  });

  it("round-trips through the reader with exact u64", () => {
    const wire = new Writer().u8(5).u16(100).u32(0xffffffff).u64(0xfedcba9876543210n).name("alice").finish();
    const r = new Reader(wire);
    expect(r.u8()).toBe(5);
    expect(r.u16()).toBe(100);
    expect(r.u32()).toBe(0xffffffff);
    expect(r.u64()).toBe(0xfedcba9876543210n);
    expect(r.name()).toBe("alice");
    expect(r.remaining).toBe(0);
    r.end();
  });

  it("refuses truncated input and trailing bytes as MALFORMED", () => {
    const r = new Reader(concat(u16(1)));
    expect(() => r.u32()).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    const t = new Reader(concat(u8(1), u8(2)));
    t.u8();
    try {
      t.end();
      throw new Error("accepted trailing byte");
    } catch (e) {
      expect(isKavachError(e, "MALFORMED")).toBe(true);
    }
  });
});

describe("B(name) and the name rule", () => {
  it("accepts 1 and 64 characters of the allowed set", () => {
    expect(isValidName("a")).toBe(true);
    expect(isValidName("A-z_09".padEnd(64, "x"))).toBe(true);
    expect(toHex(encodeName("alice"))).toBe("05616c696365");
  });

  it("rejects 0, 65, other characters and case folding", () => {
    expect(isValidName("")).toBe(false);
    expect(isValidName("x".repeat(65))).toBe(false);
    expect(isValidName("al ice")).toBe(false);
    expect(isValidName("alice!")).toBe(false);
    expect(isValidName("ålice")).toBe(false);
    expect(() => encodeName("bad!")).toThrow(expect.objectContaining({ code: "MALFORMED" }));
    expect(() => new Reader(fromHex("0121")).name()).toThrow(expect.objectContaining({ code: "MALFORMED" }));
  });
});

describe("byte order", () => {
  it("compares lexicographically", () => {
    expect(compareBytes(fromHex("00ff"), fromHex("0100"))).toBeLessThan(0);
    expect(compareBytes(fromHex("01"), fromHex("0100"))).toBeLessThan(0);
    expect(compareBytes(fromHex("ab"), fromHex("ab"))).toBe(0);
  });
});
