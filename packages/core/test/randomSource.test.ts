/**
 * The portable backend reads the random source when bytes are needed, not when the module was
 * imported: on Hermes the source is installed after import (by the Expo helper), and a source
 * captured at import time would be missing for the life of the process.
 */
import { afterEach, describe, expect, it } from "vitest";
import { randomBytes, ready, sealBox } from "../src/crypto.js";
import { nobleBackend } from "../src/crypto/noble.js";

// Node defines `globalThis.crypto` with a getter only; it is replaced through its descriptor.
const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
const setCrypto = (value: { getRandomValues?: (a: Uint8Array) => Uint8Array } | undefined): void => {
  Object.defineProperty(globalThis, "crypto", { value, configurable: true, writable: true });
};

afterEach(() => {
  if (original) Object.defineProperty(globalThis, "crypto", original);
});

describe("the random source", () => {
  it("is read at call time: a source installed after import is used, and its absence is a clear error", async () => {
    await ready();
    setCrypto(undefined);
    expect(() => randomBytes(16)).toThrow(/install a secure random source/);
    let calls = 0;
    setCrypto({
      getRandomValues: (a: Uint8Array) => {
        calls++;
        for (let i = 0; i < a.length; i++) a[i] = (i * 7 + 3) & 0xff;
        return a;
      }
    });
    const bytes = randomBytes(8);
    expect([calls, [...bytes]]).toEqual([1, [3, 10, 17, 24, 31, 38, 45, 52]]);
    // The sealed-box ephemeral key, drawn inside the backend, goes through the same path.
    const sealed = sealBox(new Uint8Array(32), nobleBackend.boxKeypairFromSeed(new Uint8Array(32).fill(5)).publicKey);
    expect([sealed.length, calls]).toEqual([80, 2]);
  });
});
