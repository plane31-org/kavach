import { describe, expect, it } from "vitest";
import { LABEL_PREFIX, PROTOCOL_REVISION, WIRE_VERSION } from "../src/index.js";

describe("constants", () => {
  it("pins the wire version and label prefix", () => {
    expect(WIRE_VERSION).toBe(5);
    expect(PROTOCOL_REVISION).toBe(4);
    expect(LABEL_PREFIX).toBe("SealedStream/5/");
  });
});
