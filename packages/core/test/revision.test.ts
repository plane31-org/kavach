/** The exported revision is the specification's: the two cannot drift apart. */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PROTOCOL_REVISION } from "../src/index.js";

describe("PROTOCOL_REVISION", () => {
  it("matches the specification header", () => {
    const spec = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../../spec/Kavach-v1.md"), "utf8");
    const m = /Kavach v1, protocol revision (\d+),/.exec(spec);
    expect(m && Number(m[1])).toBe(PROTOCOL_REVISION);
  });
});
