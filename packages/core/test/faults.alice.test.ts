/** Step 16: the crash sweep and the lost-response sweep with alice as the crashing process. */
import { beforeAll, describe, expect, it } from "vitest";
import { ready } from "../src/crypto.js";
import { crashSweep, lostResponseSweep } from "../src/testing/sweep.js";
import { memoryStores, sweepsEnabled } from "./faultStores.js";

beforeAll(() => ready());

describe.skipIf(!sweepsEnabled)("alice as the victim", () => {
  it("a crash before or after every transaction boundary is recovered by a restart", async () => {
    const result = await crashSweep({ stores: memoryStores(), victim: "alice" });
    expect(result.runs.length).toBe(result.boundaries * 2);
    expect(result.runs.every((r) => r.crashedDuring.length > 0)).toBe(true);
  }, 600_000);

  it("each mutation's response lost once after the host committed it", async () => {
    const runs = await lostResponseSweep(memoryStores(), "alice");
    expect(runs.filter((r) => r.exercised).length).toBeGreaterThan(2);
  }, 120_000);
});
