import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Hosts bundle core with esbuild (wrangler does). A dynamic import of a local module makes esbuild
// wrap every module reachable from it in a lazy `__esm` initializer while function declarations
// stay hoisted, so a host could call fromHex before bytes.js had initialized its constants and see
// every hex field rejected. Core therefore has to bundle flat: no lazy initializers at all.
describe("bundling", () => {
  it("core bundles without lazy module initializers", async () => {
    const result = await build({
      entryPoints: [fileURLToPath(new URL("../src/index.ts", import.meta.url))],
      bundle: true,
      write: false,
      format: "esm",
      platform: "neutral",
      packages: "external",
      logLevel: "silent"
    });
    const code = result.outputFiles[0]?.text ?? "";
    expect(code.length).toBeGreaterThan(0);
    expect(code).not.toMatch(/__esm\(/);
    expect(code).not.toMatch(/\bimport\(\s*["']\.\.?\//);
  });
});
