import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// The ESM entry of libsodium-wrappers-sumo expects a sibling file that pnpm does not place next
// to it. The CommonJS build is self-contained and is what React Native loads too, so tests use it.
const sodiumCjs = fileURLToPath(
  new URL("./node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js", import.meta.url)
);

export default defineConfig({
  resolve: { alias: { "libsodium-wrappers-sumo": sodiumCjs } },
  test: { include: ["test/**/*.test.ts"], environment: "node" }
});
