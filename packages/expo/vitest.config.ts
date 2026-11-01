import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const core = fileURLToPath(new URL("../core/src/index.ts", import.meta.url));
const coreTesting = fileURLToPath(new URL("../core/src/testing/index.ts", import.meta.url));
const coreAdapters = fileURLToPath(new URL("../core/src/adapters/index.ts", import.meta.url));
const sodiumCjs = fileURLToPath(new URL("../core/node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js", import.meta.url));

export default defineConfig({
  resolve: { alias: { "@blind-relay/core/testing": coreTesting, "@blind-relay/core/adapters": coreAdapters, "@blind-relay/core": core, "libsodium-wrappers-sumo": sodiumCjs } },
  test: { include: ["test/**/*.test.ts"], environment: "node" }
});
