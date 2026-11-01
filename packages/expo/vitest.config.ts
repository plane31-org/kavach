import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const core = fileURLToPath(new URL("../core/src/index.ts", import.meta.url));
const coreTesting = fileURLToPath(new URL("../core/src/testing/index.ts", import.meta.url));
const coreAdapters = fileURLToPath(new URL("../core/src/adapters/index.ts", import.meta.url));
const sodiumCjs = fileURLToPath(new URL("../core/node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js", import.meta.url));

export default defineConfig({
  resolve: { alias: { "@plane31/blind-relay/testing": coreTesting, "@plane31/blind-relay/adapters": coreAdapters, "@plane31/blind-relay": core, "libsodium-wrappers-sumo": sodiumCjs } },
  test: { include: ["test/**/*.test.ts"], environment: "node" }
});
