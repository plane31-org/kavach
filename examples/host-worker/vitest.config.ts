import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";
import path from "node:path";

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, "migrations"));
  const core = path.join(__dirname, "../../packages/core/src/index.ts");
  const coreTesting = path.join(__dirname, "../../packages/core/src/testing/index.ts");
  return {
    resolve: { alias: { "@kavach/core/testing": coreTesting, "@kavach/core": core } },
    test: {
      include: ["test/**/*.test.ts"],
      setupFiles: ["./test/applyMigrations.ts"],
      poolOptions: {
        workers: {
          wrangler: { configPath: "./wrangler.toml" },
          miniflare: { bindings: { TEST_MIGRATIONS: migrations } }
        }
      }
    }
  };
});
