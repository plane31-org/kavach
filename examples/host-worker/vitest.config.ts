import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";
import path from "node:path";

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, "migrations"));
  const core = path.join(__dirname, "../../packages/core/src/index.ts");
  const coreTesting = path.join(__dirname, "../../packages/core/src/testing/index.ts");
  const coreAdapters = path.join(__dirname, "../../packages/core/src/adapters/index.ts");
  return {
    resolve: { alias: { "@kavach/core/testing": coreTesting, "@kavach/core/adapters": coreAdapters, "@kavach/core": core } },
    test: {
      include: ["test/**/*.test.ts"],
      // Integration tests over workerd: the default 5 s is too tight on a loaded CI runner.
      testTimeout: 60_000,
      hookTimeout: 60_000,
      setupFiles: ["./test/applyMigrations.ts"],
      poolOptions: {
        workers: {
          wrangler: { configPath: "./wrangler.toml" },
          miniflare: {
            bindings: {
              TEST_MIGRATIONS: migrations,
              ALLOW_TEST_CLOCK: "true",
              // Deterministic test keys: management seed H(C("identity")), operational seed H(C("stream")), key id 07x16.
              RESET_OPERATIONAL_SEED: "79f078e6d85efaabd20a3d7951c4f3849f30ea3933701b5cd8b8db0b60748296",
              RESET_KEY_ID: "07070707070707070707070707070707",
              RESET_KEY_LIST: "050800000000000000010000018bcfe568000000018c6a6430000107070707070707070707070707070707b11d839572451509b96f045da961e17df501803298613cb6bd0e091e7d09927a50ced64a99aa6b5d387c812973cfb84d22d113ec5b55abde5ae9e71cc47f0310bbdc651028c27fef6daf380b3917d5f77fdef90b16346e3be12587a4d1d7ad03",
              TEST_MANAGEMENT_PUBLIC: "0c69abec36a0372735b51c52b457c10e20b4dd2e53184863cb4b62281c32a513"
            }
          }
        }
      }
    }
  };
});
