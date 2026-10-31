import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/dist/**", "**/node_modules/**", "**/.wrangler/**", ".venv/**"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    rules: {
      "no-console": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/explicit-module-boundary-types": "error"
    }
  },
  {
    // A dynamic import of a local module makes esbuild wrap every module reachable from it in a
    // lazy initializer, and a hoisted function can then run before its module's constants exist.
    // Hosts bundle core with esbuild (wrangler), so shipped code imports statically. The only
    // exception is the optional libsodium backend, an external package.
    files: ["packages/*/src/**/*.ts", "examples/*/src/**/*.ts"],
    ignores: ["packages/core/src/crypto/sodium.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        { selector: "ImportExpression", message: "Import statically: a dynamic import breaks module initialization order under esbuild." }
      ]
    }
  }
);
