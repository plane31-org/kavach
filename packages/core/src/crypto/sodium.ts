/**
 * The libsodium backend (wasm). Loaded only when asked for, so the default bundle never carries
 * the wasm; use it on Node, where it is faster than the portable backend, and to cross-check it.
 */
import { createRequire } from "node:module";
import type { CryptoBackend } from "./backend.js";
import { sodiumBackend, type SodiumLike } from "./sodiumLike.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

/**
 * Node only. The wrapper is loaded through its `require` condition, the CommonJS build, which is
 * self-contained; its ESM build has shipped broken (0.7.16 imports a sibling file the package does
 * not contain), and a consumer's plain `import` would hit that. The release smoke test loads this
 * entry from the packed tarball in a clean Node to keep it so.
 */
export async function loadSodiumBackend(): Promise<CryptoBackend> {
  const require = createRequire(import.meta.url);
  const mod = require("libsodium-wrappers-sumo") as { default?: Sodium } & Sodium;
  const sodium: Sodium = mod.default ?? mod;
  await sodium.ready;
  // The typed wrapper's overloads (output formats) do not match the structural interface; the calls made are the Uint8Array ones.
  return sodiumBackend(sodium as unknown as SodiumLike);
}
