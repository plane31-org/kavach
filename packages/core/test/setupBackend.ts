/** KAVACH_CRYPTO=sodium runs the whole suite on the libsodium backend instead of the portable one. */
import { setCryptoBackend } from "../src/crypto/backend.js";

if (process.env["KAVACH_CRYPTO"] === "sodium") {
  const { loadSodiumBackend } = await import("../src/crypto/sodium.js");
  setCryptoBackend(await loadSodiumBackend());
}
