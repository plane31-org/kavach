#!/usr/bin/env bash
# Pack both packages, install the tarballs into an empty directory with a plain npm, and import
# every public entry point in a plain Node: what a consumer gets, not what the workspace resolves.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# pnpm pack, not npm pack: it rewrites the workspace dependency to the real version, as publish does.
(cd "$root/packages/core" && pnpm pack --pack-destination "$work" >/dev/null)
(cd "$root/packages/expo" && pnpm pack --pack-destination "$work" >/dev/null)
cd "$work"
npm init -y >/dev/null
# Both tarballs in one install, so the Expo package's dependency on core is met by the local core.
npm install --loglevel=error --no-audit --no-fund ./plane31-blind-relay-[0-9]*.tgz ./plane31-blind-relay-expo-[0-9]*.tgz
cat > smoke.mjs <<'JS'
const core = await import("@plane31/blind-relay");
const adapters = await import("@plane31/blind-relay/adapters");
const testing = await import("@plane31/blind-relay/testing");
const sodium = await import("@plane31/blind-relay/sodium");
const expo = await import("@plane31/blind-relay-expo");
const must = (ok, what) => { if (!ok) throw new Error("smoke: " + what); };
must(typeof core.open === "function" && core.PROTOCOL_REVISION >= 8, "core entry");
must(typeof adapters.MemoryStore === "function" && typeof adapters.buildResetKeyList === "function", "adapters entry");
must(typeof testing.FakeHost === "function", "testing entry");
const backend = await sodium.loadSodiumBackend();
must(backend.name === "sodium" && backend.randomBytes(8).length === 8, "sodium backend loads and runs");
must(typeof expo.openKavach === "function" && typeof expo.SqliteStore === "function", "expo entry");
core.validatePolicy({ version: 1, replacement: "continuity", deliveryWindowMs: 1n, appendRetryWindowMs: 1n, hygieneRotationMs: 1n, maxOutboxRecords: 1, maxOutboxBytes: 1, kinds: [{ kind: 0, retentionMs: 1n, queue: "keepAll", history: true, newest: true }] });
try { core.validatePolicy({}); must(false, "policy validation"); } catch (e) { must(e.code === "MALFORMED", "error code"); }
const { existsSync } = await import("node:fs");
must(existsSync(new URL("./node_modules/@plane31/blind-relay/src/index.ts", import.meta.url)), "sources ship with the maps");
console.log("smoke: core, adapters, testing, sodium, expo entries load from the packed tarballs");
JS
node smoke.mjs
