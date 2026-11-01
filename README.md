# Kavach

End-to-end encrypted, relayed, durable records between a person's devices and the devices of the people they share with, for circles of up to 100 accounts, through a server that stores only what it cannot open and deletes each record once every reader has it. The SDK is product-agnostic: a product declares its record kinds and keeps its payload codecs in its own profile.

- `spec/Kavach-v1.md`: the protocol specification, which names no product concept. Revision 8, wire version 5.
- `spec/Profile-template.md`: what an implementation profile must decide; a product keeps its profile in its own repository.
- `spec/amendments/`: proposed changes to the protocol under review, not adopted and not implemented. A1 is account replacement authorized by the host's signing authority.
- `Kavach-v1-Build-Sequence.md`: the order in which this repository is built, one tested module at a time.
- `packages/core`: the protocol in pure TypeScript.
- `packages/expo`: Expo adapters.
- `examples/host-worker`: a reference host on Cloudflare Workers, not published.
- `spec/vectors.json`, `spec/verify_vectors.py`: the conformance fixture (regenerated for revision 6: one negative moved, one negative and one status record added) and its checker; `spec/vectors-rev2/` is the unchanged SS5 revision 2 package it was regenerated from.

Status: steps 0 to 16 of the build sequence are complete: the core protocol, the Expo adapters, the reference host running the relay scenarios inside workerd, and the fault harness. The two native recovery bridges and the device tests of step 14, and the crash sweep on SQLCipher on a phone, wait for a development build. Step 17 (benchmarks) is next. Nothing here is audited or production-ready.

## Entry points of `@plane31/blind-relay`

The package has four entry points, each an explicit list of names; nothing else is importable from outside the package.

- `@plane31/blind-relay` is what an application imports: `open` and the `Client` type with its state, event, report and query types; `KavachError` and `ErrorCode`; the `Location` type with `locationFromDegrees`, `locationToDegrees` and the byte codec `encodeLocation` and `decodeLocation` for history plaintext; `RetentionPolicy` and `validatePolicy`, `ResetTrustConfig` and `setCryptoBackend` for the options of `open`; the `RecoveryProvider` contract with its result types and `encodeRecoveryCode` and `decodeRecoveryCode` for the code an app shows to the user; and `toHex`, `fromHex` and `equalBytes` for identifiers.
- `@plane31/blind-relay/adapters` is what an adapter or host author imports: the `Store`, `Tx`, `SecretStore`, `Transport`, `Directory`, `Relay` and `RecoveryProvider` contracts with the table and row types; `MemoryStore` and `MemorySecretStore` as the behavioural reference; the byte readers and writers; `ready`, `randomBytes` and the identifier derivations; the signed-document codec a host verifies with (`parseDocument`, `verifyDocument`, `expectType`, `DocumentType` and the document types); the reset-key list builder a host's signing script uses (`buildResetKeyList` with `buildResetReceipt`); and the transactions an adapter test drives against a store (`openStore`, `t1Secrets`, `t1Header`, `t1Activate`, `t3ApplyChange`).
- `@plane31/blind-relay/testing` is the fault harness described below, plus the fixtures a test builds protocol state with: `openAccount`, `newDevice`, `deviceFromSeed`, `certify`, `accountKeypair`, `identityId`, and `testResetKeys` with `testResetKeyList` for a signed key list.
- `@plane31/blind-relay/sodium` is the optional libsodium backend for Node.

The transaction helpers, row conversions, outbox, inbox, epoch, circle and audience modules are internal: they import each other by relative path and are not part of any entry point.

## Fault harness

`@plane31/blind-relay/testing` carries, besides the fake host, a `FaultyStore` that kills the simulated process before or after a chosen transaction, a `MaliciousTransport` that loses responses after the host committed, withholds, replays, forks and tampers with served documents and duplicates or reorders deliveries, and two sweeps. `crashSweep` runs one scenario (two accounts, a circle, locations both ways, check-ins, two concurrent contexts, a phone replacement) once to count a device's transaction boundaries, then once per boundary and phase with that device crashing there, restarting on the same durable state and finishing the scenario; after every run the durable-state outcomes of protocol section 11 are checked against the host (exact epoch and record bytes, no counter reuse, one activation, cursors never ahead of the host, delivery complete). `lostResponseSweep` does the same with each mutation's response lost once. `packages/core/test/faults.*.test.ts` run them on the in-memory store, `packages/expo/test/faults.sqlite.test.ts` on SQLite files, and `packages/core/test/malicious.test.ts` holds the malicious-transport cases and the lost-device scenario with the attacker holding the complete old-device state. The sweeps take about two minutes and run on the portable backend only.

```
pnpm install
pnpm typecheck && pnpm lint && pnpm test
scripts/vectors.sh
```
