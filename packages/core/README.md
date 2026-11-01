# @plane31/blind-relay

The Kavach v1 protocol in pure TypeScript: end-to-end encrypted, relayed, durable records between a person's devices and the devices of the people they share with, for circles of up to 100 accounts, through a server that stores only what it cannot open and deletes each record once every reader has it. The package is product-agnostic: a product declares its record kinds and keeps its payload codecs in its own profile. The specification is `spec/Kavach-v1.md` in the repository; `spec/Profile-template.md` lists what a product decides.

Status: protocol revision 8, package 0.x. The primitives are audited libraries; the composition is not yet independently reviewed, and nothing here is production-ready. The API may change between 0.x minor versions; the protocol revision is tracked separately in the specification.

```
pnpm add @plane31/blind-relay
```

## Entry points

- `@plane31/blind-relay`: `open` and the `Client` with `enqueue`, `newest`, `historyPage`, `sync`, the circles API, `subscribe` and `inspect`; the `KindDeclaration` and `RetentionPolicy` a product passes to `open`; `KavachError` and `ErrorCode`; the `RecoveryProvider` contract; `toHex`, `fromHex` and `equalBytes`.
- `@plane31/blind-relay/adapters`: the `Store`, `Tx`, `SecretStore`, `Transport`, `Directory` and `Relay` contracts an adapter or host implements, with the table and row types; `MemoryStore` and `MemorySecretStore` as the behavioural reference; the signed-document codec a host verifies with; `buildResetKeyList` and `buildResetReceipt` for a host's key tooling.
- `@plane31/blind-relay/testing`: the fault harness (a fake host, a crashing store, a malicious transport, the crash and lost-response sweeps) and the fixtures a test builds protocol state with.
- `@plane31/blind-relay/sodium`: the optional libsodium backend for Node; the default backend is portable JavaScript, which is what Hermes needs.

Randomness comes from the Web Crypto global. A runtime without one (Hermes) installs it first; `@plane31/blind-relay-expo` does that from `expo-crypto`.

## Development

```
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

The test suite runs under both cipher-suite backends and against the frozen conformance vectors. Apache-2.0.
