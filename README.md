# Kavach

End-to-end encrypted location sharing and check-ins for circles of up to 100 accounts, through a server that stores only what it cannot open and deletes each record once every reader has it.

- `spec/Kavach-v1.md`: the protocol specification (Part I) and the Moyo implementation profile (Part II). Revision 4, wire version 5.
- `Kavach-v1-Build-Sequence.md`: the order in which this repository is built, one tested module at a time.
- `packages/core`: the protocol in pure TypeScript.
- `packages/expo`: Expo adapters.
- `examples/host-worker`: a reference host on Cloudflare Workers, not published.
- `spec/vectors.json`, `spec/verify_vectors.py`: the revision 4 conformance fixture and its checker; `spec/vectors-rev2/` is the unchanged SS5 revision 2 package it was regenerated from.

Status: step 0 of the build sequence is complete; step 1 (primitives and labels) is next. Nothing here is audited or production-ready.

```
pnpm install
pnpm typecheck && pnpm lint && pnpm test
scripts/vectors.sh
```
