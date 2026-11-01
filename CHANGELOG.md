# Changelog

Package versions follow semver for the TypeScript API. The protocol revision is a wire fact, tracked in `spec/Kavach-v1.md`; a package version names the revision it implements.

## 0.1.1

First published versions of `@plane31/blind-relay` and `@plane31/blind-relay-expo`, implementing protocol revision 8. (0.1.0 was tagged but never reached the registry; its tag points at an earlier tree.)

- The SDK is product-agnostic. A product declares its record kinds in the retention policy (retention, queue mode, history, newest slot, header class) and keeps its payload codecs in its own profile; the SDK never parses a payload. One `enqueue(kind, payload, options)`, one `newest(identityId, kind)`, one `recordStored` event and one `refresh` event.
- Every record plaintext is an envelope (version, kind, event time) followed by the payload; the header shows the relay only the kind's declared class. The newest slot per author and kind orders by device generation, event time clamped to the send time, then (epoch, counter), on the reader and for the sender's own records alike.
- Durable outbox with an idempotency key answered before anything needs the network; a bounded, budgeted inbox with `hasMore`; per-stream errors in the sync report with the stream and author named; history served from a time-ordered index with stable cursors.
- Expo adapters: SecureStore secrets, SQLCipher store with a cross-process writer lock, foreground-only key provisioning, recovery providers, a trusted clock, and a Web Crypto install for Hermes.
- Conformance fixture regenerated for revision 8 and verified by the Python checker.
