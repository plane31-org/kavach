# SealedStream SS5 implementation companion

The accompanying 36-page PDF is the single normative specification. Pages 1-6 are an informative overview; pages 7-25 define implementation rules; pages 26-36 provide vectors and reproduction notes. IMPLEMENTATION.md matches normative sections 1-19. The PDF takes precedence if copies diverge.

SS5 revision 2 supersedes SS5 revision 1 and the earlier SS4 draft. Account identity survives a phone change, so Circle membership and ownership remain unchanged. Each replacement phone gets fresh device keys and a fresh stream. It first uses platform recovery, then the old phone or a saved recovery code to recover account identity/control state, never location history. Joining a Circle requires only the owner's approval of the requesting account. No owner reapproval is needed for phone replacement.

Existing phones retain movement trails, older history and durable check-ins according to a required Moyo retention configuration. The map has a separate latest-location projection. Replacement phones need not recover prior-device history. Android Block Store and Apple synced Keychain are the first recovery paths; unsupported/unavailable devices fall back to transfer or code. Android cloud restore must pass real-device release tests. An explicit destructive reset requires an operational authority receipt verified against a fresh management-signed key list, closes old-owned Circles and requires re-admission of the new identity.

## Files

- `vectors.json`: full frozen inputs and expected bytes, negative cases, state decisions, 100-account boundary fixtures, storage encryption, phone replacement and encrypted recovery.
- `verify_vectors.py`: runnable reference codec and small in-memory state model, NOT a production SDK.
- `requirements.txt`: versions used for verification.
- `verification-report.json`: scope, runtime versions and file checksums.
- `IMPLEMENTATION.md`: source of the normative rules, excluding the overview and printed vector appendix.

The PDF also embeds vectors.json, verify_vectors.py, requirements.txt and this README. Some viewers do not expose attachments; this ZIP is the convenient standalone package.

## Reproduce

Use Python 3.12 or later from this directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python verify_vectors.py
```

On Windows use `.venv\Scripts\python`. Default mode regenerates in memory and compares exact bytes/results with the frozen JSON. `--generate` rewrites expected outputs and is reserved for reviewed specification changes.

Every private value here is PUBLIC TEST MATERIAL, including recovery keys and transfer tokens. Never import these into a real account or production SDK.

## Verified scope

Revision 2 adds type 8 ResetKeyList without altering types 1-7. It adds 22 deterministic cases for operational-key rotation/revocation, rollback, expiry, clock failure, re-attestation and immutable reset bindings. Deploy revision 2 to all reset-verifying clients before relying on these protections. The offline management signing process must publish a new list at least daily. An unexpired list can delay revocation up to 24 hours under the stated clock assumption.

- Six core signed documents and two core sealed boxes.
- Full 100-account certificates, membership snapshot, device-bound manifest, 100 opened wraps and maximum-size record.
- Encrypted storage row, 19 negative byte vectors, three wrap/key checks and 17 state-model cases, including live-pin ordering and retaining queued records.
- Phone replacement preserves account identity, membership and owner signing authority, starts a fresh stream, rejects old-device access to new wraps and recognizes superseded author certificates.
- Validly signed device substitution, generation rollback and equal-generation conflicts are rejected.
- Account vault recovery, wrong-key rejection, zero-Circle and pending-join vaults, canonical recovery code and pinned transfer token.
- Independent Ed25519/X25519 checks through OpenSSL and XChaCha20-Poly1305 checks through PyCryptodome. Sealed-box construction/opening both use libsodium; that is not a separate-backend comparison.

The package does not implement mobile storage, native locking, authentication or a relay. It does not establish mobile crash durability, performance or an independent security audit. See PDF sections 14, 18 and 19 for those release gates.

Normal recovery tries the platform provider, old-phone transfer and saved recovery code. Destructive reset is a separate explicitly confirmed path; it never occurs automatically. Cloud recovery, reset-authority operations and actual durable storage still require integration tests. The fixtures additionally cover check-ins surviving later locations and an authority-signed account reset.
