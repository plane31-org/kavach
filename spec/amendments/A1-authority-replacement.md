# Amendment A1: account replacement authorized by the host's signing authority

Status: **draft for review, not adopted**. Nothing in the SDK, the hosts or the fixture implements it. It proposes protocol revision 9 on wire version 5. Section numbers refer to `spec/Kavach-v1.md` at revision 8. Where this document and the specification disagree today, the specification wins; if the amendment is adopted, its text replaces the sections it names.

## 0. What this changes, in one paragraph

Today a replacement device proves it is the same account by holding the account key, recovered through the platform's synced secret store or the recovery code (section 4, "Replacing the device"). This amendment adds a second way: a new device with **no secret from the old one** generates fresh account and device keys, and the host's signing authority, after the product's fresh authentication, signs a **succession** that binds the account to the new keys. Peers verify the succession and rotate, exactly as they do for a device change today; nobody approves anything; circle ids, membership, pending joins, ownership and closures are unchanged; the old device is fenced; the new device receives no historical keys. The price is stated in section 6 and is the reason this is a decision and not a patch: an authority that can sign successions can bind any account to keys of its choosing.

## 1. Decisions this amendment needs before adoption

| # | Decision | Recommendation |
| --- | --- | --- |
| D1 | Accept that the host's authority may rebind an account's keys (section 6) | Accept only with the three conditions in 6.2: a mandatory peer signal, a custodied authority key with fresh authentication enforced before signing, and an appendable succession log |
| D2 | Keep host-independent identity continuity (the current section 4) alongside convenient account recovery | Keep both; a profile enables either or both, and the choice is enforced by every verifying peer (section 2a). Neither is legacy: they are two promises, and a product that can rely on the platform's synced secret store keeps the stronger one |
| D3 | Where a circle's sharing preference lives when the vault is unavailable | A host-held, authenticated flag per (account, circle), written by the client on enable and disable and returned by discovery; absent means disabled |
| D4 | Whether the vault and the recovery provider remain | Optional per profile. A succession may start a fresh vault so that later identity-continuity replacements work; a profile that enables only convenient account recovery needs neither |
| D5 | The stale-record policy of the original proposal (section 10 there) | Out of this amendment; a separate proposal with its own data-loss decision |

## 2. Identity model

### 2a. The two replacement models

| Model | How the new device proves it is the account | Who must be trusted | Name in this document |
| --- | --- | --- | --- |
| **Host-independent identity continuity** | It holds the account key, recovered through the platform's synced secret store or the recovery code (section 4, "Replacing the device", unchanged) | Nobody beyond first contact: the host cannot rebind a key | identity continuity |
| **Convenient account recovery** | It holds nothing; the host's authority signs a succession after the product's fresh authentication (sections 3 and 4 below) | The host's signing authority, for every account, for all future traffic | account recovery |

A profile declares which models it enables: `replacement: "continuity" | "recovery" | "both"`. The declaration is a property of the app build, decided by the product and never by a user: it is compiled into every client, it has no runtime setter, no per-account form and no server-delivered value, and it changes only by shipping a new app version, as the pinned management key does. What a user ever sees is the consequence (what a replacement asks of them, and the notice when a contact's key changes), never a choice. **The declaration is enforced by the peers who verify, not only by the device being replaced.** A client whose profile does not enable account recovery rejects every type 9 document as `UNSUPPORTED_TYPE`, whoever signed it, keeps the account's key quarantined as `ACCOUNT_KEY_CHANGED` exactly as it does today for a bare directory key change, and ignores the chain the directory attaches. That is what makes identity continuity host-independent in fact: on such a deployment a host that tries to rebind a key obtains nothing from any client. A client that enables account recovery verifies successions by section 3. A product that enables both has the convenience of both and the guarantee of account recovery, since every account on it can be rebound by the host; its profile states the enabled models and the resulting promise in one sentence, so nobody reads the stronger guarantee into a deployment that allows the weaker model.


The protocol gains one definition and changes none on the wire.

- **`accountId`** is the `identityId` an account had at enrollment: `H(C("identity") || B(accountName) || AK₀)`, where `AK₀` is its first account key. It never changes. Every document that names an account keeps naming it by `accountId`: the owner and members of a snapshot (type 2), the author and rows of a manifest (type 3), the vault header's binding, and the old identity of a reset receipt (type 7).
- **`identityId`** keeps its definition, `H(C("identity") || B(accountName) || AK)`, and is now the identity of the account's **current key**. For an account never replaced by authority, `accountId = identityId`, which is every account that exists today.
- A **succession chain** for an account is the ordered list of verified successions from `accountId` to its current `identityId`. Resolving an account means following its chain to the current key and certificate. The chain is empty for an account that has never succeeded.
- `deviceGeneration` is the **account version**. It is already monotonic per account and already advances by exactly one at every activation under compare-and-swap on the host. A succession advances it by one, like a device change under the same key. There is no second version counter.

Consequences for existing rules:

- Section 4, "First contact and pinning": a different `AK` for a pinned account remains `ACCOUNT_KEY_CHANGED` and remains quarantined, until either a reset receipt (section 12, as today) or a verified succession (section 4 below) is processed. The rule "never on an unsigned directory change" stands.
- Section 6, snapshots: members and the owner are account ids. "Resolving members MUST reject two different account keys for one account name" becomes "two different current keys for one account id". A member's succession never changes a snapshot; the owner does not republish for it.
- Section 7, audience: an audience entry is (`accountId`, `certificateHash`, `DEK.public`) for the account's current device under its current key, found through the chain. Deduplication and the 100-recipient limit are by account id, as today. A changed key with a verified succession is a rotation trigger (an accepted recipient key change), not a security error.
- Section 8, manifests: `authorIdentityId` and `recipientIdentityId` are account ids. The reader verifies the author's certificate under the author's **current** `AK`, found through the chain, and checks that the certificate's derived identity is the chain's current identity and its stream id matches. The reader's own row must name the reader's account id and its current certificate hash.
- The relay keys streams by `streamId`, which already changes with every device; nothing in section 10 changes.

## 3. The succession document

A new signed document, type 9, label `succession-sig`, signed by an operational key allowed by the current reset-key list (section 12). It is distinct from the reset receipt: a receipt retires an identity and closes what it owned; a succession continues everything.

```
body = u8(5) || u8(9) || B(accountName) || accountId[32]
       || previousIdentityId[32] || newIdentityId[32]
       || previousGeneration:u64 || newGeneration:u64
       || newCertificateHash[32] || successionId[16] || issuedAt:u64 || authorityKeyId[16]
wire = body || Ed25519(authorityKey, C("succession-sig") || body)
```

Rules: `newGeneration = previousGeneration + 1`; previous and new identity differ; `successionId` is random, 16 bytes, nonzero, and unique per account; `issuedAt` is diagnostic. Wire length is 283 bytes plus the name length.

**Verification by a peer**, for an unseen succession of account `accountId`:

1. A fresh reset-key list (section 12 rules, including `RESET_KEYS_REQUIRED` and `RESET_CLOCK_UNTRUSTED`), an allowed `authorityKeyId`, a valid signature under that key.
2. `accountName` and `accountId` match the local pin for that account.
3. `previousIdentityId` and `previousGeneration` equal the account's current pinned identity and generation. A lower generation is `ROLLBACK`. An equal generation with a different body is `EQUIVOCATION`, which quarantines the account: it means the authority signed two successors for one state.
4. A verified type 1 certificate whose body hash is `newCertificateHash`, signed by the new `AK`, carrying `accountName`, `deviceGeneration = newGeneration`, a new `deviceId`, and whose derived identity is `newIdentityId` (`SUCCESSION_BINDING` otherwise, a new code in the trust family).
5. The previous identity is not already retired by a reset receipt or an earlier succession (`SUPERSEDED_IDENTITY`).

On acceptance, in one transaction: pin the new `AK`, identity, generation and certificate hash for the account; retire the previous identity (its certificates verify nothing new; its stream is history only); increment `desiredRevision` (section 7); record the succession hash and the immutable (`successionId`, `accountId`, previous, new) binding, so a duplicate is a no-op and a conflicting binding for a known id is rejected. After commit, emit **`accountKeyChanged { accountId, accountName, reason: "succession", generation }`**. This event is not optional and the client never suppresses it; what the product shows is the product's decision (section 6).

**Chains.** A peer that missed successions receives them in order from the directory (section 7 below) and verifies each against the state the previous one produced. A peer applies no succession out of order and never skips one: a gap is `METADATA_REQUIRED`, and the peer pauses sharing to that account until the chain is complete, as it does today for a missing certificate.

## 4. Replacing the account keys (new text for section 4)

The existing procedure, "Replacing the device", is **identity continuity** and is unchanged. This is **account recovery**. A profile enables one or both (section 2a); the SDK refuses to prepare a replacement by a model the profile has not enabled, and peers refuse to verify one.

1. **Prepare** (`prepareReplacement()`, T11). On a fresh device, authenticated to the host as the account by the product's own login, the SDK resolves the account's current certificate and generation `g` through the directory, generates a fresh `accountSeed`, `deviceSeed`, `deviceId` and, when the profile uses a vault, a fresh `recoveryKey`, builds the certificate at generation `g + 1` under the new `AK`, and persists the roots, the exact certificate bytes, a random `successionId`, the expected current certificate hash and `g` in the secret store and the store, before returning. It returns the **proposal**: `{ successionId, accountName, accountId, expectedCertificateHash, expectedGeneration, certificate }`, all public. A second call on the same device returns the same pending proposal. The remote account is untouched.
2. **Authorize** (outside the SDK). The product performs its fresh authentication and asks the host to authorize the proposal. The host binds the authorization to the proposal's hash, the account, the expected generation and a single-use challenge with an expiry, and returns an opaque token. A long-lived session alone MUST NOT obtain one. How the host authenticates is the product's; the protocol sees only the token.
3. **Commit** (`completeReplacement({ successionId, authorization })`). The SDK calls `succeedAccount(expectedCertificateHash, certificate, vault?, successionId, authorization)`. The host, atomically: checks the authorization against the proposal and the challenge; compares and swaps the account's current certificate hash; stores the new certificate; signs the type 9 succession under the active operational key; moves the current-device pointer; fences the previous device from every write and from the relay; records the succession in the account's log; and returns the succession. Outcomes follow section 13's mutation outcomes: `COMMITTED` with the document; `ALREADY_COMMITTED` with the original document for a repeated `successionId` with identical bytes, answered **before** any authorization or expiry check, since a device retrying after a lost response finds its proposal already committed and its token already spent; `CONFLICT` with the current certificate when the expected hash is no longer current; `UNAUTHORIZED` for a missing, expired or mismatched token, and for a known `successionId` with different bytes. A timeout is retried with identical bytes and never prepares a second identity.
4. **Activate.** The SDK verifies the returned succession exactly as a peer would (section 3, against the expected previous state it persisted at T11), then writes the T1 header under the new identity, with `accountId` carried from the proposal, and enters `ready`. A succession that does not verify is `SUCCESSION_BINDING` and the device stays `activationPending` with the proposal intact; nothing reverts to the previous identity, because the device never held it.
5. **Bootstrap** (section 5) runs inside ordinary `sync()` calls until done. Its progress and failures are in the sync report; a failed circle does not undo activation or other circles.
6. **Peers** verify the succession on their next sync and rotate (section 3). Until an author rotates, the new device sees that author as waiting, as today. The retired device, on learning the succession, enters `retired` (section 4, "The retired device"), with one addition: it also erases its account seed, since that key is retired.

Crash outcomes (section 11): before T11 commits nothing exists; after T11, restart returns the same proposal; after remote commit but before the client has the succession, the next `completeReplacement` or `sync` gets `ALREADY_COMMITTED` with the document and finishes; a verified committed identity is never replaced by its predecessor.

## 5. Bootstrap without a vault (new text for section 5)

A device that arrives by account recovery holds no vault, so it learns its circles from the host. **Discovery is host-trusted at the level section 15 already grants enrollment**: the host authenticates the account and serves `listCircles(cursor)`: for each circle the account owns, belongs to, or has a pending request in, the `circleId`, the owner's account id, the account's role, the current snapshot, and the account's sharing preference (D3). Pages are bounded; the client persists each page's results before fetching the next and records the cursor.

For each circle the client resolves the owner's chain, verifies the snapshot under the owner's current key with the pin rules of section 6, and pins (`circleId`, owner account id) only when the snapshot names this account id as owner, member or, for a pending request, when the host says so (a pending request is host state today and stays so). Discovery is not permission to share: the circle is enabled only if the preference says so, and an absent preference is disabled. Discovery can omit a circle, which is withholding and already within the host's power; it cannot forge a snapshot, because the owner's signature and chain are verified. The original proposal's authority-signed bootstrap checkpoint adds nothing here: it would be signed by the same party that serves the list.

Bootstrap resumes across `sync()` calls, reports `bootstrap: { circles, pending, failed }` in the sync report with per-circle errors, and never erases a circle it already pinned because another failed. Membership continuity never admits a pending account, resurrects a removed or departed one, reopens a closed circle, or duplicates a member: it only reads what the owner signed.

A profile that keeps the vault (D4) may also have the succession install a fresh vault at revision 1 with the discovered entries, so that identity continuity works on the next replacement.

## 6. Security consequences (new text for section 15)

### 6.1 What changes in the attacker table

| Attacker | Can, after this amendment | Still cannot |
| --- | --- | --- |
| Holder of an allowed authority key | Sign a succession for any account to keys it holds, inherit that account's relationships, and read that account's **future** traffic from each peer's next rotation, until the change is noticed | Read any past traffic; avoid the `accountKeyChanged` signal every peer emits; sign a second successor for the same state without producing `EQUIVOCATION`; admit a member or change a snapshot |
| Malicious server | Everything above, since the authority key is the host's; present a fabricated login as fresh authentication | Everything in the current table |

Today the same key can only retire identities and close circles. The amendment turns a denial-of-service key into a key-substitution key, and the specification's statement that a malicious server "cannot substitute a key after first contact" becomes "cannot substitute a key silently or retroactively". That is the WhatsApp-style promise, not the Signal-style one, and the product must say which it is making.

### 6.2 Conditions of adoption

1. **The peer signal is mandatory.** `accountKeyChanged` with `reason: "succession"` is emitted by every peer for every succession, and the client has no option to drop it. Whether and how the product shows it is the product's, but a conforming product MUST make it discoverable (a notice, a history entry, a settings indicator).
2. **The authority key is custodied.** The operational key that signs successions MUST NOT be a plain environment secret of the application server. It lives in a key-management service or HSM that signs only after the host's fresh-authentication check has passed, with that check and the signing in one audited path. The reset-key list's 30-day lifetime and offline management key apply as today.
3. **Successions are logged append-only** by the host per account, served with the chain (section 7), so a peer or an auditor can see every key an account ever had and when. A profile MAY publish the log to a public transparency log; the protocol defines the per-account log only.
4. **Identity continuity remains available in the protocol** (D2), and the model a deployment enables is enforced by its peers (section 2a). A product that can rely on the platform's synced secret store keeps the stronger property; a product that enables account recovery, alone or alongside, says so in its profile and in its user-facing security description, because the weaker enabled model sets the promise.

### 6.3 Limits, stated plainly (additions)

11. A succession is a host assertion signed by the host's authority. Fresh authentication, however strong, is visible to the host alone; peers verify the authority's signature, not the login.
12. Compromise of an operational key now exposes future traffic of every account it is used against until the key is removed from the list and the successions are noticed; the 30-day list lifetime bounds the first, not the second.
13. Previously downloaded plaintext and keys cannot be revoked, by replacement of either kind.

## 7. Transport changes (section 13)

Directory, additions:

- `succeedAccount(expectedCertificateHash, newCertificate, newVault?, successionId, authorization)` → `COMMITTED | ALREADY_COMMITTED` with the type 9 document, `CONFLICT` with the current certificate, `UNAUTHORIZED`, `RETRYABLE`.
- `getSuccessions(accountId, afterGeneration)` → the account's successions in order, each with the new certificate; `resolveIdentities` attaches the chain for an account whose key changed, as it attaches reset receipts today.
- `listCircles(cursor)` → one page of the authenticated account's circles as in section 5, with the sharing preference.
- `setSharingPreference(circleId, enabled)`, authenticated, idempotent; the client calls it on every enable and disable and the vault update when a vault exists.

Host rules: a retired identity's device is refused every directory mutation, every relay append and every subscription read, by the certificate fence that exists today; the current-device pointer is the one source of "current". The host enforces `successionId` uniqueness and the single-use challenge. Nothing changes on the relay.

Client surface, additions: `prepareReplacement()`, `completeReplacement({ successionId, authorization })`, the `bootstrap` section of the sync report, the states `replacementPrepared` and `activationPending` reused, and the error codes `SUCCESSION_BINDING`, `SUPERSEDED_IDENTITY`, `AUTHORIZATION_REQUIRED`, `AUTHORIZATION_EXPIRED`, `SUCCESSION_PENDING`. `restoreAccount` is identity continuity and stays. `resetAccount` stays destructive and separate (D4): it still closes what the identity owned, and it does not share account recovery's continuity code. The profile's `replacement` declaration is validated at `open` like the retention policy, and `inspect()` reports it.

## 8. Conformance and fixture (section 16)

Wire version stays 5; every existing vector stays byte for byte. Added: a type 9 vector signed by the fixture's operational key for the fixture's Alice, with the generation 2 certificate under a new `AK₁`; negatives for a wrong signer, a bad binding (certificate not matching `newCertificateHash`, derived identity not matching `newIdentityId`, generation not previous plus one), a rollback, two successors for one state (`EQUIVOCATION`), and a revoked authority key; state cases for chain following, a gap, and a retired identity attempting to publish. Required tests: scenario 3 and 4 (owner and member replacement) repeated by account recovery with no recovery material; owners and peers missing several successions; a member succession while the owner is offline; removed, departed, pending, disabled and closed circles across a succession; two successions racing for one account (exactly one commits); crashes and lost responses around T11 and the commit; an old device refused after the commit; a succession by an authority key the list no longer allows; discovery pages interrupted and resumed; the lost-device tests of section 16, with the attacker holding the complete old state, showing it opens nothing new and cannot obtain a succession without the product's authentication; and, on a deployment whose profile enables identity continuity only, a valid succession served by the host being rejected by every peer, the account staying quarantined, and no rotation to the new key.

## 9. Delivery, if adopted

1. This amendment reviewed by the external reviewer, and D1 to D5 recorded, before code.
2. Core: `accountId` through pins, snapshots, audience and manifests; the type 9 codec and verifier; the chain store; T11 and the two client operations; the sync-report bootstrap section. Fixture regenerated with the added vectors only.
3. Hosts: fake host and the reference Worker: `succeedAccount`, the succession log, `getSuccessions`, `listCircles`, preferences, fencing of retired identities.
4. Expo: nothing new beyond the client surface; the profile template gains a section on which path a product enables and how it custodies the authority key.
5. Tests and measurements: the list in section 8; bootstrap requests, store transactions and replacement latency at 1, 10 and 100 circles.

Estimated size: comparable to the product-agnostic refactor of revision 8, with a larger review burden because section 6 changes what the protocol promises.
