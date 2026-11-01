# Kavach reference host

A Cloudflare Worker that implements the directory and relay contract of the Kavach v1 protocol (`spec/Kavach-v1.md`, section 13) so the SDK repository can run its own end-to-end tests, and so the first production host can be built from a working pattern. It is an example, not a product: it is not published, it has no real login, and it records notifications instead of sending them.

| Part | Where | What it holds |
| --- | --- | --- |
| Directory | D1 (`migrations/0001_directory.sql`) | accounts with their current certificate, immutable certificates by hash, vaults and snapshots by compare-and-swap, join and leave requests, reset receipts, the reader subscription index, notifications |
| Relay | one `StreamDO` per author stream (SQLite-backed Durable Object) | retained records by delivery sequence with acceptance time, one subscription per reader device with its cursor, the expiry watermark, the per-stream high-water pair and last-append outcome, epoch material while current or referenced |

Deletion runs in the same transaction as the cursor advance that completes a record. The expiry prefix advances on the object's alarm. Reads are filtered by the caller's certificate. The behavioural reference is the in-memory host in `@blind-relay/core/testing`; the tests here run the core's scenarios against this Worker through `client/httpTransport.ts`.

## What a production host replaces

- **Login.** The bearer `accountName:certificateHash` stands in for the host's own authentication. A real host authenticates the account and binds the session to the device's certificate hash, then hands those two facts to the same handlers.
- **Notifications.** `notifications` rows become pushes, decided from the record's header class as the product declares it: visible for a join request (to the owner) and a class 1 append (to each recipient), nothing for class 2, a silent wake-up otherwise. The host never sees a kind, and nothing in a row is a coordinate or a payload.
- **Reset authority.** `RESET_OPERATIONAL_SEED` and `RESET_KEY_ID` are Worker secrets; `RESET_KEY_LIST` is the management-signed list, renewed by the offline process the profile describes.
- **The test clock.** `ALLOW_TEST_CLOCK` must be unset; with it, `X-Test-Now` drives the host clock and the alarm defers to `/expire`.

## Running

```
pnpm test        # vitest inside workerd: D1 and the Durable Object are emulated
pnpm dev         # wrangler dev
```
