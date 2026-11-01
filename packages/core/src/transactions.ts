/**
 * The named transaction boundaries of protocol section 11 (T1 to T5, T8, T9). T6, T6h and T7
 * live with the outbox and the inbox. Each function takes an open `Tx` so callers can compose
 * them; nothing here opens the network.
 */
import { equalBytes, fromHex, toHex } from "./bytes.js";
import { applyAudienceEvent, initialRevisionState, type AudienceEvent } from "./audience.js";
import { DocumentType, expectType, parseDocument, type AccountDevice } from "./codec.js";
import { identityId } from "./crypto.js";
import type { PreparedEpoch } from "./epoch.js";
import { promote } from "./epoch.js";
import { KavachError } from "./errors.js";
import { openAccount, pinFromCertificate, type DeviceKeys, type OwnAccount } from "./identity.js";
import { big, pinToRow, preparedToRow, revisionToRow, rowToPrepared, rowToRevision, unbig } from "./rows.js";
import type { ActivationRow, CircleRow, MetaRow, SecretStore, Store, StoreState, Tx, VaultRow } from "./store.js";

export const META = "meta";
export const SELF = "self";
export const STREAM = "stream";
export const REVISION = "revision";
export const VAULT = "vault";

// Opening -----------------------------------------------------------------------------------------

export type OpenedState =
  | { readonly kind: "fresh" }
  | { readonly kind: "initializing"; readonly account: OwnAccount }
  | { readonly kind: StoreState; readonly meta: MetaRow; readonly account: OwnAccount }
  /** A device retired by a succession erased its account seed (amendment A1, section 4): the header stays, the key is gone. */
  | { readonly kind: "RETIRED"; readonly meta: MetaRow; readonly account: undefined };

/**
 * Bind the secret store to the local store. A mismatch between the two is `RECOVERY_REQUIRED`
 * and is resolved by device replacement, never by inventing counters.
 */
export async function openStore(store: Store, secrets: SecretStore, accountName: string): Promise<OpenedState> {
  const stage = "openStore";
  const [accountSeed, instanceId] = await Promise.all([secrets.get("accountSeed"), secrets.get("instanceId")]);
  const meta = await store.read((tx) => tx.get("meta", META));
  if (!accountSeed || !instanceId) {
    if (meta?.state === "RETIRED") return { kind: "RETIRED", meta, account: undefined };
    if (meta) throw new KavachError("RECOVERY_REQUIRED", stage, "store present but secrets missing");
    return { kind: "fresh" };
  }
  const account = openAccount(accountName, accountSeed, meta?.accountId ? fromHex(meta.accountId) : undefined);
  if (!meta) return { kind: "initializing", account };
  if (meta.instanceId !== toHex(instanceId) || meta.identityId !== toHex(account.identityId) || meta.accountName !== accountName || meta.schema !== 1) {
    throw new KavachError("RECOVERY_REQUIRED", stage, "store header does not match the secret store");
  }
  if (meta.state === "INITIALIZING") return { kind: "initializing", account };
  return { kind: meta.state, meta, account };
}

// T1 ----------------------------------------------------------------------------------------------

/** T1a: roots into the secret store. Idempotent for the same values. */
export async function t1Secrets(secrets: SecretStore, roots: { accountSeed: Uint8Array; deviceSeed: Uint8Array; recoveryKey: Uint8Array; instanceId: Uint8Array }): Promise<void> {
  await secrets.set("accountSeed", roots.accountSeed);
  await secrets.set("deviceSeed", roots.deviceSeed);
  await secrets.set("recoveryKey", roots.recoveryKey);
  await secrets.set("instanceId", roots.instanceId);
}

/** T1b: the store header with the INITIALIZING marker, the own pin and the stream state. */
export function t1Header(tx: Tx, input: { account: OwnAccount; device: DeviceKeys; certificate: Uint8Array; instanceId: Uint8Array; generation: bigint }): void {
  const doc = expectType<AccountDevice>(parseDocument(input.certificate), DocumentType.AccountDevice, "t1");
  const pin = pinFromCertificate(doc, undefined, input.account.accountId);
  if (!equalBytes(pin.identityId, input.account.identityId)) throw new KavachError("MALFORMED", "t1", "certificate is not for this account");
  tx.put("meta", META, {
    schema: 1,
    historyIndex: 1,
    newest: 1,
    instanceId: toHex(input.instanceId),
    accountName: input.account.accountName,
    identityId: toHex(input.account.identityId),
    accountId: toHex(input.account.accountId),
    certificateHash: toHex(pin.certificateHash),
    state: "INITIALIZING"
  });
  tx.put("self", SELF, {
    generation: big(input.generation),
    deviceId: toHex(input.device.deviceId),
    certificate: toHex(input.certificate),
    certificateHash: toHex(pin.certificateHash),
    streamId: toHex(pin.streamId)
  });
  tx.put("pins", toHex(pin.accountId), pinToRow(pin));
  if (!tx.get("identities", toHex(pin.identityId))) {
    tx.put("identities", toHex(pin.identityId), { accountId: toHex(pin.accountId), accountName: pin.accountName, accountKey: toHex(pin.accountKey), sinceGeneration: big(input.generation), retired: false });
  }
  tx.put("certificates", toHex(pin.certificateHash), {
    identityId: toHex(pin.accountId),
    certificateHash: toHex(pin.certificateHash),
    signingKey: toHex(pin.signingKey),
    boxKey: toHex(pin.boxKey),
    streamId: toHex(pin.streamId),
    generation: big(input.generation),
    wire: toHex(input.certificate),
    current: true
  });
  tx.put("stream", STREAM, { highestCommittedEpoch: 0, activeEpoch: undefined, pendingEpoch: undefined });
  tx.put("revision", REVISION, revisionToRow(initialRevisionState, undefined));
}

/** T1c: ACTIVE once the certificate is durable at the host. */
export function t1Activate(tx: Tx): void {
  const meta = tx.get("meta", META);
  if (!meta) throw new KavachError("STORAGE_FAILURE", "t1", "no header");
  tx.put("meta", META, { ...meta, state: "ACTIVE" });
}

// T2 ----------------------------------------------------------------------------------------------

/** T2: the exact replacement certificate and vault bytes prepared for activation. */
export function t2PrepareActivation(tx: Tx, row: ActivationRow): void {
  tx.put("activation", "pending", row);
  const meta = tx.get("meta", META);
  if (meta) tx.put("meta", META, { ...meta, state: "ACTIVATION_PENDING" });
}

// T3 ----------------------------------------------------------------------------------------------

export interface ChangeResult {
  readonly changed: boolean;
  readonly desiredRevision: bigint;
  readonly cancelled: readonly string[];
}

/**
 * T3: a verified circle or device change. Bumps the desired revision, invalidates the active
 * epoch, burns its counters and cancels queued (not yet handed off) outbox rows sealed under the
 * obsolete revision. Pauses with `rotation`.
 */
export function t3ApplyChange(tx: Tx, event: AudienceEvent): ChangeResult {
  const row = tx.get("revision", REVISION);
  const state = row ? rowToRevision(row) : initialRevisionState;
  const { state: next, changed } = applyAudienceEvent(state, event);
  if (!changed) return { changed: false, desiredRevision: state.desiredRevision, cancelled: [] };
  tx.put("revision", REVISION, revisionToRow(next, "rotation"));
  const stream = tx.get("stream", STREAM);
  if (stream?.activeEpoch !== undefined) {
    const active = tx.get("epochs", String(stream.activeEpoch));
    if (active) tx.put("epochs", String(stream.activeEpoch), { ...active, status: "obsolete" });
    tx.put("stream", STREAM, { ...stream, activeEpoch: undefined });
  }
  const cancelled: string[] = [];
  for (const [key, out] of tx.list("outbox")) {
    if (out.status === "queued" && unbig(out.desiredRevision) < next.desiredRevision) {
      tx.put("outbox", key, { ...out, wire: "", status: "cancelled", reason: "rotation" });
      cancelled.push(key);
    }
  }
  return { changed: true, desiredRevision: next.desiredRevision, cancelled };
}

/**
 * T3c: one circle row change with its bookkeeping. The row is stored, the audience event it
 * implies (if any) rotates the sending epoch, and the vault is marked so the backup follows the
 * rows. Every circle write except the restore from the vault itself goes through here.
 */
export function t3Circle(tx: Tx, row: CircleRow, event?: AudienceEvent): ChangeResult {
  tx.put("circles", row.circleId, row);
  t9MarkVault(tx);
  return event ? t3ApplyChange(tx, event) : { changed: false, desiredRevision: currentRevision(tx), cancelled: [] };
}

export function currentRevision(tx: Pick<Tx, "get">): bigint {
  const row = tx.get("revision", REVISION);
  return row ? unbig(row.desiredRevision) : 1n;
}

// T4 and T5 ---------------------------------------------------------------------------------------

/** T4: the exact manifest, wraps, key and audience checkpoint of a prepared epoch. One unresolved epoch per stream. */
export function t4PersistPrepared(tx: Tx, prepared: PreparedEpoch): void {
  const stream = tx.get("stream", STREAM) ?? { highestCommittedEpoch: 0, activeEpoch: undefined, pendingEpoch: undefined };
  // Never overwrite an unresolved epoch, even at the same number: a second preparation carries a
  // different key, and publishing both is an equivocation against ourselves.
  if (stream.pendingEpoch !== undefined) throw new KavachError("ROTATION_REQUIRED", "t4", "an epoch is already unresolved");
  if (prepared.epoch !== stream.highestCommittedEpoch + 1) throw new KavachError("MALFORMED", "t4", "epoch must be highestCommitted + 1");
  tx.put("epochs", String(prepared.epoch), preparedToRow(prepared));
  tx.put("stream", STREAM, { ...stream, pendingEpoch: prepared.epoch });
}

export type PublishRecord = "PROMOTED" | "OBSOLETE";

/** T5: a committed publication. Promotion is conditional on the revision and the exact audience. */
export function t5Committed(tx: Tx, epoch: number, currentAudienceKey: string): PublishRecord {
  const stream = tx.get("stream", STREAM);
  const row = tx.get("epochs", String(epoch));
  if (!stream || !row) throw new KavachError("STORAGE_FAILURE", "t5", "unknown epoch");
  // Idempotent: two contexts can both learn of one publication. The second must not reset a
  // counter the first already started allocating from.
  if (row.status === "active") return "PROMOTED";
  if (row.status === "obsolete" || row.status === "retired") return "OBSOLETE";
  const outcome = promote(rowToPrepared(row), currentRevision(tx), currentAudienceKey);
  const revision = tx.get("revision", REVISION);
  if (outcome === "PROMOTED") {
    tx.put("epochs", String(epoch), { ...row, status: "active", nextCounter: 0 });
    tx.put("stream", STREAM, { highestCommittedEpoch: Math.max(stream.highestCommittedEpoch, epoch), activeEpoch: epoch, pendingEpoch: undefined });
    // A promoted epoch resolved whatever paused sending: the rotation, the missing certificate,
    // or the audience limit. The sync pause belongs to the host and stays.
    if (revision?.paused && revision.paused !== "sync") tx.put("revision", REVISION, { ...revision, paused: undefined });
  } else {
    tx.put("epochs", String(epoch), { ...row, status: "obsolete" });
    tx.put("stream", STREAM, { ...stream, highestCommittedEpoch: Math.max(stream.highestCommittedEpoch, epoch), pendingEpoch: undefined });
  }
  return outcome;
}

// T8 and T9 ---------------------------------------------------------------------------------------

/** T8: the owner's successor snapshot, kept until the host confirms it. */
export function t8OwnerSnapshot(tx: Tx, circleId: Uint8Array, snapshot: Uint8Array, revision: bigint, close = false): void {
  const key = toHex(circleId);
  const row = tx.get("circles", key);
  if (!row) throw new KavachError("STORAGE_FAILURE", "t8", "unknown circle");
  tx.put("circles", key, { ...row, pending: { snapshot: toHex(snapshot), revision: big(revision), ...(close ? { close: true } : {}) } });
}

/** T9: a vault update prepared for publication (or confirmed). */
export function t9Vault(tx: Tx, row: VaultRow): void {
  tx.put("vault", VAULT, row);
}

/** T9 marker: the circle rows changed in this transaction, so the vault has to be derived from them again. */
export function t9MarkVault(tx: Tx): void {
  const row = tx.get("vault", VAULT);
  if (row && !row.dirty) tx.put("vault", VAULT, { ...row, dirty: true });
}

/** Own identity id from the header, for callers that only hold a transaction. */
export function selfIdentity(tx: Pick<Tx, "get">, accountName: string, accountKey: Uint8Array): Uint8Array {
  const meta = tx.get("meta", META);
  const iid = identityId(accountName, accountKey);
  if (meta && meta.identityId !== toHex(iid)) throw new KavachError("RECOVERY_REQUIRED", "selfIdentity");
  return iid;
}
