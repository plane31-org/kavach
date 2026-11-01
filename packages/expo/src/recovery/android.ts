/**
 * The Android recovery provider over Block Store (profile section 3).
 *
 * The entry is named `kavach.recovery.<hex identityId>` and holds
 * `u8(1) || B(accountName) || identityId[32] || recoveryKey[32]`. Before storing with cloud
 * backup the provider awaits `isEndToEndEncryptionAvailable()`; only `true` permits it. On
 * false, error or absent services the existing entry is left untouched and a reason is
 * returned; the provider never retries without cloud backup, which could delete a prior cloud
 * copy. A successful store reports `backupState = pending`: a local write is never a backup.
 */
import { Reader, Writer, concat, equalBytes, toHex, type ProviderLoadResult, type ProviderSaveResult, type ProviderStatusResult, type RecoveryProvider } from "@plane31/blind-relay/adapters";

/** The subset of the Block Store client the provider uses; a native module supplies it. */
export interface BlockStoreLike {
  isEndToEndEncryptionAvailable(): Promise<boolean>;
  /** Store bytes under a key; `cloudBackup` requests backup to the user's Google account. */
  store(key: string, bytes: Uint8Array, cloudBackup: boolean): Promise<void>;
  retrieve(key: string): Promise<Uint8Array | null>;
  delete(key: string): Promise<void>;
}

export const BLOCK_STORE_PREFIX = "kavach.recovery.";
const VERSION = 1;

export function blockStoreKey(identityId: Uint8Array): string {
  return BLOCK_STORE_PREFIX + toHex(identityId);
}

export function encodeBlockStoreValue(accountName: string, identityId: Uint8Array, recoveryKey: Uint8Array): Uint8Array {
  return new Writer().u8(VERSION).name(accountName).bytes(identityId).bytes(recoveryKey).finish();
}

export function decodeBlockStoreValue(value: Uint8Array): { accountName: string; identityId: Uint8Array; recoveryKey: Uint8Array } | undefined {
  try {
    const r = new Reader(value, "blockStore");
    if (r.u8() !== VERSION) return undefined;
    const accountName = r.name();
    const identityId = r.take(32);
    const recoveryKey = r.take(32);
    r.end();
    return { accountName, identityId, recoveryKey };
  } catch {
    return undefined;
  }
}

export class BlockStoreRecoveryProvider implements RecoveryProvider {
  private lastSave: ProviderSaveResult | undefined;

  constructor(private readonly blockStore: BlockStoreLike | undefined) {}

  async load(accountName: string, identityId: Uint8Array): Promise<ProviderLoadResult> {
    if (!this.blockStore) return { status: "unsupported", reason: "no Block Store module" };
    let raw: Uint8Array | null;
    try {
      raw = await this.blockStore.retrieve(blockStoreKey(identityId));
    } catch (e) {
      return { status: "error", reason: safeReason(e) };
    }
    if (!raw) return { status: "unavailable", reason: "no entry for this account on this Google account" };
    const decoded = decodeBlockStoreValue(raw);
    if (!decoded || decoded.accountName !== accountName || !equalBytes(decoded.identityId, identityId)) {
      return { status: "unavailable", reason: "entry does not bind to this account" };
    }
    return { status: "available", recoveryKey: decoded.recoveryKey };
  }

  async save(accountName: string, identityId: Uint8Array, recoveryKey: Uint8Array): Promise<ProviderSaveResult> {
    if (!this.blockStore) return this.remember({ status: "unsupported", reason: "no Block Store module", backupState: "unavailable" });
    let e2e: boolean;
    try {
      e2e = await this.blockStore.isEndToEndEncryptionAvailable();
    } catch (e) {
      return this.remember({ status: "error", reason: safeReason(e), backupState: "unavailable" });
    }
    if (!e2e) {
      // Never store without end-to-end encryption, and never downgrade an existing cloud copy.
      return this.remember({ status: "unavailable", reason: "end-to-end encrypted backup is not available (screen lock or Google account missing)", backupState: "unavailable" });
    }
    try {
      await this.blockStore.store(blockStoreKey(identityId), encodeBlockStoreValue(accountName, identityId, recoveryKey), true);
    } catch (e) {
      return this.remember({ status: "error", reason: safeReason(e), backupState: "unavailable" });
    }
    return this.remember({ status: "available", backupState: "pending" });
  }

  async status(): Promise<ProviderStatusResult> {
    if (!this.blockStore) return { status: "unsupported", backupState: "unavailable", reason: "no Block Store module" };
    if (this.lastSave) return { status: this.lastSave.status, backupState: this.lastSave.backupState, ...(this.lastSave.reason ? { reason: this.lastSave.reason } : {}) };
    try {
      const e2e = await this.blockStore.isEndToEndEncryptionAvailable();
      return e2e ? { status: "available", backupState: "unknown" } : { status: "unavailable", backupState: "unavailable", reason: "end-to-end encrypted backup is not available" };
    } catch (e) {
      return { status: "error", backupState: "unavailable", reason: safeReason(e) };
    }
  }

  /** Logout or retirement: the shared entry stays; only this process forgets it. */
  async eraseLocalAccess(): Promise<void> {
    this.lastSave = undefined;
  }

  private remember(r: ProviderSaveResult): ProviderSaveResult {
    this.lastSave = r;
    return r;
  }
}

function safeReason(e: unknown): string {
  // Error classes only; never a value from the entry.
  return e instanceof Error ? e.name : "error";
}

export const _concat = concat;
