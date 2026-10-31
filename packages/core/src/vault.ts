/**
 * The account vault and the recovery order (protocol section 5).
 *
 * The vault carries the account seed, the last device checkpoint and the circle pins with their
 * sharing preference. It never carries a key that decrypts a record. Recovery tries the platform
 * provider, then a saved code, and otherwise reports `ACCOUNT_RECOVERY_REQUIRED`; it never
 * manufactures identity keys.
 */
import { compareBytes, equalBytes } from "./bytes.js";
import {
  decodeRecoveryCode,
  encodeRecoveryCode,
  openVault,
  sealVault,
  type OpenedVault,
  type VaultContents,
  type VaultEntry,
  type VaultHeader
} from "./codec.js";
import { KEY_BYTES, NONCE_BYTES, bodyHash, randomBytes } from "./crypto.js";
import { KavachError, isKavachError } from "./errors.js";

export { encodeRecoveryCode, decodeRecoveryCode, openVault, sealVault };
export type { OpenedVault, VaultContents, VaultEntry, VaultHeader };

export type ProviderStatus = "available" | "unavailable" | "locked" | "unsupported" | "error";
export type BackupState = "unknown" | "pending" | "unavailable";

export interface ProviderLoadResult {
  readonly status: ProviderStatus;
  readonly reason?: string;
  readonly recoveryKey?: Uint8Array;
}

export interface ProviderSaveResult {
  readonly status: ProviderStatus;
  readonly reason?: string;
  /** A successful local write is never reported as a completed cloud backup. */
  readonly backupState: BackupState;
}

export interface ProviderStatusResult {
  readonly status: ProviderStatus;
  readonly backupState: BackupState;
  readonly reason?: string;
}

/** The platform recovery provider the host supplies (synced Keychain, Block Store, ...). */
export interface RecoveryProvider {
  load(accountName: string, identityId: Uint8Array): Promise<ProviderLoadResult>;
  save(accountName: string, identityId: Uint8Array, recoveryKey: Uint8Array): Promise<ProviderSaveResult>;
  status(): Promise<ProviderStatusResult>;
  /** Logout or retirement: forget local access without deleting the shared item. */
  eraseLocalAccess(): Promise<void>;
}

export function newRecoveryKey(): Uint8Array {
  return randomBytes(KEY_BYTES);
}

/** Seal a vault at a revision with a fresh nonce. Returns the exact bytes and their hash. */
export function buildVault(header: VaultHeader, contents: VaultContents, recoveryKey: Uint8Array): { wire: Uint8Array; hash: Uint8Array } {
  const wire = sealVault(header, contents, recoveryKey, randomBytes(NONCE_BYTES));
  return { wire, hash: bodyHash(wire) };
}

/** Pure edits to the entry list, keeping it sorted and unique by circle id. */
export function upsertEntry(entries: readonly VaultEntry[], entry: VaultEntry): VaultEntry[] {
  const rest = entries.filter((e) => !equalBytes(e.circleId, entry.circleId));
  return [...rest, entry].sort((a, b) => compareBytes(a.circleId, b.circleId));
}

export function removeEntry(entries: readonly VaultEntry[], circleId: Uint8Array): VaultEntry[] {
  return entries.filter((e) => !equalBytes(e.circleId, circleId));
}

export type RecoverySource = "provider" | "code";

export interface RecoveryOutcome {
  readonly vault: OpenedVault;
  readonly recoveryKey: Uint8Array;
  readonly source: RecoverySource;
  readonly providerStatus: ProviderStatus;
}

/**
 * The recovery order. The provider is asked first; a saved code second; when neither opens the
 * vault the result is `ACCOUNT_RECOVERY_REQUIRED` and the caller preserves what it cannot use.
 * A wrong key is an authentication failure and never a reason to reset.
 */
export async function recoverAccount(input: {
  readonly accountName: string;
  readonly identityId: Uint8Array;
  readonly accountKey: Uint8Array;
  readonly vaultWire: Uint8Array;
  readonly provider: RecoveryProvider;
  readonly recoveryCode?: string;
}): Promise<RecoveryOutcome> {
  const stage = "recoverAccount";
  const tryOpen = (key: Uint8Array): OpenedVault | undefined => {
    try {
      return openVault(input.vaultWire, key, input.accountName, input.accountKey);
    } catch (e) {
      if (isKavachError(e, "DECRYPT_FAILED")) return undefined;
      throw e;
    }
  };
  let providerStatus: ProviderStatus = "error";
  try {
    const loaded = await input.provider.load(input.accountName, input.identityId);
    providerStatus = loaded.status;
    if (loaded.status === "available" && loaded.recoveryKey) {
      const vault = tryOpen(loaded.recoveryKey);
      if (vault) return { vault, recoveryKey: loaded.recoveryKey, source: "provider", providerStatus };
    }
  } catch {
    providerStatus = "error";
  }
  if (input.recoveryCode !== undefined) {
    const key = decodeRecoveryCode(input.recoveryCode);
    const vault = tryOpen(key);
    if (vault) return { vault, recoveryKey: key, source: "code", providerStatus };
    throw new KavachError("DECRYPT_FAILED", stage, "recovery code does not open the vault");
  }
  throw new KavachError("ACCOUNT_RECOVERY_REQUIRED", stage, `provider ${providerStatus}, no code`);
}
