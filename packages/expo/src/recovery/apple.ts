/**
 * The iOS recovery provider over a synchronizable Keychain item (profile section 3).
 *
 * Expo SecureStore cannot set `kSecAttrSynchronizable`, so a small native module exposes a
 * generic-password item with `kSecAttrSynchronizable = true`, `kSecAttrAccessibleWhenUnlocked`
 * and the app's access group. The service is fixed; the account is the account name plus the
 * identity id. Logout erases nothing in the Keychain: deleting a synchronizable item deletes it
 * on every device, which is the opposite of "erase local access".
 */
import { fromHex, toHex, type ProviderLoadResult, type ProviderSaveResult, type ProviderStatusResult, type RecoveryProvider } from "@kavach/core";

/** The native bridge the provider needs. Errors carry a `code` from the Security framework. */
export interface SyncedKeychainLike {
  get(service: string, account: string): Promise<string | null>;
  set(service: string, account: string, value: string): Promise<void>;
  /** Whether iCloud Keychain is on for this device, when the platform can say. */
  isSyncEnabled?(): Promise<boolean | undefined>;
}

export const KEYCHAIN_SERVICE = "kavach.recovery";

export function keychainAccount(accountName: string, identityId: Uint8Array): string {
  return `${accountName}:${toHex(identityId)}`;
}

export class AppleKeychainRecoveryProvider implements RecoveryProvider {
  private lastSave: ProviderSaveResult | undefined;

  constructor(
    private readonly keychain: SyncedKeychainLike | undefined,
    private readonly service = KEYCHAIN_SERVICE
  ) {}

  async load(accountName: string, identityId: Uint8Array): Promise<ProviderLoadResult> {
    if (!this.keychain) return { status: "unsupported", reason: "no synced Keychain module" };
    try {
      const v = await this.keychain.get(this.service, keychainAccount(accountName, identityId));
      if (v === null) return { status: "unavailable", reason: "no item for this account in iCloud Keychain" };
      const key = fromHex(v);
      if (key.length !== 32) return { status: "unavailable", reason: "item is not a recovery key" };
      return { status: "available", recoveryKey: key };
    } catch (e) {
      return classify(e);
    }
  }

  async save(accountName: string, identityId: Uint8Array, recoveryKey: Uint8Array): Promise<ProviderSaveResult> {
    if (!this.keychain) return this.remember({ status: "unsupported", reason: "no synced Keychain module", backupState: "unavailable" });
    try {
      await this.keychain.set(this.service, keychainAccount(accountName, identityId), toHex(recoveryKey));
    } catch (e) {
      const c = classify(e);
      return this.remember({ status: c.status, ...(c.reason ? { reason: c.reason } : {}), backupState: "unavailable" });
    }
    // The item is written; whether iCloud has it is never known locally.
    const sync = await this.keychain.isSyncEnabled?.().catch(() => undefined);
    return this.remember(sync === false ? { status: "available", reason: "iCloud Keychain is off", backupState: "unavailable" } : { status: "available", backupState: "pending" });
  }

  async status(): Promise<ProviderStatusResult> {
    if (!this.keychain) return { status: "unsupported", backupState: "unavailable", reason: "no synced Keychain module" };
    if (this.lastSave) return { status: this.lastSave.status, backupState: this.lastSave.backupState, ...(this.lastSave.reason ? { reason: this.lastSave.reason } : {}) };
    const sync = await this.keychain.isSyncEnabled?.().catch(() => undefined);
    return sync === false ? { status: "unavailable", backupState: "unavailable", reason: "iCloud Keychain is off" } : { status: "available", backupState: "unknown" };
  }

  async eraseLocalAccess(): Promise<void> {
    this.lastSave = undefined;
  }

  private remember(r: ProviderSaveResult): ProviderSaveResult {
    this.lastSave = r;
    return r;
  }
}

/** Security framework codes: -25308 interaction not allowed (locked), -34018 missing entitlement. */
function classify(e: unknown): ProviderLoadResult {
  const code = typeof e === "object" && e !== null && "code" in e ? Number((e as { code: unknown }).code) : undefined;
  if (code === -25308) return { status: "locked", reason: "device locked" };
  if (code === -34018) return { status: "unsupported", reason: "keychain access group missing" };
  return { status: "error", reason: e instanceof Error ? e.name : "error" };
}
