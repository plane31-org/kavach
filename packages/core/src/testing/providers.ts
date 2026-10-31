import { toHex } from "../bytes.js";
import type { ProviderLoadResult, ProviderSaveResult, ProviderStatus, ProviderStatusResult, RecoveryProvider } from "../vault.js";

/** A platform recovery provider shared by every device signed into one platform account. */
export class MemoryPlatformProvider implements RecoveryProvider {
  status_: ProviderStatus = "available";
  items: Map<string, Uint8Array> = new Map();

  constructor(private readonly platformAccount: string) {}

  private key(accountName: string, identityId: Uint8Array): string {
    return `${this.platformAccount}:${accountName}:${toHex(identityId)}`;
  }

  async load(accountName: string, identityId: Uint8Array): Promise<ProviderLoadResult> {
    if (this.status_ !== "available") return { status: this.status_ };
    const k = this.items.get(this.key(accountName, identityId));
    return k ? { status: "available", recoveryKey: k } : { status: "unavailable", reason: "no item" };
  }

  async save(accountName: string, identityId: Uint8Array, recoveryKey: Uint8Array): Promise<ProviderSaveResult> {
    if (this.status_ !== "available") return { status: this.status_, backupState: "unavailable" };
    this.items.set(this.key(accountName, identityId), recoveryKey);
    return { status: "available", backupState: "pending" };
  }

  async status(): Promise<ProviderStatusResult> {
    return { status: this.status_, backupState: this.status_ === "available" ? "pending" : "unavailable" };
  }

  async eraseLocalAccess(): Promise<void> {}

  /** Another phone on the same platform account sees the same items. */
  twin(): MemoryPlatformProvider {
    const p = new MemoryPlatformProvider(this.platformAccount);
    p.items = this.items;
    return p;
  }
}
