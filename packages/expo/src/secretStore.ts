/**
 * The secret store over Expo SecureStore (profile section 3). Every value is device-only:
 * `WHEN_UNLOCKED_THIS_DEVICE_ONLY`, never synced, never in a backup. Values are hex strings
 * because SecureStore stores text. No biometric prompt: background work is unattended, and a
 * prompt per read would stop it.
 */
import { fromHex, toHex, type SecretName, type SecretStore } from "@plane31/blind-relay/adapters";

/** The subset of `expo-secure-store` this adapter uses, so it can be driven by a fake in tests. */
export interface SecureStoreLike {
  getItemAsync(key: string, options?: SecureStoreOptions): Promise<string | null>;
  setItemAsync(key: string, value: string, options?: SecureStoreOptions): Promise<void>;
  deleteItemAsync(key: string, options?: SecureStoreOptions): Promise<void>;
}

export interface SecureStoreOptions {
  keychainAccessible?: unknown;
  requireAuthentication?: boolean;
  keychainService?: string;
}

export interface ExpoSecretStoreOptions {
  /** `SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY`; passed through because the constant lives in the module. */
  readonly thisDeviceOnly: unknown;
  /** Key prefix, so several accounts on one device do not collide. Defaults to `kavach`. */
  readonly namespace?: string;
  /** iOS keychain service, kept per app. */
  readonly keychainService?: string;
}

export class ExpoSecretStore implements SecretStore {
  private readonly options: SecureStoreOptions;
  private readonly prefix: string;

  constructor(
    private readonly secure: SecureStoreLike,
    options: ExpoSecretStoreOptions
  ) {
    this.options = { keychainAccessible: options.thisDeviceOnly, requireAuthentication: false, ...(options.keychainService ? { keychainService: options.keychainService } : {}) };
    this.prefix = (options.namespace ?? "kavach") + ".";
  }

  async get(name: SecretName): Promise<Uint8Array | undefined> {
    const v = await this.secure.getItemAsync(this.prefix + name, this.options);
    return v === null ? undefined : fromHex(v);
  }

  async set(name: SecretName, value: Uint8Array): Promise<void> {
    await this.secure.setItemAsync(this.prefix + name, toHex(value), this.options);
  }

  async delete(name: SecretName): Promise<void> {
    await this.secure.deleteItemAsync(this.prefix + name, this.options);
  }
}
