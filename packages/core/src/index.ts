/**
 * @kavach/core: Kavach v1 protocol (revision 6, wire version 5).
 *
 * This entry is what an application imports: the client, its types, the errors and the few
 * helpers an app needs around it. Adapter and host authors import `@kavach/core/adapters`;
 * test harnesses import `@kavach/core/testing`; the optional libsodium backend is
 * `@kavach/core/sodium`. Everything else is internal and reachable only by relative import.
 */
export const PROTOCOL_NAME = "Kavach";
export const PROTOCOL_REVISION = 7;

// The client ---------------------------------------------------------------------------------------
export {
  open,
  type CircleSummary,
  type Client,
  type ClientEvent,
  type ClientState,
  type ClientStatus,
  type EnqueueOptions,
  type EnqueueResult,
  type HistoryEntry,
  type HistoryPage,
  type HistoryQuery,
  type Inspection,
  type Latest,
  type LatestStatus,
  type OpenOptions,
  type PauseReason,
  type ReceiveResult,
  type SyncError,
  type SyncOptions,
  type SyncReport
} from "./client.js";

// Errors -------------------------------------------------------------------------------------------
export { KavachError, isKavachError, type ErrorCode } from "./errors.js";

// Locations ----------------------------------------------------------------------------------------
export { locationFromDegrees, locationToDegrees } from "./record.js";
/** The 22-byte location codec (protocol section 9), for reading history plaintext and building payloads. */
export { decodeLocation, encodeLocation, type Location, type LocationStatus, type RecordKind } from "./codec.js";

// Configuration ------------------------------------------------------------------------------------
export { validatePolicy, type RetentionPolicy } from "./policy.js";
export type { ResetTrustConfig } from "./reset.js";
export { setCryptoBackend, type CryptoBackend } from "./crypto.js";

// Recovery -----------------------------------------------------------------------------------------
export {
  decodeRecoveryCode,
  encodeRecoveryCode,
  type BackupState,
  type ProviderLoadResult,
  type ProviderSaveResult,
  type ProviderStatus,
  type ProviderStatusResult,
  type RecoveryProvider
} from "./vault.js";

// Identifiers --------------------------------------------------------------------------------------
export { equalBytes, fromHex, toHex } from "./bytes.js";
