/**
 * @plane31/blind-relay: Kavach v1 protocol (revision 10, wire version 5).
 *
 * This entry is what an application imports: the client, its types, the errors and the few
 * helpers an app needs around it. Adapter and host authors import `@plane31/blind-relay/adapters`;
 * test harnesses import `@plane31/blind-relay/testing`; the optional libsodium backend is
 * `@plane31/blind-relay/sodium`. Everything else is internal and reachable only by relative import.
 */
export const PROTOCOL_NAME = "Kavach";
export const PROTOCOL_REVISION = 10;

// The client ---------------------------------------------------------------------------------------
export {
  open,
  type CircleSummary,
  type Client,
  type DrainOptions,
  type DrainReport,
  type DrainStop,
  type ClientEvent,
  type ClientState,
  type ClientStatus,
  type EnqueueOptions,
  type EnqueueResult,
  type HistoryEntry,
  type HistoryPage,
  type HistoryQuery,
  type Inspection,
  type KeyChangeEntry,
  type Newest,
  type OpenOptions,
  type PauseReason,
  type ReceiveResult,
  type ReplaceDeviceOptions,
  type ReplaceDeviceResult,
  type ReplacementProposal,
  type SyncError,
  type SyncOptions,
  type SyncReport,
  type SyncTimings
} from "./client.js";

// Errors -------------------------------------------------------------------------------------------
export { KavachError, isKavachError, type ErrorCode } from "./errors.js";

// Records -----------------------------------------------------------------------------------------
export type { RecordKind } from "./codec.js";

// Configuration ------------------------------------------------------------------------------------
export { validatePolicy, type KindDeclaration, type ReplacementModel, type RetentionPolicy } from "./policy.js";
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
