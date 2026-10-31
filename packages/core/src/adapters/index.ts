/**
 * @kavach/core/adapters: the contracts an adapter or host author implements, and what their
 * tests need to drive them. Applications import `@kavach/core` instead.
 *
 * A `Store` and `SecretStore` adapter implements the row tables and the transaction interface;
 * a `Transport` adapter implements the directory and relay calls; a `RecoveryProvider` keeps
 * the recovery key with the platform; a host parses and verifies the signed documents the
 * transport carries. The in-memory implementations are the behavioural reference.
 */

// Bytes --------------------------------------------------------------------------------------------
export { Reader, Writer, compareBytes, concat, equalBytes, fromHex, toHex, u16, u32, u64 } from "../bytes.js";

// Cipher suite: readiness, randomness and the identifiers a host derives --------------------------
export { bodyHash, identityId, randomBytes, ready, recordId, signingKeypairFromSeed, streamId, type SigningKeypair } from "../crypto.js";

// Errors -------------------------------------------------------------------------------------------
export { KavachError, isKavachError, type ErrorCode } from "../errors.js";

// Signed documents, as a host or transport sees them ----------------------------------------------
export {
  DocumentType,
  buildResetReceipt,
  expectType,
  parseDocument,
  parseVaultHeader,
  verifyDocument,
  type AccountDevice,
  type AccountResetReceipt,
  type CircleSnapshot,
  type EncryptedRecord,
  type EpochManifest,
  type Parsed,
  type ResetKeyEntry,
  type ResetKeyList,
  type SignedDocument,
  type VaultHeader
} from "../codec.js";

// Store --------------------------------------------------------------------------------------------
export {
  MemorySecretStore,
  MemoryStore,
  invokeSync,
  type ActivationRow,
  type CertificateRow,
  type CircleRow,
  type ClockRow,
  type EpochRow,
  type EpochStatus,
  type HistoryRow,
  type LivePinRow,
  type MemoryStoreOptions,
  type MetaRow,
  type OutboxRow,
  type OutboxStatus,
  type EnqueueKeyRow,
  type HistoryIndexRow,
  type KeyRange,
  inKeyRange,
  type PendingResetRow,
  type PinRow,
  type QuarantineRow,
  type ReaderEpochRow,
  type ResetListRow,
  type ResetReceiptRow,
  type RevisionRow,
  type SecretName,
  type SecretStore,
  type SelfRow,
  type StatusRow,
  type Store,
  type StoreState,
  type StreamRow,
  type SubscriptionRow,
  type TableName,
  type Tables,
  type Tx,
  type UnresolvedRow,
  type VaultRow
} from "../store.js";

// Transport ----------------------------------------------------------------------------------------
export type {
  AppendOutcome,
  AppendStatus,
  Directory,
  EpochBundle,
  JoinRequest,
  MutationOutcome,
  MutationStatus,
  ReadRecordsResult,
  Relay,
  ResolvedAccount,
  Transport
} from "../transport.js";

// Recovery provider --------------------------------------------------------------------------------
export type { BackupState, ProviderLoadResult, ProviderSaveResult, ProviderStatus, ProviderStatusResult, RecoveryProvider } from "../vault.js";

// The transactions an adapter test drives against a store -----------------------------------------
export { openStore, t1Activate, t1Header, t1Secrets, t3ApplyChange, type ChangeResult, type OpenedState } from "../transactions.js";
