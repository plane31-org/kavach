/**
 * @kavach/core: Kavach v1 protocol (revision 4, wire version 5).
 *
 * Build order follows Kavach-v1-Build-Sequence.md. Step 1: primitives and labels.
 */
export const PROTOCOL_NAME = "Kavach";
export const PROTOCOL_REVISION = 4;

export * from "./errors.js";
export * from "./bytes.js";
export * from "./crypto.js";
