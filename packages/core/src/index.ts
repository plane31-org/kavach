/**
 * @kavach/core: Kavach v1 protocol (revision 4, wire version 5).
 *
 * Build order follows Kavach-v1-Build-Sequence.md. Step 1 adds primitives and
 * labels; nothing is exported until it is tested against the vectors.
 */
export const PROTOCOL_NAME = "Kavach";
export const PROTOCOL_REVISION = 4;
export const WIRE_VERSION = 5;
/** Domain-separation prefix. Kept from the protocol's earlier name on purpose: changing it changes every vector. */
export const LABEL_PREFIX = "SealedStream/5/";
