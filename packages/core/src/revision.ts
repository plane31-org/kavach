/**
 * The protocol revision this package implements. A transport sends it with each append
 * (`AppendOptions.revision`), so a host answers a status an older client cannot read, such as
 * `AUDIENCE_STALE` (revision 12), only to clients at or above the revision that defines it.
 */
export const PROTOCOL_REVISION = 14;
