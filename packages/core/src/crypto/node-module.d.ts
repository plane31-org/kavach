/**
 * The one Node API the optional `/sodium` entry uses, declared here so the protocol package keeps
 * no dependency on Node's type definitions: the rest of core imports no platform module.
 */
declare module "node:module" {
  export function createRequire(from: string | URL): (id: string) => unknown;
}

interface ImportMeta {
  readonly url: string;
}
