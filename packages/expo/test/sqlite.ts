/** Node's built-in SQLite for tests. Loaded dynamically so the experimental module is not a hard import. */
import { createRequire } from "node:module";
import type { NodeSqliteDatabaseLike } from "../src/sqliteStore.js";

const require = createRequire(import.meta.url);
const sqlite = require("node:sqlite") as { DatabaseSync: new (path: string) => NodeSqliteDatabaseLike & { close(): void } };

export function openNodeDatabase(path: string): NodeSqliteDatabaseLike & { close(): void } {
  return new sqlite.DatabaseSync(path);
}
