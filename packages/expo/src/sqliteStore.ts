/**
 * The durable store over SQLite with SQLCipher (profile section 3).
 *
 * One table holds every logical table as JSON rows. Every write runs inside `BEGIN IMMEDIATE`,
 * so SQLite's file lock serialises writers across the foreground app, a background task and
 * any headless context; a writer that cannot take the lock within the busy timeout
 * gets `LOCKED`. The transaction callback is synchronous, so begin, callback and commit run in
 * one turn of the event loop; it may initiate a transport send before commit through
 * `tx.handoff` (T6h). Reads outside a transaction therefore see committed state only.
 *
 * The adapter speaks to the database through `SqlDriver`, a three-method surface that
 * `expo-sqlite`'s synchronous API and Node's `node:sqlite` both satisfy.
 */
import { KavachError, invokeSync, type KeyRange, type Store, type TableName, type Tables, type Tx } from "@plane31/blind-relay/adapters";

export type SqlValue = string | number | null;

export interface SqlDriver {
  exec(sql: string): void;
  run(sql: string, params?: readonly SqlValue[]): void;
  all<T = Record<string, SqlValue>>(sql: string, params?: readonly SqlValue[]): T[];
  /** Close the connection; absent for drivers that have none to close. */
  close?(): void;
}

export interface SqliteStoreOptions {
  readonly driver: SqlDriver;
  /** The 32-byte storage key from the secret store. Required with SQLCipher; omit only in tests. */
  readonly storageKey?: Uint8Array | undefined;
  /** Finite: a waiting writer fails with `LOCKED` after this. Default 5,000 ms. */
  readonly busyTimeoutMs?: number;
}

const SCHEMA = 1;

export class SqliteStore implements Store {
  private chain: Promise<void> = Promise.resolve();
  private closed = false;

  private constructor(private readonly db: SqlDriver) {}

  /** Open, key, set the pragmas, verify the key and create the schema. */
  static open(options: SqliteStoreOptions): SqliteStore {
    const db = options.driver;
    if (options.storageKey) {
      if (options.storageKey.length !== 32) throw new KavachError("INVALID_KEY", "sqliteStore", "storage key must be 32 bytes");
      db.exec(`PRAGMA key = "x'${hex(options.storageKey)}'"`);
    }
    db.exec(`PRAGMA busy_timeout = ${Math.max(1, Math.floor(options.busyTimeoutMs ?? 5000))}`);
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA synchronous = FULL");
    try {
      db.all("SELECT count(*) AS n FROM sqlite_master");
    } catch {
      // SQLCipher answers "file is not a database" to the wrong key.
      throw new KavachError("RECOVERY_REQUIRED", "sqliteStore", "database does not open with this key");
    }
    db.exec("CREATE TABLE IF NOT EXISTS kv (tbl TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (tbl, key)) WITHOUT ROWID");
    db.exec(`PRAGMA user_version = ${SCHEMA}`);
    return new SqliteStore(db);
  }

  /**
   * Close the connection once the work queued ahead has finished; every later transaction or read
   * is `CLOSED`. Idempotent. The client is closed first, so nothing is queued behind this.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    const release = await this.acquire();
    try {
      this.closed = true;
      this.db.close?.();
    } finally {
      release();
    }
  }

  async transaction<R>(fn: (tx: Tx) => R): Promise<R> {
    if (this.closed) throw new KavachError("CLOSED", "sqliteStore", "the store is closed");
    const release = await this.acquire();
    if (this.closed) {
      release();
      throw new KavachError("CLOSED", "sqliteStore", "the store is closed");
    }
    try {
      try {
        this.db.exec("BEGIN IMMEDIATE");
      } catch (e) {
        throw new KavachError("LOCKED", "sqliteStore", `could not begin: ${String(e)}`);
      }
      const tx = new SqliteTx(this.db);
      let result: R;
      try {
        result = invokeSync(fn, tx);
      } catch (e) {
        this.rollback();
        throw e;
      }
      try {
        this.db.exec("COMMIT");
      } catch (e) {
        this.rollback();
        throw new KavachError("STORAGE_FAILURE", "sqliteStore", `commit failed: ${String(e)}`);
      }
      return result;
    } finally {
      release();
    }
  }

  /**
   * Reads share the one connection with writers, and a connection sees its own uncommitted
   * writes. Because the transaction callback is synchronous, BEGIN, the callback and COMMIT (or
   * ROLLBACK) run without yielding, so no read can observe the connection mid-transaction: by the
   * time this method runs its callback the connection holds no open transaction, and the read
   * sees committed state only. The in-process chain is kept for ordering, so a read issued after
   * a transaction call observes that transaction's outcome.
   */
  async read<R>(fn: (tx: Omit<Tx, "put" | "delete" | "handoff">) => R): Promise<R> {
    if (this.closed) throw new KavachError("CLOSED", "sqliteStore", "the store is closed");
    const release = await this.acquire();
    if (this.closed) {
      release();
      throw new KavachError("CLOSED", "sqliteStore", "the store is closed");
    }
    try {
      return fn(new SqliteTx(this.db, true));
    } finally {
      release();
    }
  }

  private rollback(): void {
    try {
      this.db.exec("ROLLBACK");
    } catch {
      /* already rolled back */
    }
  }

  /** In-process serialisation; the file lock handles other processes. */
  private acquire(): Promise<() => void> {
    const previous = this.chain;
    let release: () => void = () => undefined;
    this.chain = new Promise<void>((resolve) => {
      release = resolve;
    });
    return previous.then(() => release);
  }
}

class SqliteTx implements Tx {
  constructor(
    private readonly db: SqlDriver,
    private readonly readOnly = false
  ) {}

  get<T extends TableName>(table: T, key: string): Tables[T] | undefined {
    const rows = this.db.all<{ value: string }>("SELECT value FROM kv WHERE tbl = ? AND key = ?", [table, key]);
    const v = rows[0]?.value;
    return v === undefined ? undefined : (JSON.parse(v) as Tables[T]);
  }

  put<T extends TableName>(table: T, key: string, row: Tables[T]): void {
    this.guard();
    this.db.run("INSERT INTO kv (tbl, key, value) VALUES (?, ?, ?) ON CONFLICT (tbl, key) DO UPDATE SET value = excluded.value", [table, key, JSON.stringify(row)]);
  }

  delete<T extends TableName>(table: T, key: string): void {
    this.guard();
    this.db.run("DELETE FROM kv WHERE tbl = ? AND key = ?", [table, key]);
  }

  list<T extends TableName>(table: T, prefix = ""): readonly [string, Tables[T]][] {
    return this.range(table, { prefix });
  }

  /**
   * One primary-key search: a prefix becomes the key bounds `[prefix, successor(prefix))`, so
   * every query is `tbl = ? AND key > ? AND key < ?` on the (tbl, key) index, never a filter
   * over the table's rows (`SqliteStore` tests check the query plan).
   */
  range<T extends TableName>(table: T, q: KeyRange): readonly [string, Tables[T]][] {
    const where = ["tbl = ?"];
    const params: SqlValue[] = [table];
    const bounds: [string, string | undefined][] = [[">=", q.gte], [">", q.gt], ["<", q.lt], ["<=", q.lte]];
    if (q.prefix) {
      bounds.push([">=", q.prefix]);
      const upper = keySuccessor(q.prefix);
      if (upper !== undefined) bounds.push(["<", upper]);
    }
    for (const [op, bound] of bounds) {
      if (bound === undefined) continue;
      where.push(`key ${op} ?`);
      params.push(bound);
    }
    let sql = `SELECT key, value FROM kv WHERE ${where.join(" AND ")} ORDER BY key${q.reverse ? " DESC" : ""}`;
    if (q.limit !== undefined) {
      sql += " LIMIT ?";
      params.push(Math.max(0, Math.floor(q.limit)));
    }
    return this.db.all<{ key: string; value: string }>(sql, params).map((r) => [r.key, JSON.parse(r.value) as Tables[T]]);
  }

  count(table: TableName): number {
    return this.db.all<{ n: number }>("SELECT count(*) AS n FROM kv WHERE tbl = ?", [table])[0]?.n ?? 0;
  }

  handoff<R>(start: () => Promise<R>): Promise<R> {
    this.guard();
    return start();
  }

  private guard(): void {
    if (this.readOnly) throw new KavachError("STORAGE_FAILURE", "sqliteStore", "write outside a transaction");
  }
}

/** The smallest string greater than every string with this prefix, or `undefined` when there is none. */
function keySuccessor(prefix: string): string | undefined {
  const units = [...prefix].map((c) => c.codePointAt(0) ?? 0);
  while (units.length > 0) {
    const last = units[units.length - 1] ?? 0;
    if (last < 0x10ffff) {
      units[units.length - 1] = last + 1 === 0xd800 ? 0xe000 : last + 1;
      return String.fromCodePoint(...units);
    }
    units.pop();
  }
  return undefined;
}

function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

// Drivers ----------------------------------------------------------------------------------------

/** The subset of `expo-sqlite`'s `SQLiteDatabase` the driver needs. */
export interface ExpoSqliteDatabaseLike {
  execSync(sql: string): void;
  runSync(sql: string, params: SqlValue[]): unknown;
  getAllSync<T>(sql: string, params: SqlValue[]): T[];
  closeSync?(): void;
}

/**
 * Open with `SQLite.openDatabaseSync(name, { useNewConnection: true })` after enabling SQLCipher
 * through the `expo-sqlite` config plugin (`useSQLCipher: true`), and exclude the file from
 * backups (`FileSystem` on iOS sets `isExcludedFromBackup`; Android's auto-backup rules omit it).
 */
export function expoSqliteDriver(db: ExpoSqliteDatabaseLike): SqlDriver {
  return {
    exec: (sql) => db.execSync(sql),
    run: (sql, params = []) => {
      db.runSync(sql, [...params]);
    },
    all: <T>(sql: string, params: readonly SqlValue[] = []) => db.getAllSync<T>(sql, [...params]),
    close: () => db.closeSync?.()
  };
}

/** The subset of Node's `node:sqlite` `DatabaseSync` the test driver needs. */
export interface NodeSqliteDatabaseLike {
  exec(sql: string): void;
  close?(): void;
  prepare(sql: string): { run(...params: SqlValue[]): unknown; all(...params: SqlValue[]): unknown[] };
}

/** For Node tests: a real SQLite engine with real `BEGIN IMMEDIATE` semantics, without SQLCipher. */
export function nodeSqliteDriver(db: NodeSqliteDatabaseLike): SqlDriver {
  return {
    exec: (sql) => db.exec(sql),
    run: (sql, params = []) => {
      db.prepare(sql).run(...params);
    },
    all: <T>(sql: string, params: readonly SqlValue[] = []) => db.prepare(sql).all(...params) as T[],
    close: () => db.close?.()
  };
}
