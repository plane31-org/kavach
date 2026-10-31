CREATE TABLE IF NOT EXISTS accounts (
  account_name TEXT PRIMARY KEY,
  account_key TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  certificate TEXT NOT NULL,
  certificate_hash TEXT NOT NULL,
  generation TEXT NOT NULL,
  vault TEXT,
  vault_revision TEXT,
  vault_hash TEXT,
  reset_receipt TEXT
);
CREATE INDEX IF NOT EXISTS accounts_identity ON accounts (identity_id);
CREATE TABLE IF NOT EXISTS identities (identity_id TEXT PRIMARY KEY, account_name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS certificates (certificate_hash TEXT PRIMARY KEY, account_name TEXT NOT NULL, wire TEXT NOT NULL, current INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device_ids (account_name TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY (account_name, device_id));
CREATE TABLE IF NOT EXISTS circles (circle_id TEXT PRIMARY KEY, owner_identity TEXT NOT NULL, snapshot TEXT NOT NULL, revision TEXT NOT NULL, hash TEXT NOT NULL, closed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS requests (circle_id TEXT NOT NULL, account_name TEXT NOT NULL, action TEXT NOT NULL, requested_at TEXT NOT NULL, PRIMARY KEY (circle_id, account_name, action));
CREATE TABLE IF NOT EXISTS receipts (reset_id TEXT PRIMARY KEY, account_name TEXT NOT NULL, wire TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subscriptions (stream_id TEXT NOT NULL, reader_certificate TEXT NOT NULL, author_identity TEXT NOT NULL, PRIMARY KEY (stream_id, reader_certificate));
CREATE INDEX IF NOT EXISTS subscriptions_reader ON subscriptions (reader_certificate);
CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, to_account TEXT NOT NULL, from_account TEXT NOT NULL, circle_id TEXT, at TEXT NOT NULL);
