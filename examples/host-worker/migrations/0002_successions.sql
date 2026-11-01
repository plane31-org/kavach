-- Revision 9 (amendment A1): account ids, the succession log, replacement authorizations and sharing preferences.
ALTER TABLE accounts ADD COLUMN account_id TEXT;
UPDATE accounts SET account_id = identity_id WHERE account_id IS NULL;
CREATE TABLE IF NOT EXISTS successions (
  succession_id TEXT PRIMARY KEY,
  account_name TEXT NOT NULL,
  account_id TEXT NOT NULL,
  previous_generation TEXT NOT NULL,
  new_generation TEXT NOT NULL,
  wire TEXT NOT NULL,
  certificate TEXT NOT NULL,
  certificate_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS successions_account ON successions (account_id);
CREATE TABLE IF NOT EXISTS authorizations (
  token TEXT PRIMARY KEY,
  account_name TEXT NOT NULL,
  succession_id TEXT NOT NULL,
  expected_certificate_hash TEXT NOT NULL,
  certificate_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS preferences (account_id TEXT NOT NULL, circle_id TEXT NOT NULL, enabled INTEGER NOT NULL, revision TEXT NOT NULL, PRIMARY KEY (account_id, circle_id));
