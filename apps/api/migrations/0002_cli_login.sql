-- Device-code login for the CLI (ADR 11). Only hashes of the device code are stored.
CREATE TABLE cli_login (
  device_hash   TEXT PRIMARY KEY,
  user_code     TEXT NOT NULL UNIQUE,
  identity_id   TEXT REFERENCES identity(id) ON DELETE CASCADE,
  device        TEXT,
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','used')),
  expires_at    INTEGER NOT NULL
);
