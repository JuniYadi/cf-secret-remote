-- ADR 29: login content, including its name and URL, is always encrypted.
CREATE TABLE login (
  id TEXT PRIMARY KEY,
  keyring_id TEXT NOT NULL REFERENCES keyring(id),
  current INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER
);

CREATE TABLE login_version (
  login_id TEXT NOT NULL REFERENCES login(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  keyring_id TEXT NOT NULL REFERENCES keyring(id),
  keyring_version INTEGER NOT NULL,
  wrapped_dek TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  fps TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES identity(id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (login_id, version)
);
CREATE INDEX idx_login_keyring ON login(keyring_id);
