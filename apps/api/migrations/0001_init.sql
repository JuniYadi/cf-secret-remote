-- cfs schema v1. The server stores ciphertext, wrapped keys and metadata only. Never plaintext values.

-- People (Cloudflare Access email) and apps/bots share one identity table.
CREATE TABLE identity (
  id            TEXT PRIMARY KEY,
  kind          TEXT NOT NULL CHECK (kind IN ('user','app')),
  name          TEXT NOT NULL,              -- email for users, label for apps
  role          TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
  public_key    TEXT,                       -- ECDH P-256 SPKI (base64url); null until vault is set up
  locked_key    TEXT,                       -- private key locked with the vault password (users only)
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at    INTEGER NOT NULL,
  UNIQUE (kind, name)
);

-- AppRole login: role_id public, secret_id stored as a hash only.
CREATE TABLE app_role (
  identity_id   TEXT PRIMARY KEY REFERENCES identity(id) ON DELETE CASCADE,
  role_id       TEXT NOT NULL UNIQUE,
  secret_hash   TEXT NOT NULL,
  token_ttl     INTEGER NOT NULL DEFAULT 3600,
  max_uses      INTEGER,                    -- null = unlimited
  uses          INTEGER NOT NULL DEFAULT 0,
  cidr          TEXT,                       -- optional allowlist, comma separated
  expires_at    INTEGER
);

-- A group (keyring) covers one top-level path prefix. Members hold a wrapped copy of its key.
CREATE TABLE keyring (
  id            TEXT PRIMARY KEY,
  prefix        TEXT NOT NULL UNIQUE,       -- e.g. "payments"
  version       INTEGER NOT NULL DEFAULT 1, -- bumps when a member is removed (rotation)
  created_at    INTEGER NOT NULL
);

CREATE TABLE keyring_member (
  keyring_id    TEXT NOT NULL REFERENCES keyring(id) ON DELETE CASCADE,
  identity_id   TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  version       INTEGER NOT NULL,
  wrapped_key   TEXT NOT NULL,              -- keyring key wrapped to the member's public key
  PRIMARY KEY (keyring_id, identity_id, version)
);

-- Secrets: one row per path, one row per version. Values are AES-GCM envelopes.
CREATE TABLE secret (
  id            TEXT PRIMARY KEY,
  path          TEXT NOT NULL UNIQUE,       -- e.g. "payments/prod"
  keyring_id    TEXT NOT NULL REFERENCES keyring(id),
  current       INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  deleted_at    INTEGER
);

CREATE TABLE secret_version (
  secret_id     TEXT NOT NULL REFERENCES secret(id) ON DELETE CASCADE,
  version       INTEGER NOT NULL,
  keyring_version INTEGER NOT NULL,
  names         TEXT NOT NULL,              -- JSON array of key names (names are not secret)
  wrapped_dek   TEXT NOT NULL,              -- per-version DEK wrapped with the keyring key
  ciphertext    TEXT NOT NULL,              -- envelope of the values
  created_by    TEXT NOT NULL REFERENCES identity(id),
  created_at    INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version)
);

-- Permissions: path glob + capabilities, attached to identities. Default deny.
CREATE TABLE policy (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  rules         TEXT NOT NULL               -- JSON: [{ "path": "payments/*", "caps": ["read","list"] }]
);

CREATE TABLE identity_policy (
  identity_id   TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  policy_id     TEXT NOT NULL REFERENCES policy(id) ON DELETE CASCADE,
  expires_at    INTEGER,                    -- set by approved access requests
  PRIMARY KEY (identity_id, policy_id)
);

CREATE TABLE session (
  token_hash    TEXT PRIMARY KEY,
  identity_id   TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL CHECK (kind IN ('cli','app')),
  device        TEXT,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL
);

-- Hash-chained audit log. `hash` covers prev hash + entry (see @cfs/core audit).
CREATE TABLE audit (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  at            INTEGER NOT NULL,
  entry         TEXT NOT NULL,              -- canonical JSON: who, action, path, version, ip, result
  prev          TEXT NOT NULL UNIQUE,       -- previous hash; UNIQUE stops two writers forking the chain
  hash          TEXT NOT NULL
);

CREATE INDEX idx_secret_version_by ON secret_version(created_by);
CREATE INDEX idx_audit_at ON audit(at);
CREATE INDEX idx_session_exp ON session(expires_at);
