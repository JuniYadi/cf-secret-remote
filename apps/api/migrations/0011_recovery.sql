-- ADR 20: recovery requests, the vault password lock, and the optional recovery key.

-- Private key sealed under a key derived from the 24-word recovery key (rk1.*). Null until the person sets one.
ALTER TABLE identity ADD COLUMN recovery_locked_key TEXT;

-- A forgotten-password request. The new public key and locked key are pending and immutable (see the trigger).
-- 'granted' and 'locked' rows stay for the record. A cancelled request is deleted.
CREATE TABLE recovery_request (
  id            TEXT PRIMARY KEY,
  identity_id   TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  public_key    TEXT NOT NULL,              -- ECDH P-256 SPKI, new key pair made in the browser
  locked_key    TEXT NOT NULL,              -- new private key locked with the new vault password
  cancel_hash   TEXT NOT NULL,              -- sha256 of the cancel link token; the token itself is never stored
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','granted','locked')),
  attempts      INTEGER NOT NULL DEFAULT 0, -- wrong four-word codes typed by admins; locked at 5
  resolved_by   TEXT,                       -- admin identity id that granted it
  created_at    INTEGER NOT NULL,
  resolved_at   INTEGER
);

-- At most one open request per person.
CREATE UNIQUE INDEX idx_recovery_one_pending ON recovery_request(identity_id) WHERE status = 'pending';

CREATE TRIGGER recovery_request_key_immutable
BEFORE UPDATE OF public_key, locked_key ON recovery_request
BEGIN
  SELECT RAISE(ABORT, 'pending recovery key is immutable');
END;
