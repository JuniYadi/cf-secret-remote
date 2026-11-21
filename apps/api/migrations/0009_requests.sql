-- ADR 16: access requests with approval. Time-boxed grants carry expires_at on keyring_member and identity_policy.

-- One row per request. `expires_at` is the end of the granted access (set on approval). A pending request
-- auto-expires 24 h after `created_at` (see requests-sweep.ts).
CREATE TABLE access_request (
  id            TEXT PRIMARY KEY,
  requester_id  TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  path_glob     TEXT NOT NULL,
  group_prefix  TEXT NOT NULL,
  reason        TEXT NOT NULL,
  duration      INTEGER NOT NULL,           -- seconds of access once approved (max 24 h)
  rekey_after   INTEGER NOT NULL DEFAULT 0 CHECK (rekey_after IN (0,1)),
  status        TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','approved','denied','cancelled','expired')),
  approver_id   TEXT REFERENCES identity(id),
  created_at    INTEGER NOT NULL,
  decided_at    INTEGER,
  expires_at    INTEGER
);

CREATE INDEX idx_access_request_status ON access_request(status, created_at);
CREATE INDEX idx_access_request_requester ON access_request(requester_id);

-- NULL means permanent membership. Approved requests set it; the sweep deletes lapsed rows.
ALTER TABLE keyring_member ADD COLUMN expires_at INTEGER;
