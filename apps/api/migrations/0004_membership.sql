-- ADR 14: group membership and key rotation.

-- 'rotating' blocks writes to the group (409) until commit or abort.
ALTER TABLE keyring ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','rotating'));

-- Wrapped keys for the next keyring version, staged during a rotation. Moved to keyring_member at commit, discarded at abort.
CREATE TABLE keyring_member_staged (
  keyring_id    TEXT NOT NULL REFERENCES keyring(id) ON DELETE CASCADE,
  identity_id   TEXT NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  version       INTEGER NOT NULL,
  wrapped_key   TEXT NOT NULL,
  PRIMARY KEY (keyring_id, identity_id, version)
);
