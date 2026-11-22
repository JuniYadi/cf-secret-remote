-- A personal keyring belongs to exactly one identity and cannot be shared.
ALTER TABLE keyring ADD COLUMN personal_owner TEXT REFERENCES identity(id);
CREATE UNIQUE INDEX idx_keyring_personal_owner ON keyring(personal_owner) WHERE personal_owner IS NOT NULL;
CREATE TRIGGER personal_keyring_member_insert BEFORE INSERT ON keyring_member
WHEN EXISTS (SELECT 1 FROM keyring WHERE id = NEW.keyring_id AND personal_owner IS NOT NULL AND personal_owner != NEW.identity_id)
BEGIN SELECT RAISE(ABORT, 'personal keyring cannot be shared'); END;
CREATE TRIGGER personal_keyring_member_update BEFORE UPDATE OF keyring_id, identity_id ON keyring_member
WHEN EXISTS (SELECT 1 FROM keyring WHERE id = NEW.keyring_id AND personal_owner IS NOT NULL AND personal_owner != NEW.identity_id)
BEGIN SELECT RAISE(ABORT, 'personal keyring cannot be shared'); END;
CREATE TRIGGER personal_keyring_staged_insert BEFORE INSERT ON keyring_member_staged
WHEN EXISTS (SELECT 1 FROM keyring WHERE id = NEW.keyring_id AND personal_owner IS NOT NULL AND personal_owner != NEW.identity_id)
BEGIN SELECT RAISE(ABORT, 'personal keyring cannot be shared'); END;
