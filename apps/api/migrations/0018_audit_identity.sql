-- Actor metadata is outside the hashed entry. Only unambiguous historical names can be resolved.
ALTER TABLE audit ADD COLUMN identity_id TEXT;
ALTER TABLE audit ADD COLUMN identity_kind TEXT;
CREATE INDEX idx_identity_name_backfill ON identity(name);
UPDATE audit SET identity_id = (SELECT id FROM identity WHERE name = audit.who),
  identity_kind = (SELECT kind FROM identity WHERE name = audit.who)
WHERE (SELECT COUNT(*) FROM identity WHERE name = audit.who) = 1;
DROP INDEX idx_identity_name_backfill;
ALTER TABLE audit ADD COLUMN path TEXT GENERATED ALWAYS AS (json_extract(entry, '$.path')) VIRTUAL;
ALTER TABLE audit ADD COLUMN action TEXT GENERATED ALWAYS AS (json_extract(entry, '$.action')) VIRTUAL;
CREATE INDEX idx_audit_identity ON audit(identity_id);
CREATE INDEX idx_audit_path ON audit(path);
CREATE INDEX idx_audit_action ON audit(action);
