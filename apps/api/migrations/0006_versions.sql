-- ADR 22: per-name fingerprints per version, and cleartext metadata per secret.
-- fps: JSON { NAME: hex(8 bytes) }, computed by the client with the group key. Null for versions written before this.
ALTER TABLE secret_version ADD COLUMN fps TEXT;
-- meta: JSON { description?, owner?, rotateBy? }. Cleartext, never values.
ALTER TABLE secret ADD COLUMN meta TEXT;
