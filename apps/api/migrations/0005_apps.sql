-- ADR 15: apps and bots lifecycle. Owner, first and last sign-in, and the last seen IP.
ALTER TABLE identity ADD COLUMN owner_id TEXT REFERENCES identity(id);
ALTER TABLE app_role ADD COLUMN first_login_at INTEGER;
ALTER TABLE app_role ADD COLUMN last_login_at INTEGER;
ALTER TABLE app_role ADD COLUMN last_ip TEXT;
