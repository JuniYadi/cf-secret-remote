# 23. Backup and restore

Status: accepted (not implemented yet)

## Decision
- **Export.** `GET /backup` (admin) streams a `.cfsbackup` file: gzip JSON of `identity`, `app_role` (hashes only), `keyring`, `keyring_member`, `secret`, `secret_version`, `policy`, `identity_policy`, `agent_rule`, `setting` (webhook masked out), `audit`, `checkpoint`, with a `schema` version and a SHA-256 of the body. Sessions and CLI login codes are excluded. Values stay encrypted, but paths, names, emails and dates are clear, so the file can be sealed with a passphrase (AES-GCM, PBKDF2) chosen at export. The UI says so plainly.
- **Scheduled.** If an R2 binding `BACKUP` exists, the daily cron (ADR 19) writes the file and keeps the last 30. R2 is optional (ADR 9); without it, manual download only.
- **Restore.** `cfs restore <file>` or the web screen. Steps: check hash and schema version, verify the audit chain, show counts and the time gap, require typing the host name, then replace tables in one ordered batch (chunked if large) while the instance is in maintenance (writes return 503). All sessions are invalidated, so everyone signs in again. A `restore` audit row records the event.

## Consequences
D1 free limits may make very large restores slow; the file reports sizes first.
