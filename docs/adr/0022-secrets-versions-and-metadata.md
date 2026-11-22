# 22. Secret versions, history, import, and metadata

Status: accepted, implemented

## Decision
- **Fingerprints for diffs.** The client stores, per version, `fps = { NAME: hex(HMAC-SHA256(groupKey, "fp|<path>|<NAME>|<value>")[0..8]) }` in clear. The UI can then show added, changed, removed names between versions without revealing values; guessing a value needs the group key.
- **Restore.** The client opens an older version and writes its values as a **new** version (never edits history). The UI warns that old values may have leaked.
- **Access history.** `GET /secret/history?path=` aggregates `audit` rows for the path: counts over 30 days, distinct readers, last reader, and per person whether they still have access. "Opened" means ciphertext fetched.
- **Import.** Parsing and preview are client-side. `.env` (`KEY=value`, quotes, `export`, comments) and JSON (flat object). Merge strategy chosen per import: add only, overwrite, or replace all. Booleans and numbers in JSON are stored as the strings `true`/`false`/the number text; the JSON tab shows them typed when a value is exactly a boolean or number and converts back to strings on save.
- **Metadata (cleartext).** `secret.meta = { description, owner, rotateBy }`. Owner is an identity; `rotateBy` is a date. The list view flags overdue items, and an alert rule `rotate_overdue` may be turned on (ADR 18).
- **Delete.** Soft delete (`deleted_at`), restorable by an admin for 30 days, then purged by cron.

## Consequences
Schema: `secret_version.fps`, `secret.meta`. API: `GET /secret/history`, `PUT /secret/meta`, `POST /secret/restore-delete`.
