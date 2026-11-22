# 29. Login item

Status: implemented in core and api; CLI in 30, web in 31

## Decision
- **One new item type: Login.** Fields: `name`, `url`, `environment`, `role`, `username`, `password`, `totp` (seed or `otpauth://` URI), `notes`. A site can have many Logins (one per role and environment); they may share a site and environment.
- **Everything is encrypted, including name and URL.** The server sees only `id`, the owning keyring, version, timestamps, and sizes. Search, filtering by `environment` and `role`, and URL matching run in the client over the decrypted list. Policies on path prefixes (ADR 5) do not apply to Logins; access follows the keyring.
- **Same crypto as Secrets** (ADR 10): a random DEK per version, wrapped to the keyring key. The plaintext is a versioned JSON payload (`{ v: 1, name, url, ... }`). Secrets keep their current format, so nothing existing changes.
- **Keyrings.** Every user gets a **personal keyring** with only that user as member, created when the vault is set up (and on first use for existing users). Team Logins live in group keyrings (ADR 3). Moving a Login to a group means re-wrapping its DEK to the group key and writing a new version; there is no share-to-one-person screen in v1.
- **Versions and restore** follow ADR 22, except that fingerprints are over fields, not names. Delete is soft with the same 30-day window.
- **TOTP** is computed in the client (RFC 6238, WebCrypto HMAC). Nothing is written to the server when a code is shown; revealing the seed is audited.
- **Limits.** Login ciphertext at most 64 KB. List sync is one request (`GET /api/v1/logins` with an `ETag`), not per item.
- **Audit.** One row for reveal, fill, create, update, restore, delete, and move. List and sync write nothing. The row holds the Login id, version, and identity, never the name or URL.

## Consequences
New core module `login.ts` and a shared test vector in `packages/core/test-vectors`, checked in both the browser and the CLI (CLAUDE.md rule). Schema: `login`, `login_version`. API: `/api/v1/logins`. Personal keyring creation is part of vault setup.
