# 31. Web: Logins screen

Status: implemented; import entry points in 33

## Decision
- New sidebar entry **Logins** (Indonesian: "Akun") beside Secrets: list with search, filters for keyring, environment, and role, and a detail view with Show/Copy per field, a live TOTP code with countdown, Versions tab, and Move to group.
- Password and TOTP seed are hidden again after 30 seconds; copy clears the clipboard after 30 seconds where the browser allows (same rule as ADR 24).
- Create/edit form: name, URL, environment, role, username, password (with a generator), TOTP, notes. Environment and role suggest earlier values from the decrypted list.
- Empty, loading, and error states, keyboard operation, and contrast follow ADR 24.
- All text is English with an Indonesian translation (CLAUDE.md rule).
- Import entry points (ADR 33) are added here later.

## Consequences
New routes under `apps/web/src/`. No server change beyond ADR 29. A Playwright smoke test covers create, reveal, TOTP, and move.
