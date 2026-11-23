# 33. Import Logins

Status: core and CLI implemented; web import pending ADR 31

## Decision
- **Formats, in this order:** generic CSV (`site, environment, role, username, password, totp, notes`, which is what QA spreadsheets look like), Chrome password CSV, then Bitwarden JSON (unencrypted export only).
- **Client-side only.** Parsing, preview, and encryption happen in the browser or CLI (`cfs account import <file>`). The file is never sent to the server. The UI and CLI warn the person to delete the file afterwards.
- Preview shows rows, detected duplicates (same URL, environment, role, username), and errors. The person picks add only, skip duplicates, or overwrite, and the target keyring.
- No automatic plaintext export. Export uses encrypted backup (ADR 23).

## Consequences
Parsers live in `packages/core` as plain TypeScript (no Node or Bun APIs), so browser and CLI share them. Fixture files and tests per format.
