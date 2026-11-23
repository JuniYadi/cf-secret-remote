# 30. CLI and SDK for Logins

Status: implemented; SDK not published yet

## Decision
- **Commands.** `cfs login` is already the sign-in command (ADR 11), so Login items live under `cfs account`:
  - `cfs account get <name> [--env E] [--role R] [--show] [--json]` prints the username; use `--show` to reveal the password on a terminal, or `--json` for credentials and the current TOTP code.
  - `cfs account list`, `add`, `edit`, `rm`, `totp <name>`.
  - `cfs run` accepts `--account <name>[:env[:role]]` and injects `CFS_<NAME>_USER`, `CFS_<NAME>_PASS` and `CFS_<NAME>_TOTP` (names normalised to `[A-Z0-9_]`).
- **Lookup is client-side.** The CLI fetches the encrypted list, decrypts it, and matches on name, `environment`, and `role`. An ambiguous match is an error that lists the candidates; it never picks one.
- **Identity.** Humans use the unlocked key (ADR 12). Pipelines and agents use an AppRole kit (ADR 15) with access to the keyring, the same as for Secrets.
- **`--purpose`** is recorded in the audit row so a run can be traced (for example a CI run id).
- **`@cfs/sdk`** (Node and Bun): `getAccount({ name, env, role })` returning `{ username, password, totp() }`, built on `@cfs/core` and the kit. Intended for Playwright and Cypress setup files. Published after the CLI commands are stable.
- Secrets are never printed to a TTY by default without `--show`; `--json` is for pipes.

## Consequences
`apps/cli/src/commands/account.ts`, `packages/sdk`. Tests: CLI e2e against `wrangler dev`, plus the shared Login test vector (ADR 29).
