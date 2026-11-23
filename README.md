# cf-secret-remote

A vault for QA credentials and secrets, for a team or one person. It is for small technical teams—developers, QA, agencies, and startups—with a Cloudflare account. It runs on Cloudflare Workers and D1 in your own account; hosted SaaS is out of scope.

The server cannot read values ([ADR 2](docs/adr/0002-end-to-end-encryption.md)); hash-chained audit makes access provable ([ADR 6](docs/adr/0006-hash-chained-audit.md)); and machines and agents use AppRole to get credentials ([ADR 15](docs/adr/0015-apps-and-bots-lifecycle.md), [ADR 17](docs/adr/0017-agent-proxy-and-rules.md)). Login items and their CLI, web, extension, and import workflows are planned ([ADRs 29–33](docs/adr/README.md)).

This is not a general consumer password manager: v1 has no cards, identities, passkeys, or file attachments. Secure notes are Secrets. In v1, credentials are returned to the test runner, not an LLM. Do not give agents raw passwords; for HTTP keys, use the [agent-safe proxy](docs/adr/0017-agent-proxy-and-rules.md) ([ADR 35](docs/adr/0035-deferred-agent-fill-and-account-lease.md)).

The design lives in [`DESIGN.md`](DESIGN.md), and the screens are in `design/`.

## Install the CLI
Linux and macOS:
```
curl -fsSL https://raw.githubusercontent.com/JuniYadi/cf-secret-remote/main/install.sh | sh
```
Windows (PowerShell):
```
irm https://raw.githubusercontent.com/JuniYadi/cf-secret-remote/main/install.ps1 | iex
```
Both pick the right binary for your OS and CPU, check it against the release `SHA256SUMS`, and install it as `cfs` (`~/.local/bin` or `%LOCALAPPDATA%\cfs\bin`). Pin a version with `sh -s -- v0.0.1`. Later, `cfs upgrade` updates it.

For CI or end-to-end tests without an OS keychain, set `CFS_UNLOCK_STORE=file` to force unlocked keys into `unlock.json` in the cfs config directory (`~/.config/cfs` by default, or `CFS_CONFIG_DIR`). This also avoids touching a real keychain when one is available. The file is mode 0600 and contains the unlocked private key; `cfs lock` removes it, and an expired entry is deleted on the next unlock-store read. Protect the directory and use an isolated config directory for tests.

## Agent proxy and backups

Run `cfs proxy` as a separate OS user or in a separate container from the agent, and keep `CFS_KIT` inaccessible to the agent. An agent that can read the kit on the same machine can use it directly and bypass the proxy.

If the optional R2 backup binding is configured, the scheduled backup is an unsealed gzip copy: secret values remain encrypted, but paths, names, emails and other metadata are readable. Keep the bucket private, disable public access, and restrict API tokens to only the access needed. Manual exports can be sealed with a passphrase; see [ADR 23](docs/adr/0023-backup-and-restore.md).

## Login accounts

After signing in and unlocking, add an encrypted login with `cfs account add shop --group team --env staging --role admin --username alice`. Enter the password at the hidden prompt, or pipe it on stdin. Omit `--group` for your personal keyring. Optional fields include `--url`, `--totp` (seed or URI), and `--notes`.

Use `cfs account list`, `cfs account get shop --env staging --role admin`, `cfs account totp shop`, `cfs account edit shop`, or `cfs account rm shop`. Use `--show` to reveal a password on a terminal, or `--json` for a pipe. Add `--purpose` to record why credentials were revealed.

Import logins with `cfs account import passwords.csv [--format csv|chrome|bitwarden] [--group team] [--mode add|skip|overwrite] [--yes]`. The format is detected by default, the personal keyring is used unless `--group` is given, and the default mode skips duplicates. The CLI previews counts and errors and asks for confirmation unless `--yes` is supplied. Parsing and encryption happen locally; delete the plaintext file after importing. Bitwarden exports must be unencrypted. Encrypted backups are available instead of plaintext export.

`cfs run --account shop:staging:admin --purpose ci-run -- command` injects `CFS_SHOP_USER`, `CFS_SHOP_PASS`, and `CFS_SHOP_TOTP` into the child. Repeat `--account` for more accounts. AppRole kits work through `CFS_KIT`. The private [SDK](packages/sdk/README.md) supports test setup; give credentials to the test runner, not to an LLM.

## Layout
```
apps/
  api/    Worker (Hono) + D1 migrations. Also serves the web app as static assets.
  web/    Single-page app.
  cli/    `cfs` command line, compiled to one binary with Bun.
packages/
  core/   Crypto (WebCrypto only), kit format, schemas, fingerprint code. Shared by all three.
  sdk/    Private Node and Bun account SDK (not published yet).
design/   UI canvas, brand files.
```

## Commands
```
bun install
bun run dev:api      # wrangler dev (serves apps/web/dist)
bun run build:web
bun run build:cli
bun run typecheck
bun run test
bun run lint
```

## Rules
- `packages/core` uses WebCrypto only. No Node or Bun APIs, so it runs in the browser, in Workers, and in the CLI unchanged.
- The server never decrypts anything. It stores ciphertext and wrapped keys.
- One Worker serves the API and the web app, on one hostname.
