# cf-secret-remote

A secret vault that runs entirely on Cloudflare's free tier. Secrets are locked in the browser or CLI before they are saved, so the server never holds a readable value. Every access is recorded.

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

## Login accounts

After signing in and unlocking, add an encrypted login with `cfs account add shop --group team --env staging --role admin --username alice`. Enter the password at the hidden prompt, or pipe it on stdin. Omit `--group` for your personal keyring. Optional fields include `--url`, `--totp` (seed or URI), and `--notes`.

Use `cfs account list`, `cfs account get shop --env staging --role admin`, `cfs account totp shop`, `cfs account edit shop`, or `cfs account rm shop`. Use `--show` to reveal a password on a terminal, or `--json` for a pipe. Add `--purpose` to record why credentials were revealed.

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
