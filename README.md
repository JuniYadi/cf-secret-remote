# cf-secret-remote

A secret vault that runs entirely on Cloudflare's free tier. Secrets are locked in the browser or CLI before they are saved, so the server never holds a readable value. Every access is recorded.

Status: skeleton only. No logic yet. The design lives in [`DESIGN.md`](DESIGN.md), and the screens are in `design/`.

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

## Layout
```
apps/
  api/    Worker (Hono) + D1 migrations. Also serves the web app as static assets.
  web/    Single-page app.
  cli/    `cfs` command line, compiled to one binary with Bun.
packages/
  core/   Crypto (WebCrypto only), kit format, schemas, fingerprint code. Shared by all three.
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
