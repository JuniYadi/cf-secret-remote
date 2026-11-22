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
