# 9. Bun monorepo; the Worker serves the web app

Status: accepted

## Decision
Bun workspaces: apps/api, apps/web, apps/cli, packages/core. The Worker serves the SPA as static assets (`run_worker_first: ["/api/*"]`, SPA fallback). No R2 for the web app. `core` imports only WebCrypto and has shared test vectors. R2 is optional and only for scheduled backups. Releases are CLI binaries plus a Worker bundle that `cfs deploy` installs. Build order: core, api, cli, web.

## Consequences
R2 needs a payment method and is not required.
