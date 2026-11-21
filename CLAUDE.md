# cf-secret-remote

Bun workspaces monorepo. Follow the decisions in `docs/adr/`. Read `DESIGN.md` before changing behaviour: it records every product and protocol decision.

## Layout
- `apps/api`: Cloudflare Worker (Hono), D1 migrations in `apps/api/migrations`. Serves `apps/web/dist` as static assets.
- `apps/web`: SPA.
- `apps/cli`: `cfs`, built with `bun build --compile`.
- `packages/core`: crypto and shared formats. Imported by all apps as `@cfs/core`.
- `docs/adr/`: decisions. Implement from these; the index shows the build order and status.
- `design/`: UI canvas sources and brand SVGs. Not part of the build.

## Rules that must hold
- `packages/core` imports nothing but WebCrypto and plain TypeScript. No Node, Bun or Cloudflare APIs.
- The API never decrypts values and never logs them. Audit rows hold names, versions and identities only.
- Changes to the crypto format need a new shared test vector in `packages/core/test-vectors`, checked in both the browser and the CLI.
- UI text is English by default with an Indonesian translation. Keep both when editing a screen.

## Commands
`bun install`, `bun run typecheck`, `bun run test`, `bun run lint`, `bun run dev:api`.
