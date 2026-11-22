# 26. Testing strategy

Status: accepted, implemented

## Decision
- **Core.** Unit tests plus shared test vectors in `packages/core/test-vectors` (fixed keys, IVs, expected envelopes, wrapped-key opens, kit strings, fingerprint words, audit chain). Run in Bun/Node (Vitest) and in a real browser (Playwright) so both runtimes agree.
- **API.** Integration tests run the Worker with `@cloudflare/vitest-pool-workers` (real D1, migrations applied per test file). Each ADR's rules get tests: default-deny, gates, version conflicts, rotation commit/abort, request expiry, throttling, chain verification, quota fallback.
- **Security tests.** The API must never return plaintext: a test writes a secret with a known marker and greps every response and every D1 row for it. Same for logs.
- **End to end.** One script boots `wrangler dev` with a fresh local D1, then drives the real CLI through login, unlock, groups, set/get/run, app kit, requests, rotation, offboarding, backup/restore. It runs in CI on every push.
- **CI.** GitHub Actions: install, lint, typecheck, test, e2e, build the CLI. Releases from tags.
- **Rule.** A feature is done when its ADR rules each have a test.
