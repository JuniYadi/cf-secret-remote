# Architecture decision records

Product detail lives in `DESIGN.md`. These records state the decisions that code must follow. Change one by adding a new record that supersedes it. A feature is done when each rule in its ADR has a test (ADR 26).

## Records

| # | Decision | Status |
|---|---|---|
| [1](0001-cloudflare-only-free-tier.md) | Cloudflare only, free tier | in place |
| [2](0002-end-to-end-encryption.md) | End-to-end encryption | implemented in `core` |
| [3](0003-groups-keyring-per-prefix.md) | Groups per path prefix | partly (create); rotation in 14 |
| [4](0004-identity-and-auth.md) | Identity and auth | implemented |
| [5](0005-policies-default-deny.md) | Policies | implemented |
| [6](0006-hash-chained-audit.md) | Hash-chained audit | implemented; checkpoints in 19 |
| [7](0007-recovery-under-e2e.md) | Recovery under E2E | see 20 |
| [8](0008-agent-safe-proxy.md) | Agent-safe proxy | see 17 |
| [9](0009-monorepo-worker-serves-web.md) | Monorepo, Worker serves web | implemented |
| [10](0010-secret-payload-and-key-hierarchy.md) | Secret payload and key hierarchy | implemented |
| [11](0011-cli-login-device-code.md) | CLI login: device code | implemented (web approve screen pending) |
| [12](0012-cli-unlock-and-local-state.md) | CLI unlock and local state | implemented; keychain in 25 |
| [13](0013-cli-host-config-and-run.md) | CLI host, config and run | partly; rest in 25 |
| [14](0014-membership-and-rotation.md) | Membership and key rotation | implemented |
| [15](0015-apps-and-bots-lifecycle.md) | Apps and bots lifecycle | implemented |
| [16](0016-access-requests.md) | Access requests with approval | implemented |
| [17](0017-agent-proxy-and-rules.md) | Agent proxy and rules | implemented |
| [18](0018-alerts-and-notifications.md) | Alerts and notifications | implemented |
| [19](0019-audit-retention-and-quota.md) | Audit checkpoints, retention, quota | implemented |
| [20](0020-recovery-and-vault-password.md) | Recovery, vault password, admins | implemented |
| [21](0021-offboarding.md) | Offboarding | implemented |
| [22](0022-secrets-versions-and-metadata.md) | Versions, history, import, metadata | implemented |
| [23](0023-backup-and-restore.md) | Backup and restore | implemented |
| [24](0024-web-app.md) | Web app | in progress (1/5) |
| [25](0025-deploy-and-distribution.md) | Deploy, init, hosts, releases | implemented |
| [26](0026-testing-strategy.md) | Testing strategy | implemented |
| [27](0027-hardening-and-limits.md) | Hardening and rate limits | planned |

## Build order

Tests first, then each layer in the order the ADRs depend on each other: `core`, `api`, `cli`, `web`.

1. **26** test harness (API integration tests, e2e script, CI), so every later step is tested as it lands.
2. **27** throttle, input limits, token handling (small, touches every route).
3. **14** membership and rotation, then **15** apps and bots (needed to give apps a key).
4. **22** versions, fingerprints, history, import, metadata.
5. **19** checkpoints, retention, quota, cron. Then **18** alerts (they hook into the audit writer).
6. **16** access requests, then **17** agent proxy and rules.
7. **20** recovery and vault password, then **21** offboarding.
8. **23** backup and restore.
9. **25** deploy, init, keychain, releases.
10. **24** web app, screen by screen, using the API as built.

## Working agreement

- One GitHub issue per ADR feature, one PR per issue (`Closes #N`). The PR updates the Status column above.
- Reserved migrations (to avoid number clashes): 0004 ADR 14, 0005 ADR 15, 0006 ADR 22, 0007 ADR 19, 0008 ADR 18, 0009 ADR 16, 0010 ADR 17, 0011 ADR 20. Others use the next free number and rebase.
- Each feature owns its files: `apps/api/src/routes/<feature>.ts` and `apps/cli/src/commands/<feature>.ts` (already registered). Shared files are touched only when the ADR says so.
- API tests live in `apps/api/test` (real Workers runtime and D1) and use `test/helpers.ts`.
