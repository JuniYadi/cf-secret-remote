# 19. Audit checkpoints, retention, and free-tier quota

Status: accepted, implemented

## Context
ADR 6 requires a daily head hash. D1 free writes are limited. DESIGN.md defines behaviour at quota; the mechanics are missing.

## Decision
- **Cron.** One Workers Cron Trigger at 00:05 UTC runs: checkpoint, expiry sweep (ADR 16), retention, backup (ADR 23), usage reset.
- **Checkpoint.** Store `{ day, seq, head }` in `checkpoint`; send it to the webhook and admin email. `cfs audit verify` checks the chain, and compares the head at each stored checkpoint.
- **Retention.** Default 365 days (setting). Pruning writes a checkpoint first, then deletes rows older than the cutoff and stores the last deleted hash as `audit_base`; verification starts from `audit_base` instead of `genesis`. Minimum 90 days (offboarding needs it).
- **Usage meter.** `usage_day(day, writes, reads_logged)` increments with each write batch (an estimate; D1's own counters are authoritative). The UI shows used / 100k with a warning at 80% (ADR 18).
- **At quota.** If a D1 write fails with a quota error: secret writes, group changes and invites return 503 with `Retry-After` until 00:00 UTC. Reads, logins and decryption keep working (fail-open for reads). Failed audit appends are emitted to Workers Logs as `cfs_audit_pending` and, when writes resume, one `audit.gap` row is appended with the time range, so the chain shows that entries are missing rather than hiding it.
- **Batching.** Audit appends for a single request are combined into one insert.

## Consequences
A gap marker is honest but not a record of who read what during the gap; the docs say so.
