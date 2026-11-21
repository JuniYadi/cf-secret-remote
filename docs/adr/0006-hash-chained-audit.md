# 6. Tamper-evident, hash-chained audit

Status: accepted, retention and checkpoints detailed by [19](0019-audit-retention-and-quota.md)

## Decision
Each row stores prev and hash = SHA-256(prev, canonical JSON of the entry). `prev` is UNIQUE so two writers cannot fork the chain; writers retry. Entries hold identities, names, versions and results, never values. A daily head hash goes to a Slack webhook and admin email, so rewriting history is detectable. `cfs audit verify` and `/audit/verify` re-check the chain.

## Consequences
Detects tampering but cannot prevent a Cloudflare admin from deleting rows.
