# 16. Access requests with approval

Status: accepted (not implemented yet)

## Context
Production access should be time-boxed and approved. Under E2E an approver must hand over a key, so the server alone cannot grant it.

## Decision
- **Request.** `POST /requests { path, reason, duration }` (max 24 h, set by an admin setting). Rows live in `access_request(id, requester_id, path_glob, group_prefix, reason, duration, status, approver_id, created_at, decided_at, expires_at)`. Status: `pending`, `approved`, `denied`, `cancelled`, `expired`.
- **Notify.** A Slack-compatible webhook message with the requester, path, reason, duration and a link to the approval screen (ADR 18). Email is second. Approving never happens inside Slack, because it needs a vault.
- **Approve.** The approver (an admin who is a member of the group, vault unlocked) wraps the group key to the requester's public key and calls `POST /requests/:id/approve`. In one batch the server: stores a `keyring_member` row with `expires_at`, grants a time-boxed `identity_policy` (`expires_at`), and marks the request approved. Self-approval is refused.
- **Expiry.** Both rows carry `expires_at`; the server refuses to serve the wrapped key or ciphertext after it (gate 1 of ADR 2). A cron sweep (ADR 19) deletes expired rows. Because the requester held the key, an optional "re-key the group after expiry" flag runs rotation (ADR 14).
- **Agents and prod.** Agent access to a path matching `*/prod` requires an approved request per session (ADR 17).
- **CLI.** `cfs request <path> --reason … --for 2h`, `cfs requests`, `cfs approve <id>`, `cfs deny <id>`. `cfs run --env prod` asks "Load production secrets? y/N" and, if policy requires, creates a request and waits.

## Consequences
The approver must be online. Requests auto-expire after 24 h if undecided. Every state change is audited.
