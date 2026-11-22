# 35. Deferred: agent-safe fill and account leases

Status: deferred (decision recorded, not scheduled)

## Deferred, on purpose
- **Agent-safe browser fill.** An AI agent driving a browser (Playwright MCP, computer use) asks to "log in as admin on shop-staging". A local tool fills the form and returns only success or failure, restricted by a host allowlist in policy, so the password never enters the model context. This extends ADR 8 and 17 from HTTP requests to forms.
- **Account lease.** A run checks out an account for N minutes; other runs get a different account or wait. It stops parallel jobs from locking each other's accounts and makes the audit read "run X used account Y".

## Decision for v1
- v1 returns credentials to the test runner (ADR 30), not to an LLM. Documentation says so, and tells people not to give agents raw passwords.
- Every access carries `--purpose` in the audit row, so lease can be added later without a log format change.
- Revisit lease when a QA team reports account conflicts, and agent fill after the CLI and extension are stable.

## Also not in v1
Firefox, Safari, mobile autofill, cards and identities, passkeys, file attachments, hosted SaaS, and wider self-hosting (ADR 28).
