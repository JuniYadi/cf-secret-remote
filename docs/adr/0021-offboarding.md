# 21. Offboarding

Status: accepted (not implemented yet)

## Decision
`Offboard <person>` runs as a plan the admin reviews, then steps:
1. **Plan.** `GET /offboard/:id/plan` returns groups they belong to, apps they own, their active sessions, and the list of secrets they fetched in the last 90 days (from `audit`, by name and version).
2. **Execute (client-driven).** For each group, rotate without them (ADR 14). Reassign or disable owned apps (ADR 15). Then `POST /identities/:id/disable`, which ends sessions and removes policies.
3. **Report.** Show "values this person could open" for rotation at the source, as a downloadable list of names (never values).
4. **Reminder.** Removal from the company login happens at the identity provider, not here.

The operation is resumable: each step is idempotent and shown as done/pending. Every step is audited.

## Consequences
Offboarding is blocked if it would leave fewer than two admins (ADR 20).
