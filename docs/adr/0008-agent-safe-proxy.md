# 8. Agent-safe local proxy

Status: accepted

## Decision
`cfs proxy` runs locally and injects secrets into outgoing requests so an AI agent never sees values. It enforces a host allowlist, per-agent budgets, a required reason, and human approval for `*/prod`.

## Consequences
Planned. Needs CLI first.
