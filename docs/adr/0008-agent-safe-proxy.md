# 8. Agent-safe local proxy

Status: accepted, detailed by [17](0017-agent-proxy-and-rules.md)

## Decision
`cfs proxy` runs locally and injects secrets into outgoing requests so an AI agent never sees values. It enforces a host allowlist, per-agent budgets, a required reason, and human approval for `*/prod`.

## Consequences
Planned. Needs CLI first.
