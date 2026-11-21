# 18. Alerts and notifications

Status: accepted (not implemented yet)

## Context
Alerts are a differentiator (DESIGN.md). Channels and thresholds need defining within free-tier limits.

## Decision
- **Channels.** A Slack-compatible webhook (JSON `{ "text": … }`), configured by an admin in Settings, stored in `setting` (admin-only; the API returns it masked). Optional email through the Workers `send_email` binding to verified admin addresses.
- **Rules (default on).** `blocked` (any denied request), `agent_prod_read`, `new_network` (first login from an unseen IP /24 or network per identity), `read_burst` (more than 20 reads in 5 minutes per identity), `quota_80`, `chain_broken`, `recovery_requested`, `access_request`. Each rule can be toggled per channel.
- **Evaluation.** After an audit row is written, `ctx.waitUntil(evaluate(entry))`. Burst and new-network checks query `audit` with indexes on `(who, at)`.
- **Dedupe.** One message per `(rule, subject)` per 15 minutes, tracked in `alert_state`.
- **Content.** Names, paths, identities, IPs, times. Never values.
- **Failure.** A failed send is logged and retried once; it never blocks the request.

## Consequences
Schema: `setting(key, value)`, `alert_state(rule, subject, last_sent_at)`, index `audit(who, at)`.
