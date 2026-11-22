# 1. Cloudflare only, free tier

Status: accepted

## Context
HashiCorp Vault OSS has no readable audit trail and needs servers. Target: teams up to 50 people and AI-agent builders.

## Decision
Run on Cloudflare Workers + D1 only. Cloudflare Access (free up to 50 users) handles human login. No other paid service is required.

See [ADR 28](0028-positioning-qa-credentials.md) for product positioning and the repository-layer follow-up.

## Consequences
Free-tier limits apply (D1 writes per day). At quota, reads and login keep working and saves pause until 00:00 UTC. Details in DESIGN.md.
