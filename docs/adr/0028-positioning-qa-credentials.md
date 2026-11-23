# 28. Positioning: credentials and secrets for QA teams

Status: implemented (docs); repository layer is a follow-up

## Context
QA teams test websites, and more and more of that testing is automated. Automated QA needs accounts (admin, plain user, expired trial) as well as keys. Today these live in spreadsheets, chat, and CI variables, so it is unclear who holds which password. General password managers charge per seat and are built for people filling forms, not for test runners and agents.

## Decision
- The product stores **secrets and QA credentials** in one vault, for a team or for one person, with one keyring, policy, and audit model.
- Target user: small technical teams (developers, QA, agencies, startups) that already have a Cloudflare account.
- This is **not** a general consumer password manager. No cards, identities, passkeys, or file attachments in v1. Secure notes are covered by Secrets.
- Differentiators: the server cannot read values (ADR 2), every access is provable (ADR 6), and machines and agents get credentials through AppRole without anyone pasting passwords (ADR 15, 17).
- Cloudflare Workers + D1 remains the only target (ADR 1) because it is free. Wider self-hosting (Docker, SQLite, Postgres) is a later option, not a goal now. The only preparation: business logic must not call D1 directly outside one thin repository layer.
- Hosted SaaS is out of scope until there is real demand. The data stays in the user's own Cloudflare account.

## Release order
Repo security (34), then CLI and `cfs run` (30), web (31), Chrome extension (32), import (33). Deferred items are in 35.

## Consequences
ADR 1 gets a pointer to this record. UI and docs describe the product as a vault for QA credentials and secrets.
