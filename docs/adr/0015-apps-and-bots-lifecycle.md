# 15. Apps and bots lifecycle

Status: accepted (not implemented yet)

## Context
ADR 4 defines AppRole login. The lifecycle around it (creating, delivering the kit, rotating, revoking, limiting) is not specified.

## Decision
- **Create** (`cfs app create <name>` or the web form): the client generates the key pair, sends only the public key to `POST /apps`, and receives `role_id` and `secret_id` once. It builds the kit (`cfskit1_…`, ADR 2) and shows or writes it once. The server never sees the private key.
- **Owner.** Every app has `owner_id` (the creating person). Offboarding (ADR 21) must reassign or disable an owner's apps.
- **Groups and permissions.** Adding the app to a group works as for people (ADR 14, an admin wraps the group key to the app's public key). Policies attach as in ADR 5.
- **Rotate secret_id.** `POST /apps/:id/rotate` returns a new `secret_id` once and invalidates the old one. The private key is unchanged unless the app is re-keyed (`--rekey`), which needs removal and re-adding to its groups.
- **Revoke.** `POST /apps/:id/disable` disables the identity and ends its sessions. Group removal follows ADR 14 if the key must be considered burnt.
- **Limits.** token TTL (default 1 h, max 24 h), `max_uses`, `expires_at`, and network allowlist. The allowlist accepts IPv4/IPv6 addresses and CIDR ranges (replaces the exact-IP check).
- **Login throttle.** At most 10 failed AppRole logins per `role_id` per 10 minutes, then 429 for 10 minutes (counter in `login_attempt`, see ADR 27).
- **First sign-in.** `app_role.first_login_at` is set on the first successful login; the UI shows "Waiting for first sign-in" until then.
- **Detail view data.** last seen (time, IP), sessions, recent activity, from `session` and `audit`.

## Consequences
Schema: `identity.owner_id`, `app_role.first_login_at`, `app_role.last_login_at`, `app_role.last_ip`. CLI: `app create|list|rotate|disable|show`. `cfs whoami` prints name, kind, and state.
