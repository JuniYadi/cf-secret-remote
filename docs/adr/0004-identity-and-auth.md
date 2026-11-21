# 4. Identity: Access for people, AppRole for bots

Status: accepted

## Decision
- People: Cloudflare Access JWT (RS256, checked against the team JWKS, audience and issuer). Only `BOOTSTRAP_ADMIN_EMAIL` may appear uninvited; everyone else is invited first.
- CLI: device/loopback login with a short code, then a `cfs_` token (planned).
- Apps and agents: self-managed AppRole (role_id + secret_id stored as hash, TTL, max uses, network allowlist) giving a `cfs_` token. Kit `cfskit1_…` carries host, role_id, secret_id and the private key; the private key is never sent.
- Cloudflare service tokens are not used: they live outside our system and only Cloudflare admins can manage them.

## Amendment (issue #28)
`/api/v1/*` is a Bypass path, and Access adds no `Cf-Access-Jwt-Assertion` header there. The Worker therefore also reads the Access JWT from the `CF_Authorization` cookie and verifies it the same way. Because a cookie can be sent by another site's page, a cookie-authenticated request that changes data (anything but GET/HEAD) must carry an `Origin` header equal to the request host, otherwise it is refused with 403. Bearer tokens and the header form are not affected.

## Consequences
One API tree at `/api/v1/*`. Access must bypass that path; the Worker checks `cfs_` tokens itself, and falls back to the Access JWT.
