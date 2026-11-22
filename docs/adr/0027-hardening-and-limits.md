# 27. Hardening and rate limits

Status: accepted (not implemented yet)

## Decision
- **Throttle.** `login_attempt(key, window, count)` rate-limits AppRole login (ADR 15), CLI device polling (1 request per 2 s per code, 429 beyond), code approval (5 wrong codes per identity per 10 minutes), and recovery attempts (ADR 20).
- **Input.** Bodies are size-capped (secret ciphertext 256 KB, other JSON 64 KB). Paths use the existing validator; names match `[A-Za-z_][A-Za-z0-9_]*` and are at most 128 characters.
- **Tokens.** Stored as SHA-256 only; compared in constant time. Session lists show device, last use, and allow revocation (`DELETE /sessions/:id`, also from "Signed-in devices").
- **Errors.** Generic messages for auth failures; details only in the audit row.
- **Logging.** Never request bodies, never values or tokens. Errors log the message only.
- **CORS.** None: the web app is same-origin. The API sends no CORS headers.
- **Dependency policy.** Few runtime dependencies (Hono only on the server); lockfile committed; CI runs `bun audit`.
- **Threat model.** The [threat model](../threat-model.md) records what is and is not protected (a Cloudflare admin can delete rows and swap the served JS; the checkpoints and signed releases detect or limit this).
