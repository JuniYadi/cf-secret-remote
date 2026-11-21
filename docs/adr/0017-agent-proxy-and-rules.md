# 17. Agent-safe proxy and agent rules (extends ADR 8)

Status: accepted (not implemented yet)

## Context
Agents should use keys without seeing them, and a prompt-injected agent must not be able to send a key to another host.

## Decision
- **Agent rules** are stored per app in `agent_rule(identity_id, alias, secret_path, name, upstream, inject, max_reads_per_hour, require_reason, require_approval)`:
  - `alias`: short name the agent uses.
  - `upstream`: base URL (https only). This is the host allowlist: the proxy only ever talks to the rule's upstream.
  - `inject`: where the value goes, e.g. `header:Authorization:Bearer {value}` or `query:api_key`.
  - `require_approval` defaults to true when `secret_path` matches `*/prod` (ADR 16).
- **Proxy.** `cfs proxy --listen 127.0.0.1:8787` signs in with `CFS_KIT`, loads rules, decrypts locally, and serves `http://127.0.0.1:8787/<alias>/<path>`. It forwards to `<upstream>/<path>`, adds the injected value, strips any caller-supplied value of the same header, and **redacts the value from responses** (body and headers) as `[redacted]`. Redirects to other hosts are not followed. Binds to loopback only.
- **Reason.** If `require_reason`, each request needs `X-Cfs-Reason` (or `--reason` for the session); it is written to the audit entry.
- **Budget.** The proxy fetches ciphertext once per cache window (default 5 min) and each fetch counts toward `max_reads_per_hour`, enforced by the server (429 beyond it) and audited.
- **No values in logs.** The proxy logs alias, method, status and byte counts only.

## Amendment (PR review)
- Approval for `*/prod` applies to apps that have an agent rule for that exact path with `require_approval` on (the default for `*/prod`). An app with no rule is an ordinary app governed by its policies (ADR 5); making every app request approval would break CI bots that deploy production. To treat an app as an agent, give it a rule.
- Rules match the exact `secret_path`, not a glob.
- The read budget is a fixed one-hour window per alias, not a sliding one.
- Redaction covers the plain, URL-encoded and base64 forms of the value. Encoded upstream bodies are refused because they cannot be redacted. Browser requests (with `Origin`) and foreign `Host` headers are refused (DNS rebinding guard).

## Consequences
The agent still holds whatever the proxy returns. The proxy cannot protect against an agent with shell access to the same machine that can read `CFS_KIT`; the docs say so and recommend running the proxy under a separate user or container.
