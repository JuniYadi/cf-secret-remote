# 5. Policies: path globs, capabilities, default deny

Status: accepted

## Decision
Rules are `{ path glob, caps }` with caps create, read, update, delete, list. Policies attach to identities, optionally with an expiry (used by access requests). Admins can do everything. Every denial is audited.

## Consequences
Glob `*` matches any characters including `/`. Roles and permission sets in the UI map onto policies.
