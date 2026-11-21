# 14. Group membership and key rotation

Status: accepted (not implemented yet)

## Context
ADR 3 says removing a member rotates the group key. Adding a member and rotating need exact rules, and rotation can exceed one D1 batch.

## Decision
**Add member.** An existing member with the group unlocked wraps the current group key to the new member's public key (`wrapGroupKey`) and calls `POST /keyrings/:prefix/members`. The server checks the caller is a member and an admin, and stores `keyring_member` for the current version. A member without a public key (vault not set up) cannot be added.

**Remove member (rotation).** A member's server-side access ends at once (rows for the current version are deleted), then the group is re-keyed:
1. `POST /keyrings/:prefix/rotate/start` sets `keyring.status = 'rotating'`. Writes to the group return 409 while rotating. Reads keep working at the old version.
2. The client makes a new group key and wraps it to every remaining member (`version + 1`). For each secret it re-encrypts the **current** version under a new DEK as a new secret version (`keyring_version = new`). It uploads in chunks of at most 50 secrets: `POST /keyrings/:prefix/rotate/chunk`.
3. `POST /keyrings/:prefix/rotate/commit` verifies that every non-deleted secret in the group has a version at the new keyring version, then flips `keyring.version` and `status = 'active'` in one batch. `POST .../rotate/abort` discards the staged rows.
4. Remaining members keep their wrapped keys for old versions so history stays readable. The removed member's rows for all versions are deleted.

**Limits, stated in the UI and docs.** A removed member may have copied old values or old wrapped keys; rotation protects values written after it, and the offboarding report (ADR 21) lists what they could have seen so those values are changed at the source.

**Identities.** Admins can disable and re-enable identities and change role (member/admin). Disabling ends all sessions. At least two admins must hold a vault (ADR 20).

## Consequences
Schema: `keyring.status ('active'|'rotating')`, `secret_version` staged rows carry the new `keyring_version` and are invisible until commit (`secret.current` is only moved at commit). The CLI gets `group add-member`, `group remove-member`, `group list`.
