# 7. Recovery under E2E

Status: accepted, detailed by [20](0020-recovery-and-vault-password.md) (the fingerprint becomes four BIP-39 words)

## Decision
Forgotten vault password: fresh Access login, then an admin who still holds the group key re-wraps it after typing the user's fingerprint code. The user gets a "Was this you?" email with a cancel link. An optional 24-word recovery key exists. At least two admins are required.

## Consequences
The fingerprint is currently 4 hex groups, not four words (see DESIGN.md).
