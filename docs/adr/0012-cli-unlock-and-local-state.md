# 12. CLI unlock and local state

Status: accepted, keychain storage superseded by [25](0025-deploy-and-distribution.md)

## Decision
`cfs unlock` asks for the vault password (hidden input), unlocks the private key locally, and keeps it in `~/.config/cfs/session.json` (mode 0600) together with the token and an expiry (default 8 hours, same as the token). `cfs lock` deletes it. Apps skip this: the kit holds the private key and `CFS_KIT` is used instead of the file.

## Consequences
OS keychain storage is a later improvement. Until then the unlocked key sits on disk for the unlock period, readable only by the user.
