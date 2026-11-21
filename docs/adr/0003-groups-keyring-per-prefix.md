# 3. Groups (keyrings) per top-level path prefix

Status: accepted, rotation detailed by [14](0014-membership-and-rotation.md)

## Decision
The first path segment of a secret names its group. Members hold a wrapped copy of the group key per key version. Removing a member bumps the key version, re-encrypts the group, and writes new wrapped keys for the rest.

## Consequences
Access is decided per group by key possession and per path by policy. Rotation on removal is required for real revocation. It is not implemented yet.
