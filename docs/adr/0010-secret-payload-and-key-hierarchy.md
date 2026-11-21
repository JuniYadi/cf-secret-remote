# 10. Secret payload and key hierarchy

Status: accepted

## Decision
A secret version holds a JSON object `{ NAME: value }` (strings). Hierarchy: group key (32 random bytes, wrapped per member, AAD `keyring:<prefix>:v<keyringVersion>`) -> DEK per secret version (32 random bytes) -> ciphertext.
- `wrapped_dek` = AES-GCM seal of the DEK under the group key, AAD `dek:<path>:v<version>`.
- `ciphertext` = AES-GCM seal of the JSON under the DEK, AAD `secret:<path>:v<version>`.
- The client sends `version` (current + 1) in the write. The server rejects it unless it equals current + 1, so AAD matches and concurrent writers cannot overwrite each other (409).
- Key names are stored in clear (needed for lists and diffs). Values never are.

## Consequences
Supersedes the placeholder wrapped DEK used in the first API test. Moving a secret to another path requires re-encrypting it.
