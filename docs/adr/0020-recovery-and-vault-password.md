# 20. Recovery, vault password, and admins

Status: accepted (not implemented yet)

## Context
ADR 7 gives the outline. This fixes the mechanics and replaces the interim hex fingerprint.

## Decision
- **Fingerprint code.** The first 44 bits of SHA-256 of the public key map to four words from the BIP-39 English list (11 bits per word), e.g. `anchor velvet kiwi sixty`. A pending reset request's public key is immutable: a new key means a new request and a new code. Admins get 5 attempts per request.
- **Forgot password flow.** (1) The person signs in through Access within the last 5 minutes (the Worker checks the JWT `iat`). (2) The browser makes a new key pair and vault password, and `POST /recovery/request` stores the new public key and locked key as *pending*, shows the four-word code. (3) They send the code to an admin over a channel they trust. (4) The admin types it into "Give access again"; it must equal the code of the pending key; the admin's browser wraps each group key the admin shares with the person to the new public key (`POST /recovery/:id/grant`) and the server swaps the pending key in. (5) The person gets an email and a notification with "Not me, cancel" (`POST /recovery/:id/cancel`, link signed by the server), which discards a pending request and alerts admins (ADR 18).
- **Old wrapped keys.** Old `keyring_member` rows for the person cannot be opened with the new key; they are replaced by the grant.
- **Recovery key (optional).** At setup the browser creates 32 random bytes, shows them as a 24-word BIP-39 phrase once, and stores `identity.recovery_locked_key` (the private key sealed with a key derived from those bytes by HKDF). Using it restores the private key in the browser, lets the person choose a new vault password, and issues a new recovery key.
- **Change password.** Re-lock the same private key with the new password (`PUT /me/vault`, needs the old password locally). Group access is unchanged.
- **Two admins.** An admin cannot be demoted or disabled if it would leave fewer than two admins holding a vault set up. Settings shows each admin's vault and recovery-key status.
- **Wrong password.** Counted in the browser/CLI only (the server cannot see it); the UI shows attempts left and offers the recovery path.

## Consequences
`core` gains `fingerprintWords`, `recoveryKey` (encode/decode, lock/unlock), and the BIP-39 list (copied from the official bitcoin/bips repository, with a test for its checksum and length). Schema: `recovery_request`, `identity.recovery_locked_key`.
