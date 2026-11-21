# 2. End-to-end encryption, server never decrypts

Status: accepted

## Context
A server-side master key means the API can return plaintext, and a breach or a careless response leaks every secret.

## Decision
Values are encrypted in the client (browser or CLI). Each secret version has its own DEK (AES-256-GCM, AAD binds path and version). The DEK is wrapped with the group (keyring) key. The group key is wrapped to each member's ECDH P-256 public key (ephemeral ECDH + HKDF-SHA256). Private keys are locked with the vault password (PBKDF2-SHA256, 600k) and stored only in locked form.

## Consequences
The server stores ciphertext, wrapped keys and metadata only. A lost vault password cannot be reset by the server (see ADR 7). Two gates apply: server policy decides who may fetch ciphertext, the group key decides who may decrypt. Audit logs fetches, not decryptions.
