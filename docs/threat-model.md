# Threat model

This document records the boundaries planned in [ADR 27](adr/0027-hardening-and-limits.md).

## Assets and attackers

Secrets, login credentials, vault keys, tokens, and audit history need protection. Metadata such as names, versions, and identities also needs care. Attackers may steal server data, intercept traffic, tamper with stored records or releases, or try to trick a person into filling a credential on the wrong page.

## Protected

Clients encrypt values before sending them. The server never sees plaintext. It stores ciphertext, wrapped keys, and metadata. Server policy controls who can fetch ciphertext; group keys control who can decrypt it. See [ADR 2](adr/0002-end-to-end-encryption.md).

Audit entries form a hash chain. Verification and external checkpoints can detect changes to history, but cannot prevent deletion. Audit records contain no values. See [ADR 6](adr/0006-hash-chained-audit.md).

## Not protected

A Cloudflare admin can delete rows and swap the JavaScript served to users. A compromised browser can read an unlocked vault. A malicious client or a person with access to plaintext can disclose it. Availability is not guaranteed against volumetric denial of service.

## Extension autofill

Autofill can expose credentials to a hostile page or hidden field. The planned extension matches the exact origin, including scheme, host, and port. It fills only after a user action, never on page load or by auto-submit. It does not fill cross-origin iframes or hidden fields. HTTPS is required except for localhost and 127.0.0.1. See [ADR 32](adr/0032-chrome-extension.md).
