# 34. Security disclosure, licence, and supply chain

Status: implemented; Private Vulnerability Reporting setting pending owner

## Context
The repo is open and stores credentials, so a flaw in our code is a risk for every deployment. Researchers need a safe way to report, and users need a way to check that what they run matches the source.

## Decision
- **`SECURITY.md`.** Report through GitHub **Private Vulnerability Reporting**, never a public issue. Supported: the latest release only. Targets: acknowledge within 3 days, assess within 7. Scope: Worker, web, CLI, extension, `packages/core`, and install scripts. Good-faith research is welcome (safe harbour); there is no paid bounty. Out of scope: a compromised Cloudflare account or browser (see the threat model), and denial of service by volume.
- **`LICENSE`: AGPL-3.0** for the whole repo, so nobody can run a modified copy as a closed hosted service. Parts may be relicensed later (for example `packages/core` as MIT) if embedding is needed.
- **Threat model.** `docs/threat-model.md` (planned in ADR 27) is written now: assets, attackers, and what is not protected (a Cloudflare admin can delete rows and swap served JavaScript; a compromised browser can read an unlocked vault). The extension's autofill risks (ADR 32) are part of it.
- **CI.** CodeQL, Dependabot (npm and GitHub Actions), `bun audit`, and a frozen lockfile (`bun install --frozen-lockfile`). Findings block merge for high severity.
- **Releases.** Deterministic build in GitHub Actions. The release publishes SHA-256 hashes of the CLI binaries, the web `dist`, and the extension zip, and signs them. The same extension zip can be loaded unpacked; the Chrome Web Store listing links to the release hash.
- **Disclosure.** Fixes are released with a GitHub Security Advisory and a CVE when applicable.

## Consequences
Files: `SECURITY.md`, `LICENSE`, `docs/threat-model.md`, `.github/dependabot.yml`, `.github/workflows/codeql.yml`. Repository setting: enable Private Vulnerability Reporting. This is the first record to build.
