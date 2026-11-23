# 25. Deploy, init, hosts, and releases

Status: accepted, implemented

## Decision
- **`cfs deploy [--domain d]`** uses the user's own Cloudflare account (API token or `wrangler` login): creates the D1 database, applies migrations, deploys the Worker with the built web assets, sets vars, and with `--domain` adds the custom domain and Access applications. The UI application allows the admin; separate applications for `/api/v1/*` and `/api/health` each have an everyone Bypass policy (ADR 4). The CLI needs the health bypass for its protocol check. It prints the first-run steps (set `BOOTSTRAP_ADMIN_EMAIL`, sign in, set the vault password) and writes the host to `.cfs.json`. It is re-runnable (upgrade): migrations are forward-only and tracked.
- **Release artifact.** Per tag: CLI binaries for macOS (arm64, x64), Linux (x64, arm64), Windows (x64); one `worker-bundle.tgz` (Worker code, built web, migrations, manifest with versions and hashes); checksums and signatures.
- **Compatibility.** `/api/health` returns `{ protocol, version }`. The CLI refuses a server whose protocol major differs and says which to upgrade.
- **Host trust.** A host from `.cfs.json` or `CFS_HOST` that was never signed in to prompts "Sign in to <host>? (y/N)" and is then saved to `~/.config/cfs/config.json` profiles (`--profile`). Hosts must be `https://` (localhost allowed for development).
- **`.cfs.json`.** Minimal `{ host, project }` or explicit `envs` (ordered list of secrets, later entries override). If a listed secret cannot be opened the command fails and names it. `cfs init` writes it interactively.
- **Keychain.** `cfs unlock` moves to the OS keychain (macOS `security`, Linux `secret-tool`, Windows credential manager) with `--ttl` (default 1 h); the 0600 file stays as a fallback (supersedes the storage part of ADR 12).
- **Self-update.** `cfs upgrade` downloads the matching binary and verifies its checksum.

## Consequences
Distribution is open source; we host no data.
