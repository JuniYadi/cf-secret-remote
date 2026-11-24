# PRD: Environment key consistency

Status: implemented per ADR 36 (issue #130); decisions are recorded in ADR 36

Date: 2026-11-24

## Problem and verification

Teams commonly use the same configuration key names in development, staging, and production, while keeping their values independent. Today, the product does not model those paths as a related set or track the names that each environment is expected to have. An environment can therefore miss a key without an obvious warning.

The following observations are based on the repository, not a live deployment:

| Concern | Current behavior |
|---|---|
| Initialize three environments with the same keys | Each environment is a separate path containing an encrypted key/value bundle. Users can create each path with `cfs set` or import values, but there is no shared key definition or multi-environment initialization. `cfs init` configures a local project; it does not initialize the vault's environment secrets. |
| An update reaches only one environment | Writes create a new version of one path. No relationship between paths detects or propagates a newly added or removed name. Existing values can intentionally differ. |
| Sync keys | There is no cross-environment key sync. `cfs diff` compares versions of one secret, not environments; planned external provider sync is a separate feature. |
| Give a user keys without values | `cfs list` and the list API already expose names to identities with list permission, without returning values. Secret-level description, owner and rotation date also exist. However, there is no first-class key declaration with an unset value or per-key metadata. An empty string is a real value, and web imports skip empty entries. Path permissions and group keys govern value access; there is no per-key access control. |

Evidence: [secret commands](../../apps/cli/src/commands/secrets.ts), [CLI initialization](../../apps/cli/src/commands/deploy.ts), [version commands](../../apps/cli/src/commands/versions.ts), [secret API](../../apps/api/src/routes/secrets.ts), [secret payload](../../packages/core/src/secret.ts), [web import and fields](../../apps/web/src/lib/secrets.ts), and [ADR 22](../adr/0022-secrets-versions-and-metadata.md).

## Goal

Let a team declare the expected key names once, associate explicit environment paths, see missing and extra keys, and share that name-only information with authorized users. Values remain independently managed per environment.

Example: a project declares `DATABASE_URL` and `API_KEY` for `myapp/dev`, `myapp/stg`, and `myapp/prod`. If `API_KEY` is present only in dev, the view reports it missing in staging and production. A teammate with metadata access can see what to fill without receiving the values.

## Users and scope

- Project maintainers define environments and expected keys, review drift, and decide when to change the definition.
- Environment owners provide their own values and resolve missing keys.
- Metadata viewers discover required names and optional descriptions without needing ciphertext or group keys.

The initial release supports an explicitly configured collection of environment paths, name-only definitions with optional descriptions, comparison, and an explicit way to add discovered names to the definition. It does not copy, synchronize, compare, or overwrite values; infer environments from arbitrary paths; sync to external providers; or provide per-key permissions. A configured path may be an existing bundle or a path yet to be created. Environment labels are user-defined.

## Requirements and acceptance criteria

1. **Initialize:** a maintainer creates a collection, maps unique environment labels to distinct valid paths, and declares names manually or from a reviewed union of selected existing paths. Preview shows exact additions and any inaccessible or nonexistent paths; no secret values are needed or changed. Reject duplicate names and invalid mappings.
2. **Declare unset keys:** a definition may contain a name and optional non-secret description without any value in any environment. Unset is represented by absence from that environment's stored bundle, distinct from a stored empty string. Descriptions and names are visible metadata and must not contain secrets.
3. **Detect drift:** for every authorized configured path, show each declared name as present or missing, and show names present in that path but absent from the definition as extra. A missing path is reported separately; an inaccessible path is unknown, never presented as missing or compliant. A saved empty string counts as present. Refresh reads current state and identifies the observed secret versions; changes to values alone do not constitute name drift.
4. **Reconcile deliberately:** a maintainer can preview and add selected extra names to the definition. This updates the expected set for all mapped environments and exposes their missing names. Removing or renaming definitions is explicit and previewed; it never deletes or renames environment values. Filling or deleting values uses existing per-path workflows and permissions. There is no automatic propagation or background mutation.
5. **Metadata-only access:** grant an explicit collection metadata permission for its definitions and mappings. Per-environment presence and extras require that path's existing list permission. Users without read permission or group key cannot obtain values through this feature. Existing read/list APIs and their permissions are unchanged.
6. **CLI and web:** both provide create/edit, name-only comparison, and reconciliation with the same authorization and results. Machine-readable CLI output and a nonzero drift check distinguish drift from access/error conditions. Web copy is available in English and Indonesian.
7. **Safety and concurrency:** preview contains no values. Changes are audited without values and use version checks; stale edits are rejected with a refresh-and-retry message. Partial or inaccessible results are never reported as a successful complete check. Existing clients and bundles continue to work.

## Success measures

After release, measure the proportion of configured collections with a complete drift check and the number of unresolved missing keys over time, without collecting key values. Initial targets and telemetry collection require product agreement; no new external telemetry is assumed.

## Decisions to confirm

- Whether every key is required in every environment, or exceptions/optional keys are needed. This draft assumes all are required.
- Whether the metadata permission should use a new policy capability or a dedicated collection resource, and who may administer it.
- Whether teams want value copying or external-provider sync later; either needs a separate security and product decision.

## Delivery and verification

Start with the data/API and permission model, then CLI and web. Cover initialization, mixed existing/missing paths, drift, empty strings, metadata-only access, unauthorized and deleted paths, concurrent edits, audit, and compatibility with existing clients. See the proposed [ADR 36](../adr/0036-environment-key-consistency.md).
