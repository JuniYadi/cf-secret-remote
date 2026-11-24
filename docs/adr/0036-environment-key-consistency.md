# 36. Environment key consistency and name-only definitions

Status: accepted and implemented (issue #130). The specification below is what the code does.

## Context

Environment paths are independent encrypted bundles (ADRs 10 and 22). Their key names are already cleartext metadata, visible to identities with list permission; values remain client-encrypted. There is no durable shared definition of required names, and an empty string is a value, not an unset marker. The PRD is [Environment key consistency](../prd/environment-key-consistency.md).

## Proposed decision

1. Add a versioned **collection** resource containing a name, explicit environment-label-to-secret-path mappings, and a set of expected names with optional non-secret descriptions. Store it separately from secret versions. Each collection has its own stable identifier and explicit metadata read and administration authorization. The exact policy/API syntax is an implementation design task; it must be independently enforceable and default deny. Mapping a path does not grant any permission to that path.
2. A declaration has no value. Presence is derived from the current cleartext `names` for each mapped path; a declared name absent from a bundle is missing, and a bundle name absent from the definition is extra. Empty strings count as present. Missing/deleted paths and unauthorized paths are distinct states; neither counts as a completed comparison. Expose versions/timestamps alongside observations, and mark the result as a point-in-time view rather than an atomic multi-path snapshot.
3. Reading a collection reveals its definitions, descriptions, and mapped paths only to principals authorized for that collection. Reveal presence, extra names, or path versions only where the caller also has existing list permission for that path. Avoid leaking unauthorized path existence or names in errors. Collection administration does not confer path access; initializing from existing paths requires list permission for every selected source and must fail closed if any source cannot be inspected.
4. Definition changes are explicit, audited, and guarded by a collection revision compare-and-swap. Preview is advisory: apply must validate the expected collection revision and, when importing names from paths, the observed path versions and authorization again. Reject stale inputs rather than silently applying a stale plan. Do not put secret values in the collection, audit events, previews, or logs.
5. Adding a name to the definition never writes any environment bundle. Each owner fills values through existing per-path clients and policies. Removing a definition never deletes stored values. No automatic value propagation, cross-environment value comparison, or external provider synchronization is included. Continue using the existing path/version-bound encryption and per-path version checks for actual writes.
6. Expose equivalent web and CLI operations: create/edit collections, compare, preview, and add selected extras. Machine-readable checks return distinct results for clean, drift, and incomplete/error; exact command names, schema, exit codes, limits, and API endpoints must be specified before implementation. Provide translated UI strings. Audit collection changes and denied access under existing audit conventions.

## Specification as implemented

The open points in the PRD are decided here.

- **Authorization.** A policy rule is either a secret rule (`{ "path", "caps" }`, unchanged) or a collection rule (`{ "collection": "myapp*", "caps": ["read" | "manage"] }`). A rule never mixes the two, and each engine ignores the other kind. `manage` includes `read`, because a change previews declared names, which only readers see. Admins hold every collection capability, as they do for secrets. A collection rule never grants a secret path, and a secret rule never grants a collection.
- **Tables** (migration `0019_env_collections.sql`): `env_collection` (name, revision, timestamps), `env_collection_env` (label, path), `env_collection_key` (name, description). Each change to a definition is one D1 batch. Child statements check the parent revision that the caller read, and the parent update runs last, so a stale caller changes nothing.
- **Endpoints** (all under `/api/v1`, default deny, a refusal is the same `403 {"error":"denied"}` whether or not the name exists):

| Method and path | Capability | Purpose |
|---|---|---|
| `GET /collections` | read | Collections the caller can read: name, revision, counts |
| `GET /collections/:name` | read | Definition: envs, keys, descriptions, revision |
| `GET /collections/:name/compare` | read, plus list per path | Per-environment state and `result` |
| `POST /collections/preview` | manage | Exact diff and per-path state for a proposed definition. No write |
| `POST /collections/discover` | list on each path | Names of the given paths and their union (initialisation) |
| `POST /collections` | manage | Create. `sourceVersions` (path to version) must still match |
| `PUT /collections/:name` | manage | Replace the definition at `revision`. `removed` must list every removed key and env exactly |
| `DELETE /collections/:name?revision=N` | manage | Delete the declaration. Stored values are kept |
| `POST /collections/:name/reconcile/preview` | manage | Which names are extra, and where. Returns `revision` and `sourceVersions` |
| `POST /collections/:name/reconcile` | manage | Add extra names at `revision`, with the `sourceVersions` the preview returned |

- **Comparison.** Each environment is `ok` (with `version`, `updatedAt`, `present`, `missing`, `extra`), `missing_path`, or `inaccessible`. A caller without list on a path sees `inaccessible`, and nothing about that path, even if it does not exist. The overall `result` is `incomplete` if any environment is `inaccessible` or `missing_path`. Otherwise it is `drift` if any name is missing or extra, and `clean` if none is. Presence is name-only: a stored empty string is a name and counts as present.
- **Limits.** 50 collections in total, 10 environments and 300 keys per collection, 200 characters per description, 10 paths per discover or source set, 50 names per reconcile. Labels are at most 32 characters, collection names at most 64, and `new` is reserved.
- **Audit.** `collection.create`, `collection.update` (names and labels in the note), `collection.delete`, `collection.reconcile`, and `collection.read`, `collection.manage`, `secret.list` as `denied`. The note holds names only. No audit row carries a value or a description.
- **Backup.** The three tables are in `BACKUP_TABLES` and `COLUMNS`. Schema is 19. A round trip restores definitions unchanged (tested). Restore still ends sessions, as before.
- **CLI.** `cfs collection list`, `show <name>`, `create <name> --env label=path [--key NAME[=desc]] [--from path]... [--dry-run] [--yes]`, `edit <name> [--env] [--remove-env] [--key] [--remove-key] [--dry-run] [--yes]`, `compare <name> [--json]`, `add-keys <name> NAME... [--dry-run] [--yes]`, `delete <name> [--yes]`. Every write shows the preview first, and asks unless `--yes`.
- **Exit codes for `compare`.** `0` clean, `1` drift, `2` incomplete (an environment was not read, or a path does not exist), `3` error (the check did not run). `--json` prints the server body, or `{"result":"error"}` on failure.
- **Web.** Screens: Collections (list), New collection and Edit (preview before save, and an explicit confirmation before any removal), and the detail page (comparison, names not yet declared, delete). Permissions gained a collection section for policy rules. Every string is English with an Indonesian translation.
- **Stale inputs.** Creating from paths, reconciling, and every edit reject stale input with `409` and a code: `collection_changed` (the revision moved), `source_changed` (a path's version moved), or `name_exists`. The client must preview again.

Source versions are checked again within the D1 write batch, so a concurrent secret write cannot commit between the final version check and the collection change.

## Compatibility and rollout

Existing secrets, ciphertext formats, `names`, fingerprints, list/read permissions, import, `cfs run`, and clients remain unchanged. No data is inferred or migrated automatically: a maintainer opts in by creating a collection. This avoids teaching old clients a new payload type and avoids treating empty strings as placeholders. Backups and restore, quotas, deletion behavior, policy administration, and audit retention must include the new resource before release. If a path is deleted or access revoked, the collection remains but the comparison reports the applicable incomplete state without leaking existence to an unauthorized caller.

## Alternatives

- **Copy values across environments:** rejected for this scope because values often intentionally differ and copying needs access to source values and destination writes.
- **Store unset markers inside encrypted bundles:** rejected because existing clients expect `Record<string, string>` and could inject a placeholder or empty value into a process.
- **Infer expected names from the current union:** rejected as the only source of truth because removing the last occurrence would silently remove the requirement. A reviewed union may seed the explicit definition.
- **Compare existing fingerprints across paths:** rejected because fingerprints include the path and are designed for version diffs, not cross-environment equality.

## Consequences and verification

Definitions and descriptions are cleartext metadata and reveal architecture; collection access must be deliberately scoped. Status can become stale immediately after a comparison, and the server cannot verify that client-provided names match encrypted plaintext. The existing trust model therefore remains relevant. Tests must cover authorization and information leaks, explicit unset versus empty, drift and absent paths, stale collection and path revisions, unchanged values, audit, backup/restore, old clients, and both interfaces.
