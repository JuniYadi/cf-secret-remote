export type Cap = "create" | "read" | "update" | "delete" | "list";
export interface Rule {
  path: string; // glob, "*" matches any characters
  caps: Cap[];
}

/** ADR 36: collection rules live in the same policy JSON. They never grant a secret path capability. */
export type CollectionCap = "read" | "manage";
export interface CollectionRule {
  collection: string; // glob over collection names
  caps: CollectionCap[];
}

export const SECRET_CAPS: readonly Cap[] = ["create", "read", "update", "delete", "list"];
export const COLLECTION_CAPS: readonly CollectionCap[] = ["read", "manage"];

export function globMatch(glob: string, path: string): boolean {
  const re = new RegExp(`^${glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
  return re.test(path);
}

/** A secret rule has a path glob and no collection glob. Anything else in the JSON is ignored. */
export const isSecretRule = (r: unknown): r is Rule =>
  typeof r === "object" &&
  r !== null &&
  typeof (r as Rule).path === "string" &&
  !("collection" in r) &&
  Array.isArray((r as Rule).caps);

export const isCollectionRule = (r: unknown): r is CollectionRule =>
  typeof r === "object" &&
  r !== null &&
  typeof (r as CollectionRule).collection === "string" &&
  !("path" in r) &&
  Array.isArray((r as CollectionRule).caps);

/** Default deny: a capability is allowed only if some rule matches the path and lists it. */
export function can(rules: Rule[], path: string, cap: Cap): boolean {
  return rules.some((r) => isSecretRule(r) && r.caps.includes(cap) && globMatch(r.path, path));
}

/**
 * ADR 36: default deny for collection capabilities, independent of secret paths. `manage` includes `read`,
 * because a change previews and checks the declared names, which only a reader may see.
 */
export function collectionCan(rules: CollectionRule[], name: string, cap: CollectionCap): boolean {
  return rules.some(
    (r) =>
      isCollectionRule(r) &&
      (r.caps.includes(cap) || (cap === "read" && r.caps.includes("manage"))) &&
      globMatch(r.collection, name),
  );
}

/** The group (keyring) of a secret is its first path segment. */
export const prefixOf = (path: string): string => path.split("/")[0] ?? "";

export const validPath = (p: string): boolean =>
  /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/i.test(p) && p.length <= 200;
