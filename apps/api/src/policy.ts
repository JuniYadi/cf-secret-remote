export type Cap = "create" | "read" | "update" | "delete" | "list";
export interface Rule {
  path: string; // glob, "*" matches any characters
  caps: Cap[];
}

export function globMatch(glob: string, path: string): boolean {
  const re = new RegExp(`^${glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
  return re.test(path);
}

/** Default deny: a capability is allowed only if some rule matches the path and lists it. */
export function can(rules: Rule[], path: string, cap: Cap): boolean {
  return rules.some((r) => r.caps.includes(cap) && globMatch(r.path, path));
}

/** The group (keyring) of a secret is its first path segment. */
export const prefixOf = (path: string): string => path.split("/")[0] ?? "";

export const validPath = (p: string): boolean =>
  /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/i.test(p) && p.length <= 200;
