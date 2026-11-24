// Names used by fixed web routes and secret page suffixes. Matching is case-sensitive.
export const SECRET_FIXED_NAMES = {
  new: "new",
  import: "import",
  importReview: "import/review",
} as const;
export const SECRET_PAGE_SUFFIXES = {
  edit: "edit",
  versions: "versions",
  history: "history",
} as const;
export const GROUP_FIXED_NAMES = { new: "new", offboard: "offboard", regrant: "regrant" } as const;

export function isReservedSecretPath(path: string): boolean {
  return (
    Object.values(SECRET_FIXED_NAMES).some((name) => name === path) ||
    Object.values(SECRET_PAGE_SUFFIXES).some((name) => path.split("/").at(-1) === name)
  );
}

// ADR 36: fixed web routes for environment collections. `new` is refused as a collection name.
export const COLLECTION_FIXED_NAMES = { new: "new" } as const;

export function isReservedCollectionName(name: string): boolean {
  return Object.values(COLLECTION_FIXED_NAMES).some((reserved) => reserved === name);
}

export function isReservedGroupName(name: string): boolean {
  return Object.values(GROUP_FIXED_NAMES).some((reserved) => reserved === name);
}
