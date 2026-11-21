// The import that is waiting for review. It is held in memory only: never in storage, a URL or a log.
// The review screen reads it, and clears it when the import is saved or cancelled. If the page is
// reloaded the draft is gone, and the person pastes the file again.

import type { Values } from "@cfs/core";
import type { MergeStrategy } from "./secrets.ts";

export interface ImportDraft {
  source: "json" | "env";
  values: Values;
  /** Names with an empty value. They are skipped. */
  empty: string[];
  /** Names that are not valid key names. They are skipped. */
  invalid: string[];
  /** Read errors, as text for the person. */
  errors: string[];
  /** Where the import goes. Chosen on the review screen. */
  target: { mode: "existing"; path: string } | { mode: "new"; path: string };
  strategy: MergeStrategy;
}

let draft: ImportDraft | null = null;
let hint: ImportTarget | null = null;

export function setImportDraft(next: ImportDraft): void {
  draft = next;
}

export function getImportDraft(): ImportDraft | null {
  return draft;
}

export function clearImportDraft(): void {
  draft = null;
  hint = null;
}

/** Where an import should start, when it was begun from a secret (Edit: existing; New secret: new). */
export type ImportTarget = ImportDraft["target"];

export function setImportHint(target: ImportTarget | null): void {
  hint = target;
}

export function getImportHint(): ImportTarget | null {
  return hint;
}
