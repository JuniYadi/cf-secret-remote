// Language helper. Every UI string is written as t(english, indonesian) at the call site, like the design
// boards' d() helper. English is the default. The choice is kept in localStorage; if storage is blocked
// (private windows, disabled site data) the choice lasts for the page only.

export type Lang = "en" | "id";

export const LANG_STORAGE_KEY = "cfs-lang";

export function parseLang(value: unknown): Lang {
  return value === "id" ? "id" : "en";
}

/** localStorage can throw on access in some privacy modes. Returns undefined instead. */
function storage(): Storage | undefined {
  try {
    return globalThis.localStorage ?? undefined;
  } catch {
    return undefined;
  }
}

export function readStoredLang(store: Storage | undefined = storage()): Lang {
  try {
    return parseLang(store?.getItem(LANG_STORAGE_KEY));
  } catch {
    return "en";
  }
}

let current: Lang = readStoredLang();
const listeners = new Set<() => void>();

export function currentLang(): Lang {
  return current;
}

export function setLang(lang: Lang, store: Storage | undefined = storage()): void {
  current = lang;
  try {
    store?.setItem(LANG_STORAGE_KEY, lang);
  } catch {
    // Storage is blocked. The choice still applies for this page.
  }
  if (typeof document !== "undefined") document.documentElement.lang = lang;
  for (const listener of [...listeners]) listener();
}

/** Subscribes to language changes. Returns the unsubscribe function. */
export function subscribeLang(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Picks the Indonesian text when the language is ID. An empty Indonesian text falls back to English. */
export function t(en: string, id: string): string {
  return current === "id" && id !== "" ? id : en;
}

if (typeof document !== "undefined") document.documentElement.lang = current;
