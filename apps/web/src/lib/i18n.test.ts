import { afterEach, describe, expect, it, vi } from "vitest";
import {
  currentLang,
  LANG_STORAGE_KEY,
  parseLang,
  readStoredLang,
  setLang,
  subscribeLang,
  t,
} from "./i18n.ts";

afterEach(() => {
  setLang("en", undefined);
});

function memoryStorage(initial: Record<string, string> = {}): Storage {
  const data = new Map(Object.entries(initial));
  return {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => {
      data.set(key, value);
    },
    removeItem: (key: string) => {
      data.delete(key);
    },
    clear: () => data.clear(),
    key: () => null,
    get length() {
      return data.size;
    },
  } as Storage;
}

describe("t(en, id)", () => {
  it("returns English by default", () => {
    expect(currentLang()).toBe("en");
    expect(t("Sign in", "Masuk")).toBe("Sign in");
  });

  it("returns the Indonesian text when the language is ID", () => {
    setLang("id", undefined);
    expect(t("Sign in", "Masuk")).toBe("Masuk");
  });

  it("falls back to English when the Indonesian text is empty", () => {
    setLang("id", undefined);
    expect(t("Settings", "")).toBe("Settings");
  });

  it("uses English for an unknown stored value", () => {
    expect(parseLang("fr")).toBe("en");
    expect(parseLang(null)).toBe("en");
    expect(parseLang("id")).toBe("id");
    expect(readStoredLang(memoryStorage({ [LANG_STORAGE_KEY]: "de" }))).toBe("en");
  });

  it("reads the saved choice", () => {
    expect(readStoredLang(memoryStorage({ [LANG_STORAGE_KEY]: "id" }))).toBe("id");
  });

  it("survives storage that throws on read or write", () => {
    const broken = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    } as unknown as Storage;
    expect(readStoredLang(broken)).toBe("en");
    expect(() => setLang("id", broken)).not.toThrow();
    expect(currentLang()).toBe("id");
  });

  it("saves the choice to storage", () => {
    const store = memoryStorage();
    setLang("id", store);
    expect(store.getItem(LANG_STORAGE_KEY)).toBe("id");
  });

  it("notifies subscribers when the language changes", () => {
    const listener = vi.fn();
    const stop = subscribeLang(listener);
    setLang("id", undefined);
    expect(listener).toHaveBeenCalledTimes(1);
    stop();
    setLang("en", undefined);
    expect(listener).toHaveBeenCalledTimes(1);
  });
});
