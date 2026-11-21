// Copy of a secret value (DESIGN.md, ADR 24). After 30 seconds the clipboard is cleared, but only if it
// still holds the value we copied. If the browser will not let us read the clipboard, we cannot tell
// whether it still holds the value, so we leave it alone rather than wipe something the person copied.

export const CLIPBOARD_CLEAR_MS = 30_000;

export interface ClipboardLike {
  writeText(text: string): Promise<void>;
  readText(): Promise<string>;
}

/** The browser clipboard, or undefined where the API is missing (private windows, insecure contexts). */
export function browserClipboard(): ClipboardLike | undefined {
  try {
    return globalThis.navigator?.clipboard ?? undefined;
  } catch {
    return undefined;
  }
}

/**
 * Copies text and schedules the clear. Returns false when the copy itself failed, in which case nothing is
 * scheduled. `schedule` is injectable so tests can run the clock.
 */
export async function copyWithAutoClear(
  text: string,
  clipboard: ClipboardLike | undefined = browserClipboard(),
  schedule: (fn: () => void, ms: number) => unknown = (fn, ms) => setTimeout(fn, ms),
): Promise<boolean> {
  if (!clipboard) return false;
  try {
    await clipboard.writeText(text);
  } catch {
    return false;
  }
  schedule(() => {
    void clearIfStillOurs(text, clipboard);
  }, CLIPBOARD_CLEAR_MS);
  return true;
}

/** Writes an empty string only when the clipboard still holds `text`. Any failure leaves it alone. */
export async function clearIfStillOurs(text: string, clipboard: ClipboardLike): Promise<boolean> {
  try {
    const current = await clipboard.readText();
    if (current !== text) return false;
    await clipboard.writeText("");
    return true;
  } catch {
    return false;
  }
}
