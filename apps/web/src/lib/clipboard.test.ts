import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CLIPBOARD_CLEAR_MS,
  type ClipboardLike,
  clearIfStillOurs,
  copyWithAutoClear,
} from "./clipboard.ts";
import { isRevealed, REVEAL_MS, revealDeadline } from "./reveal.ts";

/** A clipboard that remembers its text, so the test can see what the page wrote. */
function fakeClipboard(initial = ""): ClipboardLike & { value: string } {
  const clip = {
    value: initial,
    writeText: vi.fn(async (text: string) => {
      clip.value = text;
    }),
    readText: vi.fn(async () => clip.value),
  };
  return clip;
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("copy and clear", () => {
  it("clears the clipboard after 30 seconds when it still holds the copied value", async () => {
    const clip = fakeClipboard();
    expect(await copyWithAutoClear("sk_live_1", clip)).toBe(true);
    expect(clip.value).toBe("sk_live_1");
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS - 1);
    expect(clip.value).toBe("sk_live_1");
    await vi.advanceTimersByTimeAsync(1);
    expect(clip.value).toBe("");
  });

  it("does not clear when the person has copied something else since", async () => {
    const clip = fakeClipboard();
    await copyWithAutoClear("sk_live_1", clip);
    clip.value = "something the person copied";
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
    expect(clip.value).toBe("something the person copied");
    expect(clip.writeText).toHaveBeenCalledTimes(1);
  });

  it("leaves the clipboard alone when it cannot be read", async () => {
    const clip = fakeClipboard();
    clip.readText = vi.fn(async () => {
      throw new Error("denied");
    });
    await copyWithAutoClear("sk_live_1", clip);
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
    expect(clip.writeText).toHaveBeenCalledTimes(1);
    expect(clip.value).toBe("sk_live_1");
  });

  it("reports a failed copy and schedules nothing", async () => {
    const clip = fakeClipboard();
    clip.writeText = vi.fn(async () => {
      throw new Error("not allowed");
    });
    expect(await copyWithAutoClear("x", clip)).toBe(false);
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
    expect(clip.readText).not.toHaveBeenCalled();
  });

  it("does nothing where there is no clipboard API", async () => {
    expect(await copyWithAutoClear("x", undefined)).toBe(false);
  });

  it("clearIfStillOurs is the rule on its own", async () => {
    const clip = fakeClipboard("abc");
    expect(await clearIfStillOurs("abc", clip)).toBe(true);
    expect(clip.value).toBe("");
    expect(await clearIfStillOurs("abc", clip)).toBe(false);
  });
});

describe("value auto-hide window", () => {
  it("a shown value is visible for 30 seconds and then hidden", () => {
    vi.setSystemTime(new Date("2026-11-21T10:00:00Z"));
    const deadline = revealDeadline(Date.now());
    expect(REVEAL_MS).toBe(30_000);
    expect(isRevealed(deadline, Date.now())).toBe(true);
    vi.advanceTimersByTime(29_999);
    expect(isRevealed(deadline, Date.now())).toBe(true);
    vi.advanceTimersByTime(1);
    expect(isRevealed(deadline, Date.now())).toBe(false);
    expect(isRevealed(null, Date.now())).toBe(false);
  });
});
