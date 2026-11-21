import { describe, expect, it } from "vitest";
import { isAcceptablePassword, passwordStrength } from "./password.ts";
import { checkChallenge, pickChallenge } from "./recovery-check.ts";
import {
  COOLDOWN_MS,
  cooldownSeconds,
  MAX_TRIES,
  NO_ATTEMPTS,
  recordFailure,
  triesLeft,
} from "./unlock-attempts.ts";

describe("password strength hint", () => {
  it("rejects short passwords and single-character runs", () => {
    expect(passwordStrength("short")).toBe("weak");
    expect(passwordStrength("aaaaaaaaaaaaaaaa")).toBe("weak");
    expect(isAcceptablePassword("12345678901")).toBe(false);
  });

  it("grades by length", () => {
    expect(passwordStrength("abcdefghijkl")).toBe("fair");
    expect(passwordStrength("abcdefghijklmnop")).toBe("good");
    expect(passwordStrength("coffee-rain-bicycle-blue")).toBe("strong");
    expect(isAcceptablePassword("abcdefghijkl")).toBe(true);
  });

  it("counts characters, not UTF-16 units", () => {
    // Twelve distinct emoji: 12 code points, 24 UTF-16 units. Counted as 12 it is "fair", not "good".
    const twelve = "😀😁😂🤣😃😄😅😆😉😊😋😎";
    expect([...twelve]).toHaveLength(12);
    expect(passwordStrength(twelve)).toBe("fair");
  });
});

describe("unlock attempts", () => {
  it("counts wrong passwords and shows the tries left", () => {
    let s = NO_ATTEMPTS;
    expect(triesLeft(s)).toBe(MAX_TRIES);
    s = recordFailure(s, 0);
    s = recordFailure(s, 0);
    expect(triesLeft(s)).toBe(MAX_TRIES - 2);
    expect(s.lockedUntil).toBeNull();
  });

  it("waits one minute after the last try", () => {
    let s = NO_ATTEMPTS;
    for (let i = 0; i < MAX_TRIES; i++) s = recordFailure(s, 1_000);
    expect(s.lockedUntil).toBe(1_000 + COOLDOWN_MS);
    expect(cooldownSeconds(s, 1_000)).toBe(60);
    expect(cooldownSeconds(s, 1_000 + 59_500)).toBe(1);
    expect(cooldownSeconds(s, 1_000 + COOLDOWN_MS)).toBe(0);
    expect(triesLeft(s)).toBe(MAX_TRIES);
  });
});

describe("recovery key confirmation", () => {
  const phrase = Array.from({ length: 24 }, (_, i) => `word${i}`);

  it("picks three distinct, ascending positions", () => {
    const seq = [5, 5, 9, 2, 17, 0];
    let i = 0;
    const picked = pickChallenge(24, () => seq[i++] as number);
    expect(picked).toEqual([2, 5, 9]);
  });

  it("accepts the right words in any case and with spaces", () => {
    expect(checkChallenge(phrase, [1, 4, 20], [" WORD1 ", "word4", "Word20"])).toBe(true);
  });

  it("rejects a wrong word or a missing answer", () => {
    expect(checkChallenge(phrase, [1, 4, 20], ["word1", "word5", "word20"])).toBe(false);
    expect(checkChallenge(phrase, [1, 4, 20], ["word1", "word4"])).toBe(false);
  });

  it("uses secure randomness when no source is given", () => {
    const picked = pickChallenge();
    expect(picked).toHaveLength(3);
    expect(new Set(picked).size).toBe(3);
    for (const p of picked) expect(p).toBeLessThan(24);
  });
});
