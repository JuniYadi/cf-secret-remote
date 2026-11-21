import { describe, expect, it } from "vitest";
import { BIP39_ENGLISH } from "./words.ts";

// The list was copied from bitcoin/bips bip-0039/english.txt. The file's SHA-256 is recorded here.
const OFFICIAL_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

describe("BIP-39 English word list (ADR 20)", () => {
  it("has exactly 2048 unique, sorted, lowercase words", () => {
    expect(BIP39_ENGLISH).toHaveLength(2048);
    expect(new Set(BIP39_ENGLISH).size).toBe(2048);
    expect([...BIP39_ENGLISH].sort()).toEqual([...BIP39_ENGLISH]);
    for (const w of BIP39_ENGLISH) expect(w).toMatch(/^[a-z]+$/);
    expect(BIP39_ENGLISH[0]).toBe("abandon");
    expect(BIP39_ENGLISH[2047]).toBe("zoo");
  });

  it("is byte-identical to the official file (SHA-256 of the file content)", async () => {
    // The official file ends with a newline after the last word.
    const content = `${BIP39_ENGLISH.join("\n")}\n`;
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content)),
    );
    const hex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe(OFFICIAL_SHA256);
  });
});
