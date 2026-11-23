import { describe, expect, it } from "vitest";

declare global {
  interface ImportMeta {
    glob(
      patterns: string[],
      options: { eager: true; query: string; import: string },
    ): Record<string, string>;
  }
}

const sources = import.meta.glob(
  ["../src/**/*.ts", "!../src/repository/**", "!../src/**/*.test.ts"],
  { eager: true, query: "?raw", import: "default" },
);

describe("repository boundary", () => {
  it("keeps D1 query construction inside repository modules", () => {
    const violations = Object.entries(sources).flatMap(([path, source]) => {
      const text = source as string;
      // RegExp.exec is valid outside the repository; only check known D1 handle forms.
      const forbidden =
        /\.\s*prepare\s*\(|\b(?:db|(?:c\.)?env\.DB)\s*\.\s*(?:batch|exec)\s*\(|\bD1PreparedStatement\b/g;
      return [...text.matchAll(forbidden)].map((match) => `${path}: ${match[0]}`);
    });
    expect(Object.keys(sources).length).toBeGreaterThan(0);
    expect(violations).toEqual([]);
  });
});
