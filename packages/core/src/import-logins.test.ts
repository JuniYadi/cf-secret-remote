import { readFile } from "node:fs/promises";
import { expect, test } from "vitest";
import { detectImportFormat, findDuplicates, parseLogins, planImport } from "./import-logins.ts";

const fixture = (name: string) =>
  readFile(new URL(`../test-fixtures/import/${name}`, import.meta.url), "utf8");
test("parses formats and CSV quoting", async () => {
  const generic = await fixture("generic.csv"),
    chrome = await fixture("chrome.csv"),
    bw = await fixture("bitwarden.json");
  expect(detectImportFormat(generic)).toBe("csv");
  expect(parseLogins(`\uFEFF${generic.replace(/\n/g, "\r\n")}`).rows[0]?.notes).toBe(
    'line one\r\nline "two"',
  );
  expect(detectImportFormat(chrome)).toBe("chrome");
  expect(parseLogins(chrome).rows[0]?.url).toBe("https://example.test/login");
  expect(detectImportFormat(bw)).toBe("bitwarden");
  expect(parseLogins(bw).rows[0]?.totp).toBe("FAKESEED");
  expect(() => parseLogins('{"encrypted":true}', "bitwarden")).toThrow("Encrypted");
});
test("reports malformed rows and quoting", () => {
  const header = "site,environment,role,username,password,totp,notes\n";
  expect(parseLogins(`${header}a,b\n`, "csv").errors[0]?.line).toBe(2);
  expect(parseLogins(`${header}"broken`, "csv").errors[0]?.line).toBe(2);
});
test("matches origin and plans each mode, including repeated incoming rows", async () => {
  const login = parseLogins(await fixture("chrome.csv")).rows[0]!;
  const incoming = [
    { ...login, url: "https://example.test/other", password: "new" },
    { ...login, password: "last" },
  ];
  expect(findDuplicates([login], incoming)).toHaveLength(2);
  expect(findDuplicates([login], [{ ...login, url: "invalid" }])).toHaveLength(0);
  expect(planImport([login], incoming, "add").creates).toHaveLength(2);
  expect(planImport([login], incoming, "skip").creates).toHaveLength(0);
  expect(planImport([login], incoming, "overwrite").updates[0]?.login.password).toBe("last");
  expect(planImport([], incoming, "overwrite").creates[0]?.password).toBe("last");
});
