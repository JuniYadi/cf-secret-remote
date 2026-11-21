import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Fetch } from "../server.ts";
import { assetName, parseChecksums, sha256Hex, upgradeBinary, writeProjectFile } from "./deploy.ts";

const BASE = "https://releases.example.com/v1";
const OLD = "old cfs binary";
const NEW = new TextEncoder().encode("new cfs binary");

let dir: string;
let exe: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cfs-deploy-"));
  exe = join(dir, "cfs");
  writeFileSync(exe, OLD);
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Serves SHA256SUMS and the binary from BASE. Anything else is a 404. */
function release(opts: { sums?: string; binary?: Uint8Array; asset: string }) {
  const asked: string[] = [];
  const f: Fetch = async (url) => {
    asked.push(url);
    if (url === `${BASE}/SHA256SUMS`) return new Response(opts.sums ?? "");
    if (url === `${BASE}/${opts.asset}` && opts.binary)
      return new Response(opts.binary as BodyInit);
    return new Response("missing", { status: 404 });
  };
  return { f, asked };
}

const line = (hex: string, name: string) => `${hex}  ${name}\n`;

describe("cfs upgrade checksum verification (ADR 25)", () => {
  test("a matching checksum replaces the binary, executable, and leaves no temp file", async () => {
    const asset = "cfs-linux-x64";
    const sums = line(await sha256Hex(NEW), asset);
    const r = release({ sums, binary: NEW, asset });
    await upgradeBinary({ baseUrl: `${BASE}/`, asset, exePath: exe, fetch: r.f });
    expect(readFileSync(exe, "utf8")).toBe("new cfs binary");
    expect(statSync(exe).mode & 0o777).toBe(0o755);
    expect(existsSync(`${exe}.new`)).toBe(false);
    expect(r.asked).toEqual([`${BASE}/SHA256SUMS`, `${BASE}/${asset}`]);
  });

  test("a checksum mismatch aborts and the existing binary is untouched", async () => {
    const asset = "cfs-linux-x64";
    const r = release({ sums: line("0".repeat(64), asset), binary: NEW, asset });
    await expect(upgradeBinary({ baseUrl: BASE, asset, exePath: exe, fetch: r.f })).rejects.toThrow(
      /Checksum mismatch.*nothing changed/,
    );
    expect(readFileSync(exe, "utf8")).toBe(OLD);
    expect(existsSync(`${exe}.new`)).toBe(false);
  });

  test("a binary that was tampered with after the checksum was published is refused", async () => {
    const asset = "cfs-linux-x64";
    const sums = line(await sha256Hex(new TextEncoder().encode("the published build")), asset);
    const r = release({ sums, binary: NEW, asset });
    await expect(upgradeBinary({ baseUrl: BASE, asset, exePath: exe, fetch: r.f })).rejects.toThrow(
      /Checksum mismatch/,
    );
    expect(readFileSync(exe, "utf8")).toBe(OLD);
  });

  test("no checksum entry for this asset aborts", async () => {
    const asset = "cfs-linux-x64";
    const r = release({ sums: line("a".repeat(64), "cfs-darwin-arm64"), binary: NEW, asset });
    await expect(upgradeBinary({ baseUrl: BASE, asset, exePath: exe, fetch: r.f })).rejects.toThrow(
      /no entry for cfs-linux-x64/,
    );
    expect(readFileSync(exe, "utf8")).toBe(OLD);
  });

  test("a failed binary download aborts and changes nothing", async () => {
    const asset = "cfs-linux-x64";
    const r = release({ sums: line(await sha256Hex(NEW), asset), asset });
    await expect(upgradeBinary({ baseUrl: BASE, asset, exePath: exe, fetch: r.f })).rejects.toThrow(
      /Could not download the binary/,
    );
    expect(readFileSync(exe, "utf8")).toBe(OLD);
  });

  test("the download base is injectable, so the URL can point at a test server", async () => {
    const asset = "cfs-linux-x64";
    const r = release({ sums: line(await sha256Hex(NEW), asset), binary: NEW, asset });
    await upgradeBinary({ baseUrl: BASE, asset, exePath: exe, fetch: r.f });
    expect(r.asked.every((u) => u.startsWith(BASE))).toBe(true);
  });
});

describe("release assets and checksum file", () => {
  test("each supported platform maps to its release asset", () => {
    expect(assetName("darwin", "arm64")).toBe("cfs-darwin-arm64");
    expect(assetName("darwin", "x64")).toBe("cfs-darwin-x64");
    expect(assetName("linux", "arm64")).toBe("cfs-linux-arm64");
    expect(assetName("linux", "x64")).toBe("cfs-linux-x64");
    expect(assetName("win32", "x64")).toBe("cfs-windows-x64.exe");
  });

  test("unsupported platforms are refused", () => {
    expect(() => assetName("win32", "arm64")).toThrow(/no cfs release/);
    expect(() => assetName("freebsd", "x64")).toThrow(/no cfs release/);
  });

  test("SHA256SUMS is read in sha256sum format, with or without the binary marker", () => {
    const hex = "AB".repeat(32);
    const sums = parseChecksums(
      `${hex}  cfs-linux-x64\n${"cd".repeat(32)} *cfs-darwin-arm64\nnot a line\n`,
    );
    expect(sums.get("cfs-linux-x64")).toBe(hex.toLowerCase());
    expect(sums.get("cfs-darwin-arm64")).toBe("cd".repeat(32));
    expect(sums.size).toBe(2);
  });

  test("sha256 of a known input", async () => {
    expect(await sha256Hex(new TextEncoder().encode("abc"))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("cfs init writes .cfs.json", () => {
  test("writes host and project, with an https host", () => {
    const path = join(dir, ".cfs.json");
    writeProjectFile(path, { host: "https://vault.example.com/", project: "myapp" });
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({
      host: "https://vault.example.com",
      project: "myapp",
    });
  });

  test("a plain http host for a remote server is refused", () => {
    expect(() =>
      writeProjectFile(join(dir, ".cfs.json"), {
        host: "http://vault.example.com",
        project: "myapp",
      }),
    ).toThrow(/https/);
  });

  test("an invalid project name is refused", () => {
    expect(() =>
      writeProjectFile(join(dir, ".cfs.json"), {
        host: "https://v.example.com",
        project: "my app/x",
      }),
    ).toThrow(/valid project name/);
  });

  test("an existing file is only replaced when asked to", () => {
    const path = join(dir, ".cfs.json");
    writeFileSync(path, "{}");
    expect(() =>
      writeProjectFile(path, { host: "https://v.example.com", project: "myapp" }),
    ).toThrow(/already exists/);
    writeProjectFile(path, { host: "https://v.example.com", project: "myapp" }, true);
    expect(JSON.parse(readFileSync(path, "utf8")).project).toBe("myapp");
  });
});
