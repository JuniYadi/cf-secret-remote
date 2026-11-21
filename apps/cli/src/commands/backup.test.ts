import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBackup } from "@cfs/core";
import vector from "../../../../packages/core/test-vectors/backup-seal.json";
import { CliError, type Client } from "../client.ts";
import {
  type CheckReport,
  checkBackup,
  formatCheck,
  passphraseFromEnv,
  restoreBackup,
  saveBackup,
} from "./backup.ts";

interface Call {
  method: string;
  path: string;
  body?: { file?: string; confirmHost?: string };
  headers: Record<string, string>;
}

const REPORT: CheckReport = {
  ok: true,
  host: "cfs.example.com",
  schema: 12,
  createdAt: 1_700_000_000,
  gapSeconds: 7200,
  lastAuditAt: 1_699_999_000,
  audit: { rows: 40, ok: true, checkpoints: { stored: 2, verified: 2, pruned: 0, mismatched: [] } },
  counts: {
    file: { identity: 3, policy: 2 },
    current: { identity: 3, policy: 2 },
  },
  sha256: "abc",
};

/** A fake client that records every request. `refuse` makes a route answer with the given status. */
function fakeClient(refuse: Record<string, number> = {}) {
  const calls: Call[] = [];
  const client = {
    host: "https://cfs.example.com",
    call: async () => {
      throw new Error("not used by backup");
    },
    send: async (
      method: string,
      path: string,
      body?: Call["body"],
      headers: Record<string, string> = {},
    ) => {
      calls.push({ method, path, body, headers });
      const status = refuse[path] ?? 200;
      if (path === "/restore/check")
        return status === 200
          ? { status, body: REPORT }
          : { status, body: { error: "hash mismatch" } };
      return status === 200
        ? { status, body: { ok: true, restoredAt: 1_700_000_100 } }
        : { status, body: { error: "nope" } };
    },
    download: async (path: string, headers: Record<string, string> = {}) => {
      calls.push({ method: "GET", path, headers });
      const status = refuse[path] ?? 200;
      if (status !== 200) return { status, bytes: new Uint8Array(), error: "Only admins" };
      return { status, bytes: new Uint8Array([0x1f, 0x8b, 1, 2, 3]) };
    },
  };
  return { client: client as unknown as Client, calls };
}

const tmp = () => mkdtempSync(join(tmpdir(), "cfs-backup-"));
afterEach(() => {
  delete process.env.CFS_TEST_PASS;
});

describe("ADR 23: backup download", () => {
  it("sends the passphrase in a header, never in the path, and writes the file private", async () => {
    const { client, calls } = fakeClient();
    const out = join(tmp(), "b.cfsbackup");
    const r = await saveBackup(client, { out, passphrase: "a long enough pass" });
    expect(r.sealed).toBe(true);
    expect(calls[0]?.path).toBe("/backup");
    expect(calls[0]?.headers["X-Backup-Passphrase"]).toBe("a long enough pass");
    expect(calls.every((c) => !c.path.includes("a long enough pass"))).toBe(true);
    expect(readFileSync(out)).toEqual(Buffer.from([0x1f, 0x8b, 1, 2, 3]));
    expect(statSync(out).mode & 0o777).toBe(0o600);
  });

  it("writes a plain file when no passphrase is given", async () => {
    const { client, calls } = fakeClient();
    const r = await saveBackup(client, { out: join(tmp(), "p.cfsbackup") });
    expect(r.sealed).toBe(false);
    expect(calls[0]?.headers).toEqual({});
  });

  it("explains a refusal in plain words", async () => {
    const { client } = fakeClient({ "/backup": 403 });
    await expect(saveBackup(client, { out: join(tmp(), "x") })).rejects.toThrow(
      "Only admins can make a backup.",
    );
  });

  it("reads the passphrase from the named variable and checks its length first", () => {
    expect(passphraseFromEnv(undefined)).toBeUndefined();
    expect(() => passphraseFromEnv("CFS_TEST_PASS_MISSING")).toThrow(CliError);
    process.env.CFS_TEST_PASS = "short";
    expect(() => passphraseFromEnv("CFS_TEST_PASS")).toThrow("at least 8");
    process.env.CFS_TEST_PASS = "long enough passphrase";
    expect(passphraseFromEnv("CFS_TEST_PASS")).toBe("long enough passphrase");
  });
});

describe("ADR 23: restore check and confirmation", () => {
  it("--check reports counts, the time gap and the audit state, and sends nothing to /restore", async () => {
    const { client, calls } = fakeClient();
    const report = await checkBackup(client, new Uint8Array([1, 2, 3]));
    const lines = formatCheck(report).join("\n");
    expect(lines).toContain("schema 12");
    expect(lines).toContain("2 h ago");
    expect(lines).toContain("audit chain: ok");
    expect(lines).toContain("identity");
    expect(calls.map((c) => c.path)).toEqual(["/restore/check"]);
    expect(calls[0]?.body?.file).toBe(Buffer.from([1, 2, 3]).toString("base64"));
  });

  it("a refused file gives the server's reason", async () => {
    const { client } = fakeClient({ "/restore/check": 422 });
    await expect(checkBackup(client, new Uint8Array([1]))).rejects.toThrow(
      "The backup was refused: hash mismatch",
    );
  });

  it("a typed host name that does not match restores nothing", async () => {
    const { client, calls } = fakeClient();
    await expect(
      restoreBackup(client, new Uint8Array([1]), { confirm: async () => "wrong.example.com" }),
    ).rejects.toThrow("Nothing was changed.");
    expect(calls.map((c) => c.path)).toEqual(["/restore/check"]);
  });

  it("a matching host name sends the restore with that name in the body, and the passphrase in a header", async () => {
    const { client, calls } = fakeClient();
    const seen: CheckReport[] = [];
    const r = await restoreBackup(client, new Uint8Array([9]), {
      passphrase: "a long enough pass",
      confirm: async (check) => {
        seen.push(check);
        return check.host;
      },
    });
    expect(r.restoredAt).toBe(1_700_000_100);
    expect(seen).toHaveLength(1);
    const restore = calls.find((c) => c.path === "/restore");
    expect(restore?.body?.confirmHost).toBe("cfs.example.com");
    expect(restore?.body?.file).toBe(Buffer.from([9]).toString("base64"));
    expect(restore?.headers["X-Backup-Passphrase"]).toBe("a long enough pass");
    expect(calls.every((c) => !c.path.includes("passphrase"))).toBe(true);
  });

  it("a member gets a clear message", async () => {
    const { client } = fakeClient({ "/backup": 403 });
    await expect(saveBackup(client, { out: join(tmp(), "z") })).rejects.toThrow(CliError);
  });

  it("formats an empty audit as such", () => {
    const lines = formatCheck({
      ...REPORT,
      lastAuditAt: null,
      audit: { ...REPORT.audit, rows: 0 },
    });
    expect(lines.join("\n")).toContain("the file has no audit entries");
  });
});

describe("ADR 23: passphrase seal, shared vector", () => {
  it("opens the shared seal vector with the core helper (checked in the CLI as well as the browser)", async () => {
    const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
    const plain = await openBackup(hex(vector.sealed), vector.passphrase);
    expect(new TextDecoder().decode(plain)).toBe(vector.plaintext);
  });
});
