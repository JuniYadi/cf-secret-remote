import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { adminSummary, hasRecoveryKey } from "./admins.ts";
import type { Identity, RestoreCheck } from "./api.ts";
import { ApiError, api, kindForFailure, request, retryAfterOf, toBase64 } from "./api.ts";
import { backupFileName, canReplace, gapParts, hostMatches, passphraseProblem } from "./backup.ts";
import {
  getQuota,
  markQuotaReached,
  quotaActive,
  quotaSecondsLeft,
  resetQuotaForTests,
} from "./quota.ts";
import { checkPassed, restoreView } from "./restore-view.ts";

// The API client's rules for the part-5 screens. Fetch is mocked; nothing goes to a server.

const PASSPHRASE = "correct horse battery";

beforeEach(() => resetQuotaForTests());
afterEach(() => resetQuotaForTests());

/** A fetch stand-in that answers once with `res`. */
function fetchReturning(res: Response) {
  return vi.fn(async (_url: string, _init: RequestInit) => res);
}

function callOf(f: ReturnType<typeof fetchReturning>): [string, RequestInit] {
  return f.mock.calls[0] as unknown as [string, RequestInit];
}

describe("quota 503 handling (ADR 19)", () => {
  it("a write refused by the quota is a quota error with Retry-After, and marks the quota", async () => {
    const now = Date.now();
    const f = fetchReturning(
      new Response(
        JSON.stringify({ error: "daily free-tier quota reached, retry after 00:00 UTC" }),
        {
          status: 503,
          headers: { "Retry-After": "3600" },
        },
      ),
    );
    const err = await request("PATCH", "/identities/u1", { role: "admin" }, f).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).kind).toBe("quota");
    expect((err as ApiError).retryAfter).toBe(3600);
    expect(quotaActive(now)).toBe(true);
    // The resume time is set a moment after `now`, and the count rounds up: allow a second.
    expect(quotaSecondsLeft(now)).toBeGreaterThanOrEqual(3599);
    expect(quotaSecondsLeft(now)).toBeLessThanOrEqual(3601);
  });

  it("a read refused by the quota is a quota error but does not pause writes", async () => {
    const f = fetchReturning(
      new Response(JSON.stringify({ error: "daily free-tier quota reached" }), { status: 503 }),
    );
    const err = await request("GET", "/secrets", undefined, f).catch((e: unknown) => e);
    expect((err as ApiError).kind).toBe("quota");
    expect(getQuota().resumeAt).toBeNull();
  });

  it("a restore in progress is a maintenance error, not the quota", async () => {
    const f = fetchReturning(
      new Response(
        JSON.stringify({ error: "maintenance: a restore is running, try again shortly" }),
        { status: 503, headers: { "Retry-After": "60" } },
      ),
    );
    const err = await request("PUT", "/secret", {}, f).catch((e: unknown) => e);
    expect((err as ApiError).kind).toBe("maintenance");
    expect(getQuota().resumeAt).toBeNull();
  });

  it("the quota ends on its own once the wait has passed", () => {
    const t0 = 1_000_000;
    markQuotaReached(10, t0);
    expect(quotaActive(t0 + 9_000)).toBe(true);
    expect(quotaActive(t0 + 10_000)).toBe(false);
    expect(quotaSecondsLeft(t0 + 10_000)).toBe(0);
  });

  it("uses a default wait when the server sends no Retry-After", () => {
    const t0 = 5_000_000;
    markQuotaReached(null, t0);
    expect(quotaSecondsLeft(t0)).toBe(60);
  });

  it("classifies by the message, and keeps any other 503 as unavailable", () => {
    expect(kindForFailure(503, "daily free-tier quota reached")).toBe("quota");
    expect(kindForFailure(503, "maintenance: a restore is running")).toBe("maintenance");
    expect(kindForFailure(503, "")).toBe("unavailable");
    expect(kindForFailure(500, "quota")).toBe("server");
  });

  it("reads Retry-After as seconds, or null", () => {
    expect(retryAfterOf(new Response(null, { headers: { "Retry-After": "42" } }))).toBe(42);
    expect(retryAfterOf(new Response(null))).toBeNull();
    expect(retryAfterOf(new Response(null, { headers: { "Retry-After": "soon" } }))).toBeNull();
  });

  it("an ApiError carries the kind only, never a response body", () => {
    const err = new ApiError("quota", 503, 60);
    expect(err.message).toBe("quota");
  });
});

describe("the backup passphrase never reaches the URL (ADR 23)", () => {
  it("sends it in X-Backup-Passphrase and keeps it out of the URL", async () => {
    const f = fetchReturning(new Response(new Uint8Array([1, 2, 3]), { status: 200 }));
    const blob = await api.downloadBackup(PASSPHRASE, f);
    expect(blob.size).toBe(3);

    const [url, init] = callOf(f);
    expect(url).toBe("/api/v1/backup");
    expect(url).not.toContain(PASSPHRASE);
    expect(url).not.toContain("passphrase");
    expect((init.headers as Record<string, string>)["X-Backup-Passphrase"]).toBe(PASSPHRASE);
    expect(init.method).toBe("GET");
    expect(init.body).toBeUndefined();
  });

  it("sends no passphrase header for a plain download", async () => {
    const f = fetchReturning(new Response(new Uint8Array([1]), { status: 200 }));
    await api.downloadBackup(undefined, f);
    const [url, init] = callOf(f);
    expect(url).toBe("/api/v1/backup");
    expect((init.headers as Record<string, string>)["X-Backup-Passphrase"]).toBeUndefined();
  });

  it("sends the restore file as base64 in the body, and the passphrase only in the header", async () => {
    const f = fetchReturning(
      new Response(JSON.stringify({ ok: true, host: "vault.example", schema: 12 }), {
        status: 200,
      }),
    );
    const bytes = new Uint8Array([0x1f, 0x8b, 0x08]);
    await api.restoreCheck(bytes, PASSPHRASE, f);
    const [url, init] = callOf(f);
    expect(url).toBe("/api/v1/restore/check");
    expect(url).not.toContain(PASSPHRASE);
    expect(String(init.body)).not.toContain(PASSPHRASE);
    expect(JSON.parse(String(init.body))).toEqual({ file: toBase64(bytes) });
    expect((init.headers as Record<string, string>)["X-Backup-Passphrase"]).toBe(PASSPHRASE);
  });

  it("encodes bytes as base64, in chunks, the same as the platform", () => {
    const bytes = new Uint8Array(70_000).map((_, i) => i % 251);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    expect(toBase64(bytes)).toBe(btoa(binary));
  });

  it("asks for at least the server's minimum passphrase length, and no more", () => {
    expect(passphraseProblem("")).toBeNull();
    expect(passphraseProblem("1234567")).toBe("too-short");
    expect(passphraseProblem("12345678")).toBeNull();
  });

  it("names the file by the UTC day", () => {
    expect(backupFileName(new Date("2026-11-21T23:30:00Z"))).toBe(
      "cfs-backup-2026-11-21.cfsbackup",
    );
  });
});

describe("restore check view model (ADR 23)", () => {
  const check: RestoreCheck = {
    ok: true,
    host: "vault.myorg.com",
    schema: 12,
    createdAt: Date.UTC(2026, 10, 19, 0, 0) / 1000,
    gapSeconds: 2 * 86400 + 5 * 3600 + 7 * 60,
    lastAuditAt: null,
    audit: {
      rows: 248,
      ok: true,
      checkpoints: { stored: 2, verified: 2, pruned: 0, mismatched: [] },
    },
    counts: {
      file: { identity: 12, secret: 9, audit: 240 },
      current: { identity: 12, secret: 14, audit: 260 },
    },
    sha256: "ab".repeat(32),
  };

  it("shows when it was made, the counts and the chain result", () => {
    const v = restoreView(check);
    expect(v.madeAt).toBe("2026-11-19 00:00 UTC");
    expect(v.gap).toEqual({ days: 2, hours: 5, minutes: 7 });
    expect(v.people).toBe(12);
    expect(v.secrets).toBe(9);
    expect(v.logEntries).toBe(240);
    expect(v.currentSecrets).toBe(14);
    expect(v.chainOk).toBe(true);
    expect(v.checkpointsOk).toBe(true);
    expect(checkPassed(check)).toBe(true);
  });

  it("reports a broken chain or a mismatched checkpoint as not passed", () => {
    const broken = { ...check, audit: { ...check.audit, ok: false } };
    expect(checkPassed(broken)).toBe(false);
    const mismatch = {
      ...check,
      audit: {
        ...check.audit,
        checkpoints: { ...check.audit.checkpoints, mismatched: ["seq 40"] },
      },
    };
    const v = restoreView(mismatch);
    expect(v.checkpointsOk).toBe(false);
    expect(v.hasMismatchedCheckpoints).toBe(true);
  });

  it("the replace button needs the host typed exactly and the loss acknowledged", () => {
    expect(hostMatches("  VAULT.myorg.com ", "vault.myorg.com")).toBe(true);
    expect(hostMatches("vault.myorg", "vault.myorg.com")).toBe(false);
    expect(canReplace("vault.myorg.com", check, true)).toBe(true);
    expect(canReplace("vault.myorg.com", check, false)).toBe(false);
    expect(canReplace("other.example", check, true)).toBe(false);
  });

  it("splits the gap into days, hours and minutes, never negative", () => {
    expect(gapParts(-5)).toEqual({ days: 0, hours: 0, minutes: 0 });
    expect(gapParts(90_061)).toEqual({ days: 1, hours: 1, minutes: 1 });
  });
});

describe("the two-admin rule on the Admins screen (ADR 20)", () => {
  const row = (over: Partial<Identity>): Identity => ({
    id: "x",
    kind: "user",
    name: "someone@myorg.com",
    role: "member",
    publicKey: null,
    status: "active",
    last_unlocked_at: null,
    recoverySet: false,
    ...over,
  });

  it("counts only admins who hold a vault toward the two", () => {
    const dir = [
      row({ id: "a", role: "admin", publicKey: "pk-a" }),
      row({ id: "b", role: "admin", publicKey: null }),
      row({ id: "c", role: "member", publicKey: "pk-c" }),
    ];
    const s = adminSummary(dir);
    expect(s.admins.map((a) => a.id)).toEqual(["a", "b"]);
    expect(s.withVault.map((a) => a.id)).toEqual(["a"]);
    expect(s.twoAdminsOk).toBe(false);
    expect(s.candidates.map((c) => c.id)).toEqual(["c"]);
  });

  it("is satisfied with two admins holding a vault, and ignores apps and disabled people", () => {
    const dir = [
      row({ id: "a", role: "admin", publicKey: "pk-a" }),
      row({ id: "b", role: "admin", publicKey: "pk-b" }),
      row({ id: "d", role: "admin", publicKey: "pk-d", status: "disabled" }),
      row({ id: "app", kind: "app", role: "member", publicKey: "pk-app" }),
    ];
    expect(adminSummary(dir).twoAdminsOk).toBe(true);
  });

  it("reads the recovery-key flag as true or 1 (SQLite)", () => {
    expect(hasRecoveryKey({ recoverySet: 1 })).toBe(true);
    expect(hasRecoveryKey({ recoverySet: true })).toBe(true);
    expect(hasRecoveryKey({ recoverySet: 0 })).toBe(false);
  });
});
