import { describe, expect, test } from "bun:test";
import { checkServer, type Fetch, protocolMajor } from "./server.ts";

/** A fake /api/health that answers with the given body. Records the URLs it was asked for. */
function health(body: unknown, status = 200) {
  const asked: string[] = [];
  const f: Fetch = async (url) => {
    asked.push(url);
    return new Response(JSON.stringify(body), { status });
  };
  return { f, asked };
}

describe("protocol major check (ADR 25)", () => {
  test("the major is the number before the first dot", () => {
    expect(protocolMajor(1)).toBe(1);
    expect(protocolMajor("1.4")).toBe(1);
    expect(protocolMajor("2")).toBe(2);
    expect(protocolMajor(undefined)).toBeUndefined();
  });

  test("a server with the same protocol major is accepted, and /api/health is what is asked", async () => {
    const h = health({ ok: true, protocol: 1, version: "0.0.0" });
    await checkServer("https://same.example.com", h.f);
    expect(h.asked).toEqual(["https://same.example.com/api/health"]);
  });

  test("a server with a higher protocol major is refused, and the message says to upgrade cfs", async () => {
    const h = health({ ok: true, protocol: 2, version: "2.0.0" });
    const err = await checkServer("https://newer.example.com", h.f).catch((e: Error) => e);
    expect((err as Error).message).toContain("protocol 2");
    expect((err as Error).message).toContain("cfs upgrade");
  });

  test("a server with a lower protocol major is refused, and the message says to upgrade the server", async () => {
    const h = health({ ok: true, protocol: 0, version: "0.0.1" });
    const err = await checkServer("https://older.example.com", h.f).catch((e: Error) => e);
    expect((err as Error).message).toContain("Upgrade the server");
  });

  test("a server that reports no protocol is refused", async () => {
    const h = health({ ok: true });
    await expect(checkServer("https://none.example.com", h.f)).rejects.toThrow(
      /did not report a protocol version/,
    );
  });

  test("Cloudflare Access in front of /api/health is named as the cause", async () => {
    const blocked: Fetch = async () => {
      const r = new Response("<html>login</html>", { headers: { "content-type": "text/html" } });
      Object.defineProperty(r, "redirected", { value: true });
      Object.defineProperty(r, "url", {
        value: "https://team.cloudflareaccess.com/cdn-cgi/access/login/x",
      });
      return r;
    };
    await expect(checkServer("https://vault.example.com", blocked)).rejects.toThrow(
      /Cloudflare Access is blocking.*\/api\/v1\/\*/,
    );
  });

  test("an unreachable server gives a clear error", async () => {
    const down: Fetch = async () => {
      throw new TypeError("fetch failed");
    };
    await expect(checkServer("https://down.example.com", down)).rejects.toThrow(/Cannot reach/);
  });
});
