import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { accessJwt, installAccessCerts } from "./access-jwt.ts";

// ADR 4 follow-up (#28): /api/v1/* is an Access bypass path, so the browser's identity arrives as the
// CF_Authorization cookie, not as the Cf-Access-Jwt-Assertion header.

const ADMIN = "admin@test.dev"; // BOOTSTRAP_ADMIN_EMAIL in vitest.config.ts
const ORIGIN = "http://t.test";

beforeAll(installAccessCerts);

const call = (method: string, path: string, headers: Record<string, string>, body?: unknown) =>
  SELF.fetch(`${ORIGIN}/api/v1${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

describe("Access JWT from the CF_Authorization cookie", () => {
  it("signs a person in on GET, with no Access header", async () => {
    const jwt = await accessJwt(ADMIN, Math.floor(Date.now() / 1000));
    const r = await call("GET", "/whoami", { Cookie: `theme=dark; CF_Authorization=${jwt}` });
    expect(r.status).toBe(200);
    expect(((await r.json()) as { name: string }).name).toBe(ADMIN);
  });

  it("rejects a forged or expired cookie like a forged header", async () => {
    const jwt = await accessJwt(ADMIN, Math.floor(Date.now() / 1000));
    const forged = `${jwt.slice(0, -4)}AAAA`;
    expect((await call("GET", "/whoami", { Cookie: `CF_Authorization=${forged}` })).status).toBe(
      401,
    );
    expect((await call("GET", "/whoami", { Cookie: "CF_Authorization=not.a.jwt" })).status).toBe(
      401,
    );
    expect((await call("GET", "/whoami", {})).status).toBe(401);
  });

  it("refuses a state-changing cookie request from another origin (CSRF)", async () => {
    const jwt = await accessJwt(ADMIN, Math.floor(Date.now() / 1000));
    const cookie = { Cookie: `CF_Authorization=${jwt}` };
    const body = { email: "csrf@test.dev" };
    expect((await call("POST", "/invites", cookie, body)).status).toBe(403); // no Origin
    expect(
      (await call("POST", "/invites", { ...cookie, Origin: "https://evil.example" }, body)).status,
    ).toBe(403);
    expect((await call("POST", "/invites", { ...cookie, Origin: ORIGIN }, body)).status).toBe(201);
  });

  it("does not apply the Origin rule to the header form or to bearer tokens", async () => {
    const jwt = await accessJwt(ADMIN, Math.floor(Date.now() / 1000));
    const r = await call(
      "POST",
      "/invites",
      { "Cf-Access-Jwt-Assertion": jwt },
      { email: "hdr@test.dev" },
    );
    expect(r.status).toBe(201);
  });
});
