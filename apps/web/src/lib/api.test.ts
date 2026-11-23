import { describe, expect, it, vi } from "vitest";
import { ApiError, api, kindForStatus, request } from "./api.ts";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("API client", () => {
  it("maps HTTP statuses to error kinds", () => {
    expect(kindForStatus(400)).toBe("invalid");
    expect(kindForStatus(401)).toBe("unauthorized");
    expect(kindForStatus(403)).toBe("forbidden");
    expect(kindForStatus(404)).toBe("not-found");
    expect(kindForStatus(409)).toBe("conflict");
    expect(kindForStatus(429)).toBe("rate-limited");
    expect(kindForStatus(503)).toBe("unavailable");
    expect(kindForStatus(500)).toBe("server");
    expect(kindForStatus(502)).toBe("server");
  });

  it("sends the same-origin credentials and reads JSON", async () => {
    const fetchImpl = vi.fn(async () => json(200, { id: "u1" }));
    const body = await request<{ id: string }>("GET", "/whoami", undefined, fetchImpl);
    expect(body).toEqual({ id: "u1" });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/whoami");
    expect(init.credentials).toBe("same-origin");
    expect(init.method).toBe("GET");
    expect(init.body).toBeUndefined();
  });

  it("sends a JSON body with a content type for writes", async () => {
    const fetchImpl = vi.fn(async () => json(200, { ok: true }));
    await request("POST", "/vault", { publicKey: "PUB", lockedKey: "LOCK" }, fetchImpl);
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.headers).toMatchObject({ "Content-Type": "application/json" });
    expect(JSON.parse(String(init.body))).toEqual({ publicKey: "PUB", lockedKey: "LOCK" });
  });

  it("throws an ApiError with the mapped kind, and no response text", async () => {
    const fetchImpl = async () =>
      json(409, { error: "vault already set up for alice@x", code: "vault_already_setup" });
    const err = await request("POST", "/vault", {}, fetchImpl).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).kind).toBe("conflict");
    expect((err as ApiError).status).toBe(409);
    expect((err as ApiError).message).toBe("conflict");
    expect((err as ApiError).code).toBe("vault_already_setup");
  });

  it("retains future conflict codes and ignores malformed codes", async () => {
    for (const body of [{ code: "not a code" }, {}, null]) {
      const err = await request("POST", "/secret", {}, async () => json(409, body)).catch(
        (e: unknown) => e,
      );
      expect((err as ApiError).code).toBeUndefined();
    }
    const future = await request("POST", "/secret", {}, async () =>
      json(409, { code: "future_code" }),
    ).catch((e: unknown) => e);
    expect((future as ApiError).code).toBe("future_code");
  });

  it("maps a failed connection to network", async () => {
    const fetchImpl = async () => {
      throw new TypeError("Failed to fetch");
    };
    const err = (await request("GET", "/whoami", undefined, fetchImpl).catch(
      (e: unknown) => e,
    )) as ApiError;
    expect(err.kind).toBe("network");
    expect(err.status).toBe(0);
  });

  it("maps 401 from /whoami to unauthorized", async () => {
    const fetchImpl = async () => json(401, { error: "unauthorized" });
    const err = (await request("GET", "/whoami", undefined, fetchImpl).catch(
      (e: unknown) => e,
    )) as ApiError;
    expect(err.kind).toBe("unauthorized");
  });

  it("does not add a bearer token outside dev builds", async () => {
    const fetchImpl = vi.fn(async () => json(200, {}));
    await request("GET", "/whoami", undefined, fetchImpl);
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.headers).not.toHaveProperty("Authorization");
  });

  it("sets the path on a fetched secret, because the Worker does not return it", async () => {
    const body = {
      version: 1,
      keyringVersion: 1,
      names: ["A"],
      wrappedDek: "d",
      ciphertext: "v1.x",
      createdAt: 1,
    };
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(json(200, body));
    try {
      const rec = await api.secret("demo/prod");
      expect(rec.path).toBe("demo/prod");
      expect(rec.version).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });
});
