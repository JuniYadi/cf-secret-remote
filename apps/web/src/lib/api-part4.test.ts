import { describe, expect, it, vi } from "vitest";
import { ApiError, queryString, request } from "./api.ts";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("query strings", () => {
  it("skips empty values and encodes the rest", () => {
    expect(queryString({ who: "a b", action: "", path: undefined, from: 10 })).toBe(
      "?who=a%20b&from=10",
    );
    expect(queryString({ who: "", path: null })).toBe("");
  });
});

describe("error details kept by the client", () => {
  it("keeps attemptsLeft from a 404 body, and nothing else from the body", async () => {
    const fetchImpl = async () =>
      json(404, { error: "code not found or expired", attemptsLeft: 3, secret: "x" });
    const err = await request("GET", "/cli/login?code=AAAA-BBBB", undefined, fetchImpl).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).attemptsLeft).toBe(3);
    expect((err as ApiError).message).toBe("not-found");
  });

  it("ignores a body that is not a count", async () => {
    const fetchImpl = async () => json(404, { attemptsLeft: "many" });
    const err = await request("POST", "/cli/approve", { userCode: "x" }, fetchImpl).catch(
      (e: unknown) => e,
    );
    expect((err as ApiError).attemptsLeft).toBeUndefined();
  });

  it("does not read the body of other errors", async () => {
    const fetchImpl = vi.fn(async () => json(500, { attemptsLeft: 2 }));
    const err = await request("GET", "/usage", undefined, fetchImpl).catch((e: unknown) => e);
    expect((err as ApiError).attemptsLeft).toBeUndefined();
  });
});
