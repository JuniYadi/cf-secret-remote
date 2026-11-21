import { describe, expect, test } from "bun:test";
import { CliError } from "../client.ts";
import { MAX_SECONDS, parseDuration, request } from "./request.ts";

// ADR 16: the CLI's duration parsing and argument checks. The server tests cover the rules themselves.

describe("request duration", () => {
  test("accepts seconds, minutes and hours up to 24 h", () => {
    expect(MAX_SECONDS).toBe(86400);
    expect(parseDuration("90")).toBe(90);
    expect(parseDuration("30s")).toBe(30);
    expect(parseDuration("30m")).toBe(1800);
    expect(parseDuration("2h")).toBe(7200);
    expect(parseDuration("24h")).toBe(86400);
  });

  test("refuses zero, over 24 h, and anything else", () => {
    expect(parseDuration("0")).toBeNull();
    expect(parseDuration("25h")).toBeNull();
    expect(parseDuration("86401")).toBeNull();
    expect(parseDuration("2d")).toBeNull();
    expect(parseDuration("1.5h")).toBeNull();
    expect(parseDuration("")).toBeNull();
  });
});

describe("request command arguments", () => {
  const run = (name: "request" | "requests" | "approve" | "deny", ...args: string[]) => {
    const cmd = request[name];
    if (!cmd) throw new Error(`${name} missing`);
    return cmd.run([...args]);
  };

  test("cfs request needs a path, a reason and a duration, and shows usage otherwise", async () => {
    await expect(run("request", "payments/prod", "--for", "2h")).rejects.toBeInstanceOf(CliError);
    await expect(run("request", "payments/prod", "--reason", "x")).rejects.toBeInstanceOf(CliError);
    await expect(run("request", "payments/prod", "--reason", "x", "--for", "2d")).rejects.toThrow(
      "1s to 24h",
    );
  });

  test("approve and deny need a request id", async () => {
    await expect(run("approve")).rejects.toThrow("Usage: cfs approve");
    await expect(run("deny")).rejects.toThrow("Usage: cfs deny");
  });
});
