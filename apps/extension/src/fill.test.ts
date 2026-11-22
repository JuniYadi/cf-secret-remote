import { describe, expect, it } from "vitest";
import { eligibleOrigin } from "./fill.ts";

describe("fill origins", () => {
  it("requires the exact secure origin, allowing HTTP only for loopback hosts", () => {
    expect(eligibleOrigin("https://shop.com/cart", "https://shop.com/login")).toBe(true);
    expect(eligibleOrigin("https://staging.shop.com", "https://shop.com")).toBe(false);
    expect(eligibleOrigin("http://localhost:3000", "http://localhost:5173")).toBe(false);
    expect(eligibleOrigin("http://localhost:3000", "http://localhost:3000")).toBe(true);
    expect(eligibleOrigin("http://127.0.0.1:3000", "http://127.0.0.1:3000")).toBe(true);
    expect(eligibleOrigin("http://shop.com", "http://shop.com")).toBe(false);
  });
});
