import { b64uEncode, generateKeyPair, newGroupKey, unwrapGroupKey, wrapGroupKey } from "@cfs/core";
import { describe, expect, it, vi } from "vitest";
import {
  type Approval,
  approveWithGroupKey,
  checkRequest,
  MAX_REQUEST_SECONDS,
  validDuration,
} from "./requests.ts";

describe("request duration", () => {
  it("accepts whole seconds from 1 to 24 hours", () => {
    expect(validDuration(1)).toBe(true);
    expect(validDuration(3600)).toBe(true);
    expect(validDuration(MAX_REQUEST_SECONDS)).toBe(true);
  });

  it("refuses zero, more than 24 hours, and fractions", () => {
    expect(validDuration(0)).toBe(false);
    expect(validDuration(MAX_REQUEST_SECONDS + 1)).toBe(false);
    expect(validDuration(90.5)).toBe(false);
    expect(validDuration(Number.NaN)).toBe(false);
  });
});

describe("request form checks", () => {
  const good = { path: "myapp/prod", reason: "Hotfix for checkout bug #482", duration: 7200 };

  it("passes a complete request", () => {
    expect(checkRequest(good)).toEqual({});
  });

  it("needs a path with a literal group, and no leading or trailing slash", () => {
    expect(checkRequest({ ...good, path: "" }).path).toBe("path");
    expect(checkRequest({ ...good, path: "/myapp/prod" }).path).toBe("path");
    expect(checkRequest({ ...good, path: "myapp//prod" }).path).toBe("path");
    expect(checkRequest({ ...good, path: "my*app/prod" }).path).toBe("path");
    expect(checkRequest({ ...good, path: "payments/*" })).toEqual({});
  });

  it("needs a reason of up to 500 characters", () => {
    expect(checkRequest({ ...good, reason: "   " }).reason).toBe("reason");
    expect(checkRequest({ ...good, reason: "x".repeat(501) }).reason).toBe("reason");
    expect(checkRequest({ ...good, reason: "x".repeat(500) })).toEqual({});
  });

  it("flags a duration over 24 hours", () => {
    expect(checkRequest({ ...good, duration: 25 * 3600 }).duration).toBe("duration");
  });
});

describe("approval wraps the group key for the requester", () => {
  const prefix = "shop";
  const version = 4;

  it("sends only a wrapped key, which the requester alone can open", async () => {
    const approver = await generateKeyPair();
    const requester = await generateKeyPair();
    const groupKey = await newGroupKey();
    const forApprover = await wrapGroupKey(groupKey, approver.publicKey, prefix, version);

    const sent: Approval[] = [];
    await approveWithGroupKey({ requesterId: "req-1", groupPrefix: prefix }, approver, {
      fetchGroupKey: vi.fn(async (p: string) => {
        expect(p).toBe(prefix);
        return { wrappedKey: forApprover, version };
      }),
      requesterPublicKey: vi.fn(async (id: string) => {
        expect(id).toBe("req-1");
        return requester.publicKey;
      }),
      send: vi.fn(async (a: Approval) => {
        sent.push(a);
      }),
    });

    expect(sent).toHaveLength(1);
    const body = JSON.stringify(sent[0]);
    // The group key never appears in the request body in the clear, in any encoding this code uses.
    expect(body).not.toContain(b64uEncode(groupKey));
    expect(body).not.toContain(forApprover);
    expect(sent[0]?.version).toBe(version);

    const opened = await unwrapGroupKey(
      sent[0]?.wrappedKey ?? "",
      requester.privateKey,
      requester.publicKey,
      prefix,
      version,
    );
    expect(b64uEncode(opened)).toBe(b64uEncode(groupKey));
  });

  it("does not send anything when the approver cannot open their own copy", async () => {
    const approver = await generateKeyPair();
    const stranger = await generateKeyPair();
    const requester = await generateKeyPair();
    const groupKey = await newGroupKey();
    const forApprover = await wrapGroupKey(groupKey, approver.publicKey, prefix, version);
    const send = vi.fn(async () => undefined);

    await expect(
      approveWithGroupKey({ requesterId: "req-1", groupPrefix: prefix }, stranger, {
        fetchGroupKey: async () => ({ wrappedKey: forApprover, version }),
        requesterPublicKey: async () => requester.publicKey,
        send,
      }),
    ).rejects.toThrow();
    expect(send).not.toHaveBeenCalled();
  });
});
