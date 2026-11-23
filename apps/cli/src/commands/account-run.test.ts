import { expect, test } from "bun:test";
import { accountPrefixes } from "./secrets.ts";

test("normalises account names and rejects collisions", () => {
  expect(accountPrefixes(["shop-admin:dev:admin", "other"])).toEqual(["SHOP_ADMIN", "OTHER"]);
  expect(() => accountPrefixes(["shop-admin", "shop_admin:prod"])).toThrow("collide");
  expect(() => accountPrefixes([":dev"])).toThrow("nonempty");
});
