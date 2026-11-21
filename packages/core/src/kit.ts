import { b64uDecode, b64uEncode, fromUtf8, utf8 } from "./encoding.ts";

// An access kit is one string for the env var CFS_KIT: "cfskit1_" + base64url(JSON).
// host: server URL, roleId/secretId: AppRole login, privateKey: never sent to the server.
export interface Kit {
  host: string;
  roleId: string;
  secretId: string;
  privateKey: string;
}

const PREFIX = "cfskit1_";

export const encodeKit = (kit: Kit): string => PREFIX + b64uEncode(utf8(JSON.stringify(kit)));

export function decodeKit(s: string): Kit {
  if (!s.startsWith(PREFIX)) throw new Error("not a cfs access kit");
  const k = JSON.parse(fromUtf8(b64uDecode(s.slice(PREFIX.length))));
  for (const f of ["host", "roleId", "secretId", "privateKey"] as const) {
    if (typeof k[f] !== "string" || !k[f]) throw new Error(`access kit is missing ${f}`);
  }
  return k as Kit;
}
