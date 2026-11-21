import { b64uDecode, fromUtf8 } from "@cfs/core";
import type { Env } from "./types.ts";

interface Jwk extends JsonWebKey {
  kid: string;
}
let cache: { at: number; keys: Jwk[] } | undefined;

async function keys(env: Env): Promise<Jwk[]> {
  if (cache && Date.now() - cache.at < 3600_000) return cache.keys;
  const r = await fetch(`https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`);
  if (!r.ok) throw new Error("cannot load Access keys");
  const body = (await r.json()) as { keys: Jwk[] };
  cache = { at: Date.now(), keys: body.keys };
  return body.keys;
}

/** Verifies a Cloudflare Access JWT (RS256) and returns the user's email, or null. */
export async function verifyAccessJwt(env: Env, jwt: string | undefined): Promise<string | null> {
  return (await verifyAccessClaims(env, jwt))?.email ?? null;
}

export interface AccessClaims {
  email: string;
  /** Issued-at, unix seconds. ADR 20 uses it to require a fresh login for recovery. */
  iat: number;
}

/** Verifies a Cloudflare Access JWT (RS256) and returns its email and issue time, or null. */
export async function verifyAccessClaims(
  env: Env,
  jwt: string | undefined,
): Promise<AccessClaims | null> {
  if (!jwt || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  const [h, p, s] = jwt.split(".");
  if (!h || !p || !s) return null;
  try {
    const header = JSON.parse(fromUtf8(b64uDecode(h))) as { kid?: string; alg?: string };
    if (header.alg !== "RS256") return null;
    const jwk = (await keys(env)).find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      b64uDecode(s) as BufferSource,
      new TextEncoder().encode(`${h}.${p}`) as BufferSource,
    );
    if (!ok) return null;
    const c = JSON.parse(fromUtf8(b64uDecode(p))) as {
      aud?: string[] | string;
      iss?: string;
      exp?: number;
      iat?: number;
      email?: string;
    };
    const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
    if (!aud.includes(env.ACCESS_AUD)) return null;
    if (c.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) return null;
    if (!c.exp || c.exp < Date.now() / 1000) return null;
    if (typeof c.iat !== "number" || !c.email) return null;
    return { email: c.email.toLowerCase(), iat: c.iat };
  } catch {
    return null;
  }
}
