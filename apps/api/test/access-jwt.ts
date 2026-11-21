import { b64uEncode, utf8 } from "@cfs/core";

// Test-only Cloudflare Access JWTs. vitest.config.ts sets ACCESS_TEAM_DOMAIN=team.test and ACCESS_AUD=aud-test.
// The Worker fetches the team's certs over HTTPS; installAccessCerts() answers that one URL in-process and
// passes every other fetch through.

const KID = "test-kid";
const CERTS_URL = "https://team.test/cdn-cgi/access/certs";

let signing: Promise<CryptoKeyPair> | undefined;
const pair = () =>
  (signing ??= crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>);

let installed = false;
export async function installAccessCerts(): Promise<void> {
  if (installed) return;
  installed = true;
  const jwk = {
    ...(await crypto.subtle.exportKey("jwk", (await pair()).publicKey)),
    kid: KID,
    alg: "RS256",
    use: "sig",
  };
  const realFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === CERTS_URL) return Promise.resolve(Response.json({ keys: [jwk] }));
    return realFetch(input, init);
  };
}

/** A signed Access token for `email`, issued at `iat` (unix seconds). */
export async function accessJwt(email: string, iat: number): Promise<string> {
  const header = b64uEncode(utf8(JSON.stringify({ alg: "RS256", kid: KID })));
  const payload = b64uEncode(
    utf8(
      JSON.stringify({
        aud: ["aud-test"],
        iss: "https://team.test",
        email,
        iat,
        exp: Math.floor(Date.now() / 1000) + 3600,
      }),
    ),
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      (await pair()).privateKey,
      utf8(`${header}.${payload}`) as BufferSource,
    ),
  );
  return `${header}.${payload}.${b64uEncode(sig)}`;
}

/** Headers for a login made just now, as Cloudflare Access sends them. */
export async function freshLogin(email: string): Promise<Record<string, string>> {
  return { "Cf-Access-Jwt-Assertion": await accessJwt(email, Math.floor(Date.now() / 1000)) };
}
