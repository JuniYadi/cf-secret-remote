// ADR 24: the web app is served from the assets binding. The Worker adds the security headers to every
// non-API response, so the strict CSP does not depend on a separate `_headers` file.

export const CONTENT_SECURITY_POLICY =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

/** Returns a copy of the response with the web security headers set. The body is passed through. */
export function withSecurityHeaders(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set("Content-Security-Policy", CONTENT_SECURITY_POLICY);
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/** Serves a static file (or the SPA fallback index.html) through the ASSETS binding, with headers. */
export async function serveAsset(req: Request, assets: Fetcher): Promise<Response> {
  return withSecurityHeaders(await assets.fetch(req));
}
