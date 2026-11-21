import { b64uEncode, utf8 } from "./encoding.ts";

// Tamper-evident audit: entry hash = SHA-256(prevHash "\n" canonicalJSON(entry)). Entries hold names and identities only.
export const GENESIS = "genesis";

export function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .filter((k) => o[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
    .join(",")}}`;
}

export async function chainHash(prev: string, entry: unknown): Promise<string> {
  const d = await crypto.subtle.digest(
    "SHA-256",
    utf8(`${prev}\n${canonical(entry)}`) as BufferSource,
  );
  return b64uEncode(new Uint8Array(d));
}

export interface ChainRow<T = unknown> {
  entry: T;
  hash: string;
}

/** Returns the index of the first bad row, or -1 if the chain is intact. */
export async function verifyChain(rows: ChainRow[], start: string = GENESIS): Promise<number> {
  let prev = start;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]!;
    if ((await chainHash(prev, r.entry)) !== r.hash) return i;
    prev = r.hash;
  }
  return -1;
}
