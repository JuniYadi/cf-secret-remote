import { now } from "./util.ts";

/** Fixed-window limiter (ADR 27). Returns true if the caller is still within `limit` for this window. */
export async function hit(
  db: D1Database,
  key: string,
  limit: number,
  windowSec: number,
): Promise<boolean> {
  const w = now() - (now() % windowSec);
  await db
    .prepare(
      "INSERT INTO login_attempt (key, window, count) VALUES (?, ?, 1) ON CONFLICT (key, window) DO UPDATE SET count = count + 1",
    )
    .bind(key, w)
    .run();
  const row = await db
    .prepare("SELECT count FROM login_attempt WHERE key = ? AND window = ?")
    .bind(key, w)
    .first<{ count: number }>();
  return (row?.count ?? 0) <= limit;
}

/** Constant-time string comparison for hashes. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
