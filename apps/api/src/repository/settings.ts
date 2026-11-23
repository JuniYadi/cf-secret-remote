export async function readLimits(db: D1Database): Promise<string | null> {
  const row = await db
    .prepare("SELECT value FROM setting WHERE key = ?")
    .bind("limits")
    .first<{ value: string }>();
  return row?.value ?? null;
}

export async function writeLimits(db: D1Database, value: string): Promise<void> {
  await db
    .prepare("INSERT OR REPLACE INTO setting (key, value) VALUES (?, ?)")
    .bind("limits", value)
    .run();
}
