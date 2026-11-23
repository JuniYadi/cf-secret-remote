/** D1 operations for fixed-window login attempt counts. */
export function countAttempt(db: D1Database, key: string, window: number) {
  return db
    .prepare(
      "INSERT INTO login_attempt (key, window, count) VALUES (?, ?, 1) ON CONFLICT (key, window) DO UPDATE SET count = count + 1",
    )
    .bind(key, window)
    .run();
}

export function getAttemptCount(db: D1Database, key: string, window: number) {
  return db
    .prepare("SELECT count FROM login_attempt WHERE key = ? AND window = ?")
    .bind(key, window)
    .first<{ count: number }>();
}
