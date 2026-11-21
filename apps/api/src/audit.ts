import { canonical, chainHash, GENESIS } from "@cfs/core";
import { now } from "./util.ts";

export interface AuditEntry {
  who: string;
  action: string; // e.g. secret.read, secret.write, login.ok, login.denied
  path?: string;
  version?: number;
  result: "ok" | "denied" | "error";
  ip?: string;
  note?: string;
}

/** Appends one hash-chained row. Retries if another writer took the same `prev`. Never put values in an entry. */
export async function audit(db: D1Database, entry: AuditEntry): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const last = await db
      .prepare("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
      .first<{ hash: string }>();
    const prev = last?.hash ?? GENESIS;
    const at = now();
    const full = { ...entry, at };
    const hash = await chainHash(prev, full);
    try {
      await db
        .prepare("INSERT INTO audit (at, entry, prev, hash) VALUES (?, ?, ?, ?)")
        .bind(at, canonical(full), prev, hash)
        .run();
      return;
    } catch (e) {
      if (!String(e).includes("UNIQUE")) throw e;
    }
  }
  throw new Error("audit chain contention");
}
