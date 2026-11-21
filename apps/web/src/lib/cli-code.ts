// The short code from the terminal (ADR 11): ABCD-EFGH. The person may type it in any case, with or without
// the hyphen, or with spaces. The same rule as normalizeUserCode in apps/api/src/routes/cli.ts.

export const CODE_PATTERN = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;

/** Upper case, no spaces or other marks, and a hyphen after four characters once eight are typed. */
export function normalizeUserCode(raw: string): string {
  const s = raw.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return s.length === 8 ? `${s.slice(0, 4)}-${s.slice(4)}` : raw.trim().toUpperCase();
}

/** True when the normalised value is a full code. */
export const isCompleteCode = (raw: string): boolean => CODE_PATTERN.test(normalizeUserCode(raw));
