import { type Login, loginOrigin } from "./login.ts";

export type ImportFormat = "csv" | "chrome" | "bitwarden";
export type ImportResult = { rows: Login[]; errors: { line: number; message: string }[] };
export type ImportMode = "add" | "skip" | "overwrite";

// Parse records with their physical starting line. A syntax error cannot be safely recovered.
function csvRecords(text: string): { values: string[]; line: number }[] {
  text = text.replace(/^\uFEFF/, "");
  const records: { values: string[]; line: number }[] = [];
  let values: string[] = [],
    value = "",
    line = 1,
    start = 1,
    quoted = false,
    closed = false,
    started = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          value += '"';
          i++;
        } else {
          quoted = false;
          closed = true;
        }
      } else {
        value += ch;
        if (ch === "\n") line++;
        else if (ch === "\r" && text[i + 1] !== "\n") line++;
      }
    } else if (ch === ",") {
      values.push(value);
      value = "";
      closed = false;
      started = true;
    } else if (ch === "\r" || ch === "\n") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      values.push(value);
      records.push({ values, line: start });
      values = [];
      value = "";
      closed = false;
      started = false;
      line++;
      start = line;
    } else if (ch === '"' && !value && !closed) {
      quoted = true;
      started = true;
    } else if (ch === '"' || closed) throw new Error(`line ${line}: invalid CSV quoting`);
    else {
      value += ch;
      started = true;
    }
  }
  if (quoted) throw new Error(`line ${start}: unterminated quoted field`);
  if (started || values.length) {
    values.push(value);
    records.push({ values, line: start });
  }
  return records;
}

const headers: Record<"csv" | "chrome", string[]> = {
  csv: ["site", "environment", "role", "username", "password", "totp", "notes"],
  chrome: ["name", "url", "username", "password", "note"],
};
export function detectImportFormat(text: string): ImportFormat {
  if (
    text
      .replace(/^\uFEFF/, "")
      .trimStart()
      .startsWith("{")
  )
    return "bitwarden";
  const first = csvRecords(text)[0]?.values.map((v) => v.trim().toLowerCase()) ?? [];
  if (headers.csv.every((h) => first.includes(h))) return "csv";
  if (headers.chrome.every((h) => first.includes(h))) return "chrome";
  throw new Error("Unrecognized import format or CSV header");
}
export function parseLogins(
  text: string,
  format: ImportFormat = detectImportFormat(text),
): ImportResult {
  const result: ImportResult = { rows: [], errors: [] };
  if (format === "bitwarden") {
    let data: unknown;
    try {
      data = JSON.parse(text.replace(/^\uFEFF/, ""));
    } catch {
      throw new Error("Invalid Bitwarden JSON");
    }
    if (!data || typeof data !== "object" || Array.isArray(data))
      throw new Error("Invalid Bitwarden export");
    const exportData = data as Record<string, unknown>;
    if (exportData.encrypted === true || typeof exportData.data === "string")
      throw new Error("Encrypted Bitwarden exports are not supported; use an unencrypted export");
    if (!Array.isArray(exportData.items))
      throw new Error("Invalid Bitwarden export: missing items array");
    exportData.items.forEach((item: unknown, i: number) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        result.errors.push({ line: i + 1, message: "Invalid item" });
        return;
      }
      const v = item as Record<string, unknown>;
      if (v.type !== 1) return;
      const login =
        v.login && typeof v.login === "object" && !Array.isArray(v.login)
          ? (v.login as Record<string, unknown>)
          : null;
      const uris = login?.uris;
      const first = Array.isArray(uris) ? uris[0] : undefined;
      const uri =
        first && typeof first === "object" ? (first as Record<string, unknown>).uri : undefined;
      const vals = [v.name, v.notes, login?.username, login?.password, login?.totp, uri];
      if (!login || vals.some((x) => x != null && typeof x !== "string")) {
        result.errors.push({ line: i + 1, message: "Invalid login fields" });
        return;
      }
      result.rows.push({
        v: 1,
        name: (v.name as string) ?? "",
        url: (uri as string) ?? "",
        environment: "",
        role: "",
        username: (login.username as string) ?? "",
        password: (login.password as string) ?? "",
        totp: (login.totp as string) ?? "",
        notes: (v.notes as string) ?? "",
      });
    });
    return result;
  }
  let records: ReturnType<typeof csvRecords>;
  try {
    records = csvRecords(text);
  } catch (e) {
    const message = (e as Error).message;
    const line = Number(/^line (\d+):/.exec(message)?.[1] ?? 1);
    return { rows: [], errors: [{ line, message }] };
  }
  const header = records.shift()?.values.map((v) => v.trim().toLowerCase()) ?? [];
  if (new Set(header).size !== header.length || !headers[format].every((h) => header.includes(h)))
    throw new Error(`Invalid ${format} CSV header`);
  for (const record of records) {
    if (record.values.length !== header.length) {
      result.errors.push({
        line: record.line,
        message: `Expected ${header.length} columns, got ${record.values.length}`,
      });
      continue;
    }
    const get = (key: string) => record.values[header.indexOf(key)] ?? "";
    result.rows.push({
      v: 1,
      name: get(format === "csv" ? "site" : "name"),
      url: get(format === "csv" ? "site" : "url"),
      environment: format === "csv" ? get("environment") : "",
      role: format === "csv" ? get("role") : "",
      username: get("username"),
      password: get("password"),
      totp: format === "csv" ? get("totp") : "",
      notes: get(format === "csv" ? "notes" : "note"),
    });
  }
  return result;
}
function key(login: Login): string | null {
  const origin = loginOrigin(login.url);
  return origin === null
    ? null
    : JSON.stringify([origin, login.environment, login.role, login.username]);
}
export function findDuplicates(existing: Login[], incoming: Login[]) {
  return incoming.flatMap((login, incomingIndex) => {
    const k = key(login);
    return k === null
      ? []
      : existing.flatMap((item, existingIndex) =>
          key(item) === k ? [{ existingIndex, incomingIndex }] : [],
        );
  });
}
export function planImport(existing: Login[], incoming: Login[], mode: ImportMode) {
  const creates: Login[] = [];
  const updates: { existingIndex: number; login: Login }[] = [];
  const seen = new Map<string, { kind: "existing" | "create"; index: number }>();
  existing.forEach((login, index) => {
    const k = key(login);
    if (k !== null && !seen.has(k)) seen.set(k, { kind: "existing", index });
  });
  incoming.forEach((login) => {
    const k = key(login),
      match = k === null ? undefined : seen.get(k);
    if (mode === "add" || !match) {
      const index = creates.push(login) - 1;
      if (k !== null && !match) seen.set(k, { kind: "create", index });
    } else if (mode === "overwrite") {
      if (match.kind === "create") creates[match.index] = login;
      else {
        const previous = updates.find((u) => u.existingIndex === match.index);
        if (previous) previous.login = login;
        else updates.push({ existingIndex: match.index, login });
      }
    }
  });
  return { creates, updates };
}
