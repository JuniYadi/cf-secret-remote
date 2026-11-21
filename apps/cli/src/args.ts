export function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  args.splice(i, v ? 2 : 1);
  return v;
}

export function flagAll(args: string[], name: string): string[] {
  const out: string[] = [];
  for (let v = flag(args, name); v; v = flag(args, name)) out.push(v);
  return out;
}

export function parseEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    let v = m[2] as string;
    if (/^(".*"|'.*')$/.test(v)) v = v.slice(1, -1);
    out[m[1] as string] = v;
  }
  return out;
}
