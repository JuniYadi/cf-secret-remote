import { createInterface } from "node:readline";

/** Reads one line from the terminal. An empty answer returns `fallback`. */
export async function ask(question: string, fallback = ""): Promise<string> {
  if (!process.stdin.isTTY) throw new Error("No terminal to ask in. Pass the value as a flag.");
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const answer = await new Promise<string>((resolve) => rl.question(question, resolve));
  rl.close();
  return answer.trim() || fallback;
}

/** A yes/no question. Only "y" or "yes" is a yes, so the default is no. */
export async function confirm(question: string): Promise<boolean> {
  return /^y(es)?$/i.test(await ask(question));
}

/** Reads one line without echoing it. Falls back to CFS_PASSWORD for scripts. */
export async function askHidden(label: string): Promise<string> {
  if (process.env.CFS_PASSWORD) return process.env.CFS_PASSWORD;
  if (!process.stdin.isTTY)
    throw new Error("No terminal to ask for the vault password. Set CFS_PASSWORD.");
  process.stderr.write(label);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve) => {
    let s = "";
    process.stdin.on("data", function onData(buf: Buffer) {
      for (const ch of buf.toString("utf8")) {
        if (ch === "\r" || ch === "\n" || ch === "\u0004") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.off("data", onData);
          process.stderr.write("\n");
          return resolve(s);
        }
        if (ch === "\u0003") process.exit(130);
        if (ch === "\u007f") s = s.slice(0, -1);
        else s += ch;
      }
    });
  });
}
