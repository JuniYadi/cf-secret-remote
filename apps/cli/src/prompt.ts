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
