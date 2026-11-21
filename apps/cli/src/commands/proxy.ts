import { flag } from "../args.ts";
import { CliError, connect } from "../client.ts";
import {
  type AgentRule,
  cachedSecrets,
  clientSecretLoader,
  fetchUpstreamReal,
  parseListen,
  startProxy,
} from "../proxy.ts";
import type { Commands } from "./types.ts";

// ADR 17. `cfs proxy --listen 127.0.0.1:8787 [--reason text]` runs the local proxy for this app's rules.
// It signs in with CFS_KIT, loads its own rules, and decrypts locally. The server enforces the budget,
// the reason and approval on every fetch (apps/api/src/agent-guard.ts).

export const proxy: Commands = {
  proxy: {
    help: "cfs proxy [--listen 127.0.0.1:8787] [--reason text]   inject secrets for an agent (ADR 17)",
    run: async (a, h) => {
      const listen = parseListen(flag(a, "--listen") ?? "127.0.0.1:8787");
      const reason = flag(a, "--reason");
      const c = await connect(h);
      const r = await c.call<AgentRule[]>("GET", "/agent/rules");
      if (r.status !== 200) throw new CliError("Could not load this app's rules.");
      if (r.body.length === 0)
        throw new CliError("This app has no agent rules. An admin adds them with the API.");
      const server = await startProxy(listen, {
        rules: r.body,
        getSecret: cachedSecrets(clientSecretLoader(c)),
        fetchUpstream: fetchUpstreamReal,
        sessionReason: reason,
      });
      const aliases = r.body.map((x) => x.alias).join(", ");
      console.log(
        `cfs proxy listening on http://127.0.0.1:${server.port} for: ${aliases}. Values never leave this process.`,
      );
      // Runs until the process is stopped.
      await new Promise<void>(() => {});
    },
  },
};
