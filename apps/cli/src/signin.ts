import { CliError, saveProfile, saveSession } from "./config.ts";
import { checkServer, type Fetch, postJson } from "./server.ts";

// ADR 11 device login, shared by `cfs login` and the trust prompt.

/** Signs in with the device code flow, then saves the profile, the trusted host and the session. */
export async function signIn(
  host: string,
  profile: string,
  fetchImpl: Fetch = fetch,
): Promise<void> {
  await checkServer(host, fetchImpl);
  const api = `${host}/api/v1`;
  const start = await postJson<{
    deviceCode: string;
    userCode: string;
    expiresIn: number;
    interval: number;
  }>(`${api}/cli/start`, { device: process.env.HOSTNAME ?? "cli" }, fetchImpl);
  if (start.status !== 200) throw new CliError("The server did not start a login.");
  console.log(`Open ${host}/cli/authorize and enter this code:\n\n    ${start.body.userCode}\n`);
  const until = Date.now() + start.body.expiresIn * 1000;
  while (Date.now() < until) {
    await Bun.sleep(start.body.interval * 1000);
    const p = await postJson<{ token?: string; expiresIn?: number }>(
      `${api}/cli/poll`,
      { deviceCode: start.body.deviceCode },
      fetchImpl,
    );
    if (p.status === 200 && p.body.token) {
      saveProfile(profile, host);
      saveSession({
        host,
        token: p.body.token,
        expiresAt: Math.floor(Date.now() / 1000) + (p.body.expiresIn ?? 3600),
      });
      console.log("Signed in. Next: cfs unlock");
      return;
    }
    if (p.status === 410) break;
  }
  throw new CliError("The code expired. Run cfs login again.");
}
