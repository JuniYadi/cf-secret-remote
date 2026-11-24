import { account } from "./account.ts";
import { app } from "./app.ts";
import { audit } from "./audit.ts";
import { backup } from "./backup.ts";
import { collection } from "./collection.ts";
import { deploy } from "./deploy.ts";
import { group } from "./group.ts";
import { offboard } from "./offboard.ts";
import { proxy } from "./proxy.ts";
import { recovery } from "./recovery.ts";
import { request } from "./request.ts";
import { secrets } from "./secrets.ts";
import { session } from "./session.ts";
import type { Commands, Handler } from "./types.ts";
import { versions } from "./versions.ts";

/** True for `cfs restore <secret> <version>` (ADR 22); anything else is a backup file (ADR 23). */
export function isVersionRestore(args: string[]): boolean {
  const [path, version] = args;
  return (
    path !== undefined &&
    !path.startsWith("-") &&
    version !== undefined &&
    /^[1-9][0-9]*$/.test(version)
  );
}

// `versions` and `backup` both define `restore`; spreading one over the other hid the version restore.
const restore: Handler = (args, host) =>
  (isVersionRestore(args) ? versions : backup).restore?.run(args, host);

export const commands: Commands = {
  ...session,
  ...account,
  ...secrets,
  ...group,
  ...app,
  ...request,
  ...proxy,
  ...audit,
  ...recovery,
  ...offboard,
  ...versions,
  ...collection,
  ...backup,
  ...deploy,
  restore: {
    help: `${versions.restore?.help}\n  ${backup.restore?.help}`,
    run: restore,
  },
};
