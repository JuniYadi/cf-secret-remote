import { account } from "./account.ts";
import { app } from "./app.ts";
import { audit } from "./audit.ts";
import { backup } from "./backup.ts";
import { deploy } from "./deploy.ts";
import { group } from "./group.ts";
import { offboard } from "./offboard.ts";
import { proxy } from "./proxy.ts";
import { recovery } from "./recovery.ts";
import { request } from "./request.ts";
import { secrets } from "./secrets.ts";
import { session } from "./session.ts";
import type { Commands } from "./types.ts";
import { versions } from "./versions.ts";

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
  ...backup,
  ...deploy,
};
