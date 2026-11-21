// The two-admin rule (ADR 20) as the Admins screen shows it. The server enforces it on PATCH /identities/:id;
// this only computes what to show before the person clicks.

import type { Identity } from "./api.ts";
import { adminsWithVault } from "./groups.ts";

/** The server stores recoverySet as 0 or 1 from SQLite, and the JSON may carry either form. */
export const hasRecoveryKey = (i: Pick<Identity, "recoverySet">): boolean =>
  i.recoverySet === true || i.recoverySet === 1;

export interface AdminSummary {
  /** Active people with the admin role. */
  admins: Identity[];
  /** Admins who hold a vault (a public key). Only these count toward the two-admin rule. */
  withVault: Identity[];
  /** True when at least two admins hold a vault. */
  twoAdminsOk: boolean;
  /** Active people who are not admins: the ones who can be made admin. */
  candidates: Identity[];
}

export function adminSummary(directory: Identity[]): AdminSummary {
  const people = directory.filter((i) => i.kind === "user");
  const admins = people.filter((i) => i.role === "admin" && i.status === "active");
  const withVault = admins.filter((i) => i.publicKey !== null);
  return {
    admins,
    withVault,
    twoAdminsOk: adminsWithVault(directory) >= 2,
    candidates: people.filter((i) => i.role === "member" && i.status === "active"),
  };
}
