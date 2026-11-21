// Offboarding (ADR 21) as a resumable step runner. The plan comes from the server (names and paths only).
// Each step is an API call the server audits and can repeat safely. Group removal runs the client-driven
// rotation (rotation.ts). Running again re-reads the plan, so finished steps drop out and nothing repeats.

import type { OffboardPlan } from "./api.ts";

export type OffboardStep =
  | { kind: "remove-group"; prefix: string }
  | { kind: "reassign-app"; appId: string; appName: string; ownerId: string }
  | { kind: "disable-app"; appId: string; appName: string };

/** For each app the person owns: the new owner's id, or absent to disable the app. */
export interface OffboardChoices {
  reassign: Record<string, string>;
}

/** The steps still to do for this plan, in order: groups first, then apps. */
export function planSteps(plan: OffboardPlan, choices: OffboardChoices): OffboardStep[] {
  const steps: OffboardStep[] = plan.groups.map((prefix) => ({ kind: "remove-group", prefix }));
  for (const app of plan.apps) {
    if (app.status !== "active") continue;
    const ownerId = choices.reassign[app.id];
    steps.push(
      ownerId
        ? { kind: "reassign-app", appId: app.id, appName: app.name, ownerId }
        : { kind: "disable-app", appId: app.id, appName: app.name },
    );
  }
  return steps;
}

export interface OffboardDeps {
  plan: (personId: string) => Promise<OffboardPlan>;
  removeFromGroup: (prefix: string, personId: string) => Promise<unknown>;
  reassignApp: (personId: string, appId: string, ownerId: string) => Promise<unknown>;
  disableApp: (appId: string) => Promise<unknown>;
  finish: (
    personId: string,
  ) => Promise<{ changed: { sessionsEnded: number; policiesRemoved: number; disabled: boolean } }>;
}

export interface OffboardEvent {
  status: "running" | "done";
  step: OffboardStep | { kind: "finish" };
}

export interface OffboardResult {
  /** The steps this run performed. Empty when everything was already done. */
  performed: OffboardStep[];
  finish: { sessionsEnded: number; policiesRemoved: number; disabled: boolean };
  /** The names-only report: what the person could open in the window (ADR 21). */
  report: OffboardPlan["opened"];
  person: OffboardPlan["person"];
}

export class OffboardBlocked extends Error {
  readonly plan: OffboardPlan;
  constructor(plan: OffboardPlan) {
    super("offboarding is not finished");
    this.name = "OffboardBlocked";
    this.plan = plan;
  }
}

/**
 * Runs the offboarding of `personId`. If a step fails, the error propagates and the run stops; calling
 * this again with the same choices picks up where it stopped. Finish is refused (OffboardBlocked) while the
 * person is still in a group, owns an active app, or would leave fewer than two admins with a vault.
 */
export async function runOffboarding(
  deps: OffboardDeps,
  personId: string,
  choices: OffboardChoices,
  onEvent: (event: OffboardEvent) => void = () => undefined,
): Promise<OffboardResult> {
  const plan = await deps.plan(personId);
  const performed: OffboardStep[] = [];

  for (const step of planSteps(plan, choices)) {
    onEvent({ status: "running", step });
    if (step.kind === "remove-group") await deps.removeFromGroup(step.prefix, personId);
    else if (step.kind === "reassign-app")
      await deps.reassignApp(personId, step.appId, step.ownerId);
    else await deps.disableApp(step.appId);
    performed.push(step);
    onEvent({ status: "done", step });
  }

  // Re-read before finish, so the check uses what the server holds now.
  const current = await deps.plan(personId);
  if (!current.canFinish) throw new OffboardBlocked(current);
  onEvent({ status: "running", step: { kind: "finish" } });
  const done = await deps.finish(personId);
  onEvent({ status: "done", step: { kind: "finish" } });
  return {
    performed,
    finish: {
      sessionsEnded: done.changed.sessionsEnded,
      policiesRemoved: done.changed.policiesRemoved,
      disabled: done.changed.disabled,
    },
    report: current.opened,
    person: current.person,
  };
}

/** The report as plain lines, names and paths only, for copying or saving (never values). */
export function reportText(report: OffboardPlan["opened"], name: string): string {
  const lines = [
    `Values ${name} could open (fetched in the last ${report.windowDays} days).`,
    "Names only. Change these values at their source; rotation protects only values written after it.",
    "",
  ];
  if (report.secrets.length === 0) lines.push("(none)");
  for (const s of report.secrets) {
    const names = s.names.length ? s.names.join(", ") : "(names no longer stored)";
    lines.push(`${s.path}\t${names}\tversions ${s.versions.join(", ")}`);
  }
  return lines.join("\n");
}
