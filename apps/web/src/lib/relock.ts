// The one re-locking job shown on the "Re-locking" screen (ADR 14). The job holds progress and names only.
// The group key and the values are local to runRotation and are never kept here.
//
// The job runs as a promise. If the person leaves the screen it keeps going. If the page is reloaded the
// job is gone, and the screen says so and offers to cancel the staged rotation.

import type { SecretListRow } from "./api.ts";
import { type RelockProgress, RotationError, type RotationInput, runRotation } from "./groups.ts";

export type JobStatus = "running" | "done" | "failed";

export interface RelockJob {
  id: number;
  prefix: string;
  /** The person removed. Shown by name only. */
  removedName: string;
  /** Names of values they could open: path and secret names, never values. */
  openable: { path: string; names: string[] }[];
  progress: RelockProgress;
  status: JobStatus;
  error: RotationError | null;
}

let job: RelockJob | null = null;
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of [...listeners]) listener();
}

export function currentJob(prefix: string): RelockJob | null {
  return job !== null && job.prefix === prefix ? job : null;
}

export function subscribeRelock(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Forgets the job (after the person leaves the screen with a result, or cancels). */
export function clearRelock(): void {
  job = null;
  emit();
}

/** Test helper. */
export function resetRelockForTests(): void {
  job = null;
  listeners.clear();
}

/**
 * Starts the staged re-key for a removal. Returns the job at once; the promise settles in the job's status.
 * `input.onProgress` is set here, so the caller only supplies the data.
 */
export function startRelock(
  input: Omit<RotationInput, "onProgress">,
  removedName: string,
  client?: Parameters<typeof runRotation>[1],
): RelockJob {
  const openable = input.secrets.map((s: SecretListRow) => ({ path: s.path, names: [...s.names] }));
  const id = ++nextId;
  const started: RelockJob = {
    id,
    prefix: input.prefix,
    removedName,
    openable,
    progress: { total: openable.length, done: 0, current: null, items: [] },
    status: "running",
    error: null,
  };
  job = started;
  emit();

  // Updates only apply to the job that started them. A newer job, or a cleared one, ignores late callbacks.
  const update = (patch: Partial<RelockJob>): void => {
    if (job?.id !== id) return;
    job = { ...job, ...patch };
    emit();
  };

  runRotation({ ...input, onProgress: (progress) => update({ progress }) }, client)
    .then((progress) => update({ progress, status: "done" }))
    .catch((err: unknown) => {
      const error = err instanceof RotationError ? err : new RotationError("secrets", err);
      update({ status: "failed", error });
    });
  return started;
}

let nextId = 0;
