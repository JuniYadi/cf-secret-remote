// Values are hidden unless the person presses Show. A shown value hides again after 30 seconds (ADR 24).
// The timer lives in the component (components/Revealable.tsx). This file holds the rule itself.

export const REVEAL_MS = 30_000;

/** The time a value shown at `now` (epoch milliseconds) hides again. */
export const revealDeadline = (now: number): number => now + REVEAL_MS;

/** True while a shown value is still inside its window. */
export const isRevealed = (deadline: number | null, now: number): boolean =>
  deadline !== null && now < deadline;
