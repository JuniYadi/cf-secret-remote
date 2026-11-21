// Confirms that the person saved the recovery key: they type three random words from the 24 (ADR 20).
// The positions are random so a photo of the screen or a half-copied list is not enough by itself.

export const CHALLENGE_SIZE = 3;

/** Picks CHALLENGE_SIZE distinct zero-based word positions out of total, in ascending order. */
export function pickChallenge(
  total = 24,
  random: (n: number) => number = secureRandomBelow,
): number[] {
  const picked = new Set<number>();
  while (picked.size < CHALLENGE_SIZE) picked.add(random(total));
  return [...picked].sort((a, b) => a - b);
}

/** Checks the typed words against the phrase. Case and surrounding spaces are ignored. */
export function checkChallenge(phrase: string[], positions: number[], answers: string[]): boolean {
  return positions.every((pos, i) => {
    const expected = phrase[pos];
    const typed = answers[i];
    return expected !== undefined && typed !== undefined && typed.trim().toLowerCase() === expected;
  });
}

function secureRandomBelow(n: number): number {
  // Rejection sampling keeps the result uniform even when n does not divide 2^32.
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    const value = buf[0] as number;
    if (value < limit) return value % n;
  }
}
