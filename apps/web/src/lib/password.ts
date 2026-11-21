// Strength hint for the vault password. This is advice for the person, not a security boundary: the
// password is only checked by unlocking the key (AES-GCM fails on a wrong password).

export const MIN_PASSWORD_LENGTH = 12;

export type Strength = "weak" | "fair" | "good" | "strong";

export function passwordStrength(password: string): Strength {
  const chars = [...password];
  const distinct = new Set(chars).size;
  if (chars.length < MIN_PASSWORD_LENGTH || distinct < 4) return "weak";
  if (chars.length < 16) return "fair";
  if (chars.length < 20) return "good";
  return "strong";
}

/** The vault password can be created only if it reaches the minimum strength. */
export const isAcceptablePassword = (password: string): boolean =>
  passwordStrength(password) !== "weak";
