// The recovery words: the 24-word recovery key (ADR 20) and the four-word code made from a new public key.
// The code is how an admin checks the person before giving access again (ADR 20, DESIGN.md "Verifikasi").

import { fingerprintWords, normalizeWords, recoveryEntropy } from "@cfs/core";

/** Splits typed words. Case, extra spaces and line breaks do not matter. */
export function splitWords(text: string): string[] {
  const norm = normalizeWords(text);
  return norm === "" ? [] : norm.split(" ");
}

/** True when the text has exactly 24 words. The check of the words themselves comes later (checksum). */
export const isRecoveryPhraseShape = (text: string): boolean => splitWords(text).length === 24;

/** The 24 words of a recovery key. Returns the phrase normalized, or null when it is not a valid key. */
export async function validRecoveryPhrase(text: string): Promise<string | null> {
  if (!isRecoveryPhraseShape(text)) return null;
  const phrase = splitWords(text).join(" ");
  try {
    await recoveryEntropy(phrase);
    return phrase;
  } catch {
    return null;
  }
}

/** The four-word code for a public key, the same words the server returns on request (ADR 20). */
export const codeFor = (publicKey: string): Promise<string> => fingerprintWords(publicKey);

/** True when the typed four words are the code of this public key. Checked on the screen as the admin types. */
export async function codeMatches(typed: string, publicKey: string): Promise<boolean> {
  return splitWords(typed).join(" ") === (await fingerprintWords(publicKey));
}
