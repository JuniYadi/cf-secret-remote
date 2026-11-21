// The vault's crypto steps for the screens. Only @cfs/core does the cryptography. This file just sequences
// the calls. Passwords and private keys are returned to the caller and never stored here.

import {
  generateKeyPair,
  lockPrivateKey,
  lockWithRecoveryKey,
  newRecoveryKey,
  recoveryPhrase,
  unlockPrivateKey,
} from "@cfs/core";

export interface NewVault {
  publicKey: string;
  privateKey: string;
  /** The private key locked with the vault password. This is what the server stores. */
  lockedKey: string;
}

/** Makes a key pair and locks the private key with the vault password. */
export async function createVault(password: string): Promise<NewVault> {
  const pair = await generateKeyPair();
  const lockedKey = await lockPrivateKey(pair.privateKey, password);
  return { publicKey: pair.publicKey, privateKey: pair.privateKey, lockedKey };
}

/** Opens the locked private key. Rejects when the password is wrong. */
export const unlockVault = (lockedKey: string, password: string): Promise<string> =>
  unlockPrivateKey(lockedKey, password);

export interface NewRecoveryKey {
  /** The 24 words, shown once. */
  phrase: string;
  /** The 32 bytes behind the phrase. Kept in memory until the lock is stored. */
  entropy: Uint8Array;
}

export async function createRecoveryKey(): Promise<NewRecoveryKey> {
  const entropy = newRecoveryKey();
  return { phrase: await recoveryPhrase(entropy), entropy };
}

/** Seals the private key under the recovery key. The result is what the server stores. */
export const lockRecovery = (privateKey: string, entropy: Uint8Array): Promise<string> =>
  lockWithRecoveryKey(privateKey, entropy);
