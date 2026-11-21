// The forgot-password request that this browser started (ADR 20). It holds the new public key, the locked
// key, the four words and the cancel token, in memory only. Nothing goes to storage or the URL. A reload
// loses it, and the person starts again (the words on the admin's side are then stale and refused).

export interface PendingRecovery {
  id: string;
  words: string;
  cancelToken: string;
  publicKey: string;
  lockedKey: string;
}

let pending: PendingRecovery | null = null;

export const setPendingRecovery = (next: PendingRecovery): void => {
  pending = next;
};

export const getPendingRecovery = (): PendingRecovery | null => pending;

export const clearPendingRecovery = (): void => {
  pending = null;
};

/** Test helper. */
export const resetPendingRecoveryForTests = (): void => {
  pending = null;
};
