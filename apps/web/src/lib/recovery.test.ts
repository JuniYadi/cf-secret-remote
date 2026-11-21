import {
  generateKeyPair,
  lockPrivateKey,
  newGroupKey,
  unlockPrivateKey,
  unwrapGroupKey,
  wrapGroupKey,
} from "@cfs/core";
import { describe, expect, it } from "vitest";
import { ApiError } from "./api.ts";
import {
  codeFor,
  codeMatches,
  isRecoveryPhraseShape,
  splitWords,
  validRecoveryPhrase,
} from "./recovery-code.ts";
import { regrantKeys } from "./regrant.ts";
import {
  createRecoveryKey,
  lockRecovery,
  openWithRecoveryKey,
  relockWithNewPassword,
} from "./vault.ts";

// The shared test vectors (packages/core/test-vectors/recovery.json) for the words, and the real @cfs/core
// primitives for the keys. The browser and the CLI must agree on these.

const ABANDON_24 = `${"abandon ".repeat(23)}art`;
const FINGERPRINT_PUB =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2hEYo9q0x3k7qkIskBE5SDryBZ1dQHhe1gHYR5EE8T9NXUwMHTCmgJ7S0osVvhgh0u-AEJvnNRJxaKdnR4SLQ";

describe("recovery words", () => {
  it("normalizes typed words: case, spaces and line breaks do not matter", () => {
    expect(splitWords("  Anchor\tVELVET \n kiwi   sixty ")).toEqual([
      "anchor",
      "velvet",
      "kiwi",
      "sixty",
    ]);
    expect(splitWords("   ")).toEqual([]);
  });

  it("checks the shape: exactly 24 words", () => {
    expect(isRecoveryPhraseShape(ABANDON_24)).toBe(true);
    expect(isRecoveryPhraseShape(ABANDON_24.split(" ").slice(1).join(" "))).toBe(false);
  });

  it("accepts the 24 words of the vector, normalized, and rejects a bad checksum or word", async () => {
    expect(await validRecoveryPhrase(`  ${ABANDON_24.toUpperCase()} `)).toBe(ABANDON_24);
    // Changing the last word breaks the checksum.
    expect(await validRecoveryPhrase(`${"abandon ".repeat(23)}abandon`)).toBeNull();
    // A word that is not in the list.
    expect(await validRecoveryPhrase(`${"abandon ".repeat(23)}notaword`)).toBeNull();
    expect(await validRecoveryPhrase("abandon abandon")).toBeNull();
  });

  it("makes the four-word code of a public key, the same as the vector", async () => {
    expect(await codeFor(FINGERPRINT_PUB)).toBe("envelope until chimney noble");
  });

  it("matches the typed code against the key, ignoring case and spacing", async () => {
    expect(await codeMatches("  Envelope  UNTIL chimney noble", FINGERPRINT_PUB)).toBe(true);
    expect(await codeMatches("envelope until chimney", FINGERPRINT_PUB)).toBe(false);
    expect(await codeMatches("anchor velvet kiwi sixty", FINGERPRINT_PUB)).toBe(false);
  });
});

describe("recovery key flow (ADR 20)", () => {
  it("opens the private key with the 24 words it was sealed under", async () => {
    const kp = await generateKeyPair();
    const rk = await createRecoveryKey();
    const sealed = await lockRecovery(kp.privateKey, rk.entropy);
    expect(sealed.startsWith("rk1.")).toBe(true);
    expect(await openWithRecoveryKey(sealed, rk.phrase)).toBe(kp.privateKey);
  });

  it("refuses the words of a different recovery key", async () => {
    const kp = await generateKeyPair();
    const rk = await createRecoveryKey();
    const other = await createRecoveryKey();
    const sealed = await lockRecovery(kp.privateKey, rk.entropy);
    await expect(openWithRecoveryKey(sealed, other.phrase)).rejects.toThrow();
  });

  it("refuses a phrase that is not a valid recovery key", async () => {
    const kp = await generateKeyPair();
    const rk = await createRecoveryKey();
    const sealed = await lockRecovery(kp.privateKey, rk.entropy);
    await expect(
      openWithRecoveryKey(sealed, ABANDON_24.replace(/art$/, "abandon")),
    ).rejects.toThrow();
  });
});

describe("change vault password (ADR 20)", () => {
  it("locks the same private key again: the new password opens it, the old one does not", async () => {
    const kp = await generateKeyPair();
    const locked = await lockPrivateKey(kp.privateKey, "coffee-rain-bicycle-blue");

    const next = await relockWithNewPassword(
      locked,
      "coffee-rain-bicycle-blue",
      "river-stone-lantern-oak",
    );
    expect(next.privateKey).toBe(kp.privateKey);
    expect(await unlockPrivateKey(next.lockedKey, "river-stone-lantern-oak")).toBe(kp.privateKey);
    await expect(unlockPrivateKey(next.lockedKey, "coffee-rain-bicycle-blue")).rejects.toThrow();
  });

  it("keeps group access: a group key wrapped to the public key still opens after the change", async () => {
    const kp = await generateKeyPair();
    const gk = await newGroupKey();
    const wrapped = await wrapGroupKey(gk, kp.publicKey, "myapp", 1);
    const locked = await lockPrivateKey(kp.privateKey, "coffee-rain-bicycle-blue");

    const next = await relockWithNewPassword(
      locked,
      "coffee-rain-bicycle-blue",
      "river-stone-lantern-oak",
    );
    const opened = await unwrapGroupKey(wrapped, next.privateKey, kp.publicKey, "myapp", 1);
    expect(opened).toEqual(gk);
  });

  it("rejects the wrong current password", async () => {
    const kp = await generateKeyPair();
    const locked = await lockPrivateKey(kp.privateKey, "coffee-rain-bicycle-blue");
    await expect(
      relockWithNewPassword(locked, "coffee-rain-bicycle-bleu", "river-stone-lantern-oak"),
    ).rejects.toThrow();
  });
});

describe("give access again: re-wrap for the new key (ADR 20)", () => {
  it("re-wraps the groups the admin holds, and lists the ones the admin does not", async () => {
    const admin = await generateKeyPair();
    const person = await generateKeyPair();
    const gk = await newGroupKey();
    const adminWrapped = await wrapGroupKey(gk, admin.publicKey, "myapp", 3);

    const out = await regrantKeys(
      {
        groupKey: async (prefix: string) => {
          if (prefix === "myapp") return { wrappedKey: adminWrapped, version: 3 };
          throw new ApiError("not-found", 404);
        },
      },
      { groups: ["myapp", "infra"], publicKey: person.publicKey },
      { privateKey: admin.privateKey, publicKey: admin.publicKey },
    );

    expect(out.notRewrapped).toEqual(["infra"]);
    expect(out.keys).toHaveLength(1);
    const key = out.keys[0];
    expect(key).toMatchObject({ prefix: "myapp", version: 3 });
    // The person opens the group key with their own new private key, and it is the same key.
    expect(
      await unwrapGroupKey(key?.wrappedKey ?? "", person.privateKey, person.publicKey, "myapp", 3),
    ).toEqual(gk);
  });

  it("passes other errors through rather than hiding them as a missing group", async () => {
    const admin = await generateKeyPair();
    await expect(
      regrantKeys(
        {
          groupKey: async () => {
            throw new ApiError("unavailable", 503);
          },
        },
        { groups: ["myapp"], publicKey: admin.publicKey },
        { privateKey: admin.privateKey, publicKey: admin.publicKey },
      ),
    ).rejects.toBeInstanceOf(ApiError);
  });
});
