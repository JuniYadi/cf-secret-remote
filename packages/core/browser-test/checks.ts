import {
  chainHash,
  decodeKit,
  encodeKit,
  fingerprints,
  fingerprintWords,
  GENESIS,
  type Login,
  loginFingerprints,
  openBackup,
  openLogin,
  openSecret,
  openText,
  recoveryEntropy,
  recoveryPhrase,
  totp,
  unwrapDek,
  unwrapGroupKey,
  verifyChain,
} from "../src/index.ts";

// ADR 26: the same checks run in Bun (src/vectors.test.ts) and in Chromium (vectors.pw.ts, through
// the bundle from build.ts). Plain TypeScript on WebCrypto only: no Node or Bun APIs in here.

export interface Vectors {
  envelope: {
    cases: { keyHex: string; aad: string; plaintext: string; envelope: string; wrongAad: string }[];
  };
  wrappedKey: {
    recipient: { privateKey: string; publicKey: string };
    cases: { aad: string; dekHex: string; wrapped: string; wrongAad: string }[];
  };
  kit: {
    cases: {
      kit: { host: string; roleId: string; secretId: string; privateKey: string };
      encoded: string;
    }[];
    rejects: string[];
  };
  fingerprint: {
    groupKeyHex: string;
    cases: { path: string; values: Record<string, string>; fps: Record<string, string> }[];
  };
  recovery: {
    mnemonic: { entropyHex: string; words: string }[];
    fingerprint: { publicKey: string; words: string }[];
  };
  auditChain: {
    genesis: string;
    rows: { entry: unknown; hash: string }[];
    tampered: { index: number; entry: unknown; firstBad: number };
  };
  secret: {
    member: { privateKey: string; publicKey: string };
    prefix: string;
    keyringVersion: number;
    groupKeyHex: string;
    groupKeyWrapped: string;
    path: string;
    version: number;
    valuesJson: string;
    wrappedDek: string;
    ciphertext: string;
  };
  login: {
    groupKeyHex: string;
    id: string;
    version: number;
    login: Login;
    wrappedDek: string;
    ciphertext: string;
    fps: Record<string, string>;
    totp: { uri: string; time: number; code: string }[];
  };
  backupSeal: { passphrase: string; sealed: string; plaintext: string };
}

export interface CheckResult {
  group: string;
  name: string;
  ok: boolean;
  error?: string;
}

const hexBytes = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const same = (got: unknown, want: unknown, what: string): void => {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) throw new Error(`${what}: got ${g}, want ${w}`);
};

async function rejects(p: Promise<unknown>, what: string): Promise<void> {
  try {
    await p;
  } catch {
    return;
  }
  throw new Error(`${what}: expected a rejection`);
}

/** Runs every shared vector group. Returns one result per check; the caller decides what fails. */
export async function runVectorChecks(v: Vectors): Promise<CheckResult[]> {
  const out: CheckResult[] = [];
  const check = async (group: string, name: string, fn: () => Promise<void> | void) => {
    try {
      await fn();
      out.push({ group, name, ok: true });
    } catch (e) {
      out.push({ group, name, ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  };

  for (const [i, c] of v.envelope.cases.entries()) {
    await check("envelope", `open #${i}`, async () => {
      same(await openText(hexBytes(c.keyHex), c.envelope, c.aad), c.plaintext, "plaintext");
      await rejects(openText(hexBytes(c.keyHex), c.envelope, c.wrongAad), "wrong aad");
    });
  }

  for (const [i, c] of v.wrappedKey.cases.entries()) {
    await check("wrapped-key", `open #${i}`, async () => {
      const dek = await unwrapDek(
        c.wrapped,
        v.wrappedKey.recipient.privateKey,
        v.wrappedKey.recipient.publicKey,
        c.aad,
      );
      same(toHex(dek), c.dekHex, "dek");
      await rejects(
        unwrapDek(
          c.wrapped,
          v.wrappedKey.recipient.privateKey,
          v.wrappedKey.recipient.publicKey,
          c.wrongAad,
        ),
        "wrong aad",
      );
    });
  }

  for (const [i, c] of v.kit.cases.entries()) {
    await check("kit", `decode and encode #${i}`, () => {
      same(decodeKit(c.encoded), c.kit, "decoded kit");
      same(encodeKit(c.kit), c.encoded, "encoded kit");
    });
  }
  for (const [i, bad] of v.kit.rejects.entries()) {
    await check("kit", `rejects #${i}`, () => {
      let threw = false;
      try {
        decodeKit(bad);
      } catch {
        threw = true;
      }
      if (!threw) throw new Error("accepted a bad kit");
    });
  }

  for (const [i, c] of v.fingerprint.cases.entries()) {
    await check("fingerprint", `per-name #${i}`, async () => {
      same(await fingerprints(hexBytes(v.fingerprint.groupKeyHex), c.path, c.values), c.fps, "fps");
    });
  }

  for (const [i, c] of v.recovery.mnemonic.entries()) {
    await check("recovery-words", `phrase #${i}`, async () => {
      same(await recoveryPhrase(hexBytes(c.entropyHex)), c.words, "words");
      same(toHex(await recoveryEntropy(c.words)), c.entropyHex, "entropy");
    });
  }
  for (const [i, c] of v.recovery.fingerprint.entries()) {
    await check("recovery-words", `fingerprint words #${i}`, async () => {
      same(await fingerprintWords(c.publicKey), c.words, "fingerprint words");
    });
  }

  await check("audit-chain", "intact chain", async () => {
    for (const [i, r] of v.auditChain.rows.entries()) {
      const prev =
        i === 0 ? v.auditChain.genesis : (v.auditChain.rows[i - 1] as { hash: string }).hash;
      same(await chainHash(prev, r.entry), r.hash, `hash of row ${i}`);
    }
    same(await verifyChain(v.auditChain.rows, v.auditChain.genesis), -1, "verify");
  });
  await check("audit-chain", "tampered row is found", async () => {
    const rows = v.auditChain.rows.map((r) => ({ ...r }));
    rows[v.auditChain.tampered.index] = {
      ...(rows[v.auditChain.tampered.index] as { hash: string }),
      entry: v.auditChain.tampered.entry,
    };
    same(await verifyChain(rows, GENESIS), v.auditChain.tampered.firstBad, "first bad row");
  });

  await check("secret-hierarchy", "member opens group key", async () => {
    const s = v.secret;
    const key = await unwrapGroupKey(
      s.groupKeyWrapped,
      s.member.privateKey,
      s.member.publicKey,
      s.prefix,
      s.keyringVersion,
    );
    same(toHex(key), s.groupKeyHex, "group key");
  });
  await check("secret-hierarchy", "group key opens values", async () => {
    const s = v.secret;
    const key = hexBytes(s.groupKeyHex);
    same(
      await openSecret(key, s.path, s.version, s.wrappedDek, s.ciphertext),
      JSON.parse(s.valuesJson),
      "values",
    );
    await rejects(
      openSecret(key, s.path, s.version + 1, s.wrappedDek, s.ciphertext),
      "wrong version",
    );
  });

  await check("login", "open and fingerprints", async () => {
    const l = v.login;
    const key = hexBytes(l.groupKeyHex);
    same(await openLogin(key, l.id, l.version, l.wrappedDek, l.ciphertext), l.login, "login");
    same(await loginFingerprints(key, l.id, l.login), l.fps, "fps");
    await rejects(openLogin(key, l.id, l.version + 1, l.wrappedDek, l.ciphertext), "wrong version");
  });
  for (const [i, c] of v.login.totp.entries()) {
    await check("login", `TOTP #${i}`, async () => same(await totp(c.uri, c.time), c.code, "TOTP"));
  }

  await check("backup-seal", "opens sealed backup", async () => {
    const plain = await openBackup(hexBytes(v.backupSeal.sealed), v.backupSeal.passphrase);
    same(new TextDecoder().decode(plain), v.backupSeal.plaintext, "plaintext");
  });

  return out;
}
