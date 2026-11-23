import { type Login, loginFingerprints, moveLogin, openLogin, sealLogin, totp } from "@cfs/core";
import { useEffect, useState } from "preact/hooks";
import { Link } from "wouter-preact";
import { MASK, useReveal } from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { ApiError } from "../lib/api.ts";
import { copyWithAutoClear } from "../lib/clipboard.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import {
  type LoginRecord,
  type LoginVersion,
  loginClient,
  loginKeyFor,
  loginTargets,
} from "../lib/logins.ts";
import { PATHS, pageCrumbs } from "../routes.ts";

type Field = keyof Omit<Login, "v">;
const labels: Record<Field, [string, string]> = {
  name: ["Name", "Nama"],
  url: ["URL", "URL"],
  environment: ["Environment", "Lingkungan"],
  role: ["Role", "Peran"],
  username: ["Username", "Nama pengguna"],
  password: ["Password", "Kata sandi"],
  totp: ["TOTP seed", "Seed TOTP"],
  notes: ["Notes", "Catatan"],
};
function LoginField({
  id,
  field,
  value,
  onError,
}: {
  id: string;
  field: Field;
  value: string;
  onError: () => void;
}) {
  const reveal = useReveal();
  const label = t(...labels[field]);
  const audit = async () => {
    try {
      await loginClient.reveal(id, { field });
      return true;
    } catch {
      onError();
      return false;
    }
  };
  return (
    <div class="field">
      <strong>{label}</strong>
      <div>{reveal.shown ? value : MASK}</div>
      <button
        type="button"
        class="btn ghost sm"
        aria-label={`${reveal.shown ? t("Hide", "Sembunyikan") : t("Show", "Tampilkan")} ${label}`}
        onClick={async () => {
          if (reveal.shown) reveal.hide();
          else if (await audit()) reveal.show();
        }}
      >
        {reveal.shown ? t("Hide", "Sembunyikan") : t("Show", "Tampilkan")}
      </button>{" "}
      <button
        type="button"
        class="btn ghost sm"
        aria-label={`${t("Copy", "Salin")} ${label}`}
        onClick={async () => {
          if (await audit()) {
            if (!(await copyWithAutoClear(value))) onError();
          }
        }}
      >
        {t("Copy", "Salin")}
      </button>
    </div>
  );
}
function Code({ seed }: { seed: string }) {
  const [now, setNow] = useState(Date.now());
  const [code, setCode] = useState("");
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    let live = true;
    totp(seed, now / 1000)
      .then((v) => {
        if (live) setCode(v);
      })
      .catch(() => {
        if (live) setCode("");
      });
    return () => {
      live = false;
    };
  }, [seed, now]);
  let period = 30;
  try {
    if (seed.toLowerCase().startsWith("otpauth://"))
      period = Number(new URL(seed).searchParams.get("period") ?? 30);
  } catch {
    /* Invalid seed is reported below. */
  }
  if (!Number.isSafeInteger(period) || period < 1) period = 30;
  return (
    <div class="field">
      <strong>{t("Verification code", "Kode verifikasi")}</strong>
      <p>
        {code || t("Invalid TOTP", "TOTP tidak valid")}{" "}
        {code && `(${period - (Math.floor(now / 1000) % period)}s)`}
      </p>
    </div>
  );
}
export function LoginDetailPage({ id }: { id: string }) {
  useLang();
  const [record, setRecord] = useState<LoginRecord | null>(null);
  const [login, setLogin] = useState<Login | null>(null);
  const [versions, setVersions] = useState<LoginVersion[] | null>(null);
  const [targets, setTargets] = useState<Awaited<ReturnType<typeof loginTargets>>>([]);
  const [target, setTarget] = useState("");
  const [tab, setTab] = useState<"values" | "versions">("values");
  const [deleted, setDeleted] = useState(false);
  const [missing, setMissing] = useState(false);
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let live = true;
    setRecord(null);
    setLogin(null);
    setError(false);
    setMissing(false);
    const get = loginClient.get(id).catch((err: unknown) => {
      if (live && err instanceof ApiError && err.kind === "not-found") setMissing(true);
      throw err;
    });
    Promise.all([get, loginTargets()])
      .then(async ([r, options]) => {
        const key = await loginKeyFor(r.keyringId, r.keyringVersion);
        const opened = await openLogin(key, r.id, r.version, r.wrappedDek, r.ciphertext);
        if (live) {
          setRecord(r);
          setLogin(opened);
          setTargets(options);
        }
      })
      .catch(() => {
        if (live) setError(true);
      });
    return () => {
      live = false;
    };
  }, [id, attempt]);
  const action = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(false);
    try {
      await fn();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  };
  const reload = () => {
    setVersions(null);
    setTab("values");
    setAttempt((n) => n + 1);
  };
  const openVersions = () => {
    setTab("versions");
    void action(async () => setVersions(await loginClient.versions(id)));
  };
  const restore = (old: LoginVersion) =>
    void action(async () => {
      if (!record) return;
      const r = await loginClient.version(id, old.version);
      const oldKey = await loginKeyFor(r.keyringId, r.keyringVersion);
      const oldLogin = await openLogin(oldKey, id, r.version, r.wrappedDek, r.ciphertext);
      const destination = targets.find((x) => x.id === record.keyringId);
      if (!destination) throw new Error("missing key");
      const key = await loginKeyFor(destination.id, destination.version);
      const version = record.version + 1;
      await loginClient.restore(id, old.version, {
        keyringId: destination.id,
        keyringVersion: destination.version,
        version,
        ...(await sealLogin(key, id, version, oldLogin)),
        fps: await loginFingerprints(key, id, oldLogin),
      });
      reload();
    });
  const move = () =>
    void action(async () => {
      if (!record || !login) return;
      const destination = targets.find((x) => x.id === target);
      if (!destination) throw new Error("missing key");
      const sourceKey = await loginKeyFor(record.keyringId, record.keyringVersion);
      const destinationKey = await loginKeyFor(destination.id, destination.version);
      const envelope = await moveLogin(
        sourceKey,
        destinationKey,
        id,
        record.version,
        record.wrappedDek,
        record.ciphertext,
      );
      await loginClient.move(id, {
        keyringId: destination.id,
        keyringVersion: destination.version,
        version: record.version + 1,
        ...envelope,
        fps: await loginFingerprints(destinationKey, id, login),
      });
      setTarget("");
      reload();
    });
  return (
    <div class="secrets-page">
      <PageTitle crumbs={pageCrumbs("loginDetail")} />
      {error && (
        <p role="alert">{t("Something went wrong. Try again.", "Terjadi kesalahan. Coba lagi.")}</p>
      )}
      {deleted ? (
        <div>
          <p>{t("Login deleted.", "Akun dihapus.")}</p>
          <button
            type="button"
            class="btn"
            disabled={busy}
            onClick={() =>
              void action(async () => {
                await loginClient.undelete(id);
                setDeleted(false);
                reload();
              })
            }
          >
            {t("Undo delete", "Urungkan penghapusan")}
          </button>
        </div>
      ) : !record || !login ? (
        missing ? (
          <div>
            <p>
              {t(
                "This login is unavailable or deleted.",
                "Akun ini tidak tersedia atau telah dihapus.",
              )}
            </p>
            <button
              type="button"
              class="btn"
              disabled={busy}
              onClick={() =>
                void action(async () => {
                  await loginClient.undelete(id);
                  reload();
                })
              }
            >
              {t("Restore deleted login", "Pulihkan akun yang dihapus")}
            </button>
          </div>
        ) : error ? (
          <button type="button" class="btn" onClick={reload}>
            {t("Try again", "Coba lagi")}
          </button>
        ) : (
          <p role="status">{t("Loading...", "Memuat...")}</p>
        )
      ) : (
        <>
          <h2>{login.name}</h2>
          <Link class="btn ghost" href={`${PATHS.logins}/${encodeURIComponent(id)}/edit`}>
            {t("Edit", "Ubah")}
          </Link>{" "}
          <button
            type="button"
            class="btn ghost"
            disabled={busy}
            onClick={() => {
              if (confirm(t("Delete this login?", "Hapus akun ini?")))
                void action(async () => {
                  await loginClient.delete(id);
                  setDeleted(true);
                  setLogin(null);
                });
            }}
          >
            {t("Delete", "Hapus")}
          </button>
          <nav class="tabs" aria-label={t("Login sections", "Bagian akun")}>
            <button type="button" aria-pressed={tab === "values"} onClick={() => setTab("values")}>
              {t("Values", "Nilai")}
            </button>
            <button type="button" aria-pressed={tab === "versions"} onClick={openVersions}>
              {t("Versions", "Versi")}
            </button>
          </nav>
          {tab === "values" ? (
            <>
              <div class="card">
                {(Object.keys(labels) as Field[]).map((field) => (
                  <LoginField
                    key={field}
                    id={id}
                    field={field}
                    value={login[field]}
                    onError={() => setError(true)}
                  />
                ))}
                {login.totp && <Code seed={login.totp} />}
              </div>
              <div class="field">
                <label for="login-move">{t("Move to group", "Pindah ke grup")}</label>
                <select
                  id="login-move"
                  value={target}
                  onChange={(e) => setTarget(e.currentTarget.value)}
                >
                  <option value="">{t("Choose a keyring", "Pilih gantungan kunci")}</option>
                  {targets
                    .filter((x) => x.id !== record.keyringId)
                    .map((x) => (
                      <option key={x.id} value={x.id}>
                        {x.personal ? t("Personal", "Pribadi") : x.prefix}
                      </option>
                    ))}
                </select>
                <button type="button" class="btn" disabled={!target || busy} onClick={move}>
                  {t("Move", "Pindahkan")}
                </button>
              </div>
            </>
          ) : (
            <div class="card">
              <p>
                {t(
                  "Restoring an old version can bring back exposed values.",
                  "Memulihkan versi lama dapat mengembalikan nilai yang telah bocor.",
                )}
              </p>
              {versions === null ? (
                <p role="status">{t("Loading...", "Memuat...")}</p>
              ) : (
                versions.map((v) => (
                  <div key={v.version}>
                    {t("Version", "Versi")} {v.version}{" "}
                    {v.version !== record.version && (
                      <button
                        type="button"
                        class="btn ghost sm"
                        disabled={busy}
                        onClick={() => restore(v)}
                      >
                        {t("Restore", "Pulihkan")}
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
