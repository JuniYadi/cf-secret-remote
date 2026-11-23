import { type Login, loginFingerprints, openLogin, sealLogin, totp } from "@cfs/core";
import { useEffect, useState } from "preact/hooks";
import { useLocation } from "wouter-preact";
import { PageTitle } from "../components/shared.tsx";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import {
  decryptLoginList,
  type LoginRecord,
  loginClient,
  loginKeyFor,
  loginTargets,
} from "../lib/logins.ts";
import { PATHS, pageCrumbs } from "../routes.ts";

const empty: Login = {
  v: 1,
  name: "",
  url: "",
  environment: "",
  role: "",
  username: "",
  password: "",
  totp: "",
  notes: "",
};
/** 64 equally likely symbols, using the operating system's cryptographic RNG. */
export function generatePassword(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  return Array.from(crypto.getRandomValues(new Uint8Array(24)), (n) => chars[n & 63]).join("");
}
export function LoginFormPage({ id }: { id?: string }) {
  useLang();
  const [, navigate] = useLocation();
  const [login, setLogin] = useState<Login>(empty);
  const [record, setRecord] = useState<LoginRecord | null>(null);
  const [targets, setTargets] = useState<Awaited<ReturnType<typeof loginTargets>> | null>(null);
  const [target, setTarget] = useState("");
  const [suggestions, setSuggestions] = useState<Login[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    Promise.all([
      loginTargets(),
      loginClient.list(),
      id ? loginClient.get(id) : Promise.resolve(null),
    ])
      .then(async ([options, rows, r]) => {
        const opened = await decryptLoginList(rows, loginKeyFor);
        let value = empty;
        if (r)
          value = await openLogin(
            await loginKeyFor(r.keyringId, r.keyringVersion),
            id as string,
            r.version,
            r.wrappedDek,
            r.ciphertext,
          );
        if (live) {
          setTargets(options);
          setSuggestions(opened.map((x) => x.login));
          setRecord(r);
          setLogin(value);
          setTarget(r?.keyringId ?? options.find((x) => x.personal)?.id ?? "");
        }
      })
      .catch(() => {
        if (live) setError(t("Could not load the form.", "Formulir tidak bisa dimuat."));
      });
    return () => {
      live = false;
    };
  }, [id]);
  const update = (field: keyof Omit<Login, "v">, value: string) =>
    setLogin((current) => ({ ...current, [field]: value }));
  const save = async (event: Event) => {
    event.preventDefault();
    setError("");
    if (!login.name.trim()) {
      setError(t("Enter a name.", "Masukkan nama."));
      return;
    }
    if (login.totp.trim()) {
      try {
        await totp(login.totp);
      } catch {
        setError(t("Enter a valid TOTP seed or URI.", "Masukkan seed atau URI TOTP yang valid."));
        return;
      }
    }
    const destination = targets?.find((x) => x.id === target);
    if (!destination || (id && !record)) {
      setError(t("Choose an available keyring.", "Pilih gantungan kunci yang tersedia."));
      return;
    }
    setBusy(true);
    try {
      const loginId = id ?? crypto.randomUUID();
      const version = (record?.version ?? 0) + 1;
      const key = await loginKeyFor(destination.id, destination.version);
      const body = {
        keyringId: destination.id,
        keyringVersion: destination.version,
        version,
        ...(await sealLogin(key, loginId, version, login)),
        fps: await loginFingerprints(key, loginId, login),
      };
      if (id) await loginClient.update(id, body);
      else await loginClient.create(loginId, body);
      navigate(`${PATHS.logins}/${encodeURIComponent(loginId)}`);
    } catch {
      setError(
        t(
          "Could not save the login. Check your connection or reload and try again.",
          "Akun tidak bisa disimpan. Periksa koneksi atau muat ulang lalu coba lagi.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };
  const field = (
    name: keyof Omit<Login, "v">,
    en: string,
    ind: string,
    type: "text" | "password" | "url" = "text",
    list?: string,
  ) => (
    <div class="field">
      <label for={`login-${name}`}>{t(en, ind)}</label>
      {type === "password" ? (
        <input
          id={`login-${name}`}
          type="password"
          value={login[name]}
          onInput={(e) => update(name, e.currentTarget.value)}
        />
      ) : (
        <input
          id={`login-${name}`}
          type="text"
          value={login[name]}
          ref={(element) => {
            if (element && list) element.setAttribute("list", list);
          }}
          onInput={(e) => update(name, e.currentTarget.value)}
        />
      )}
    </div>
  );
  const values = (name: "environment" | "role") =>
    [...new Set(suggestions.map((x) => x[name]).filter(Boolean))].sort();
  return (
    <div class="secrets-page">
      <PageTitle crumbs={pageCrumbs(id ? "loginEdit" : "loginNew")} />
      {error && <p role="alert">{error}</p>}
      {targets === null ? (
        !error && <p role="status">{t("Loading...", "Memuat...")}</p>
      ) : (
        <form class="card" onSubmit={save}>
          {field("name", "Name", "Nama")}
          {field("url", "URL", "URL", "url")}
          {field("environment", "Environment", "Lingkungan", "text", "environments")}
          {field("role", "Role", "Peran", "text", "roles")}
          <datalist id="environments">
            {values("environment").map((x) => (
              <option key={x} value={x} />
            ))}
          </datalist>
          <datalist id="roles">
            {values("role").map((x) => (
              <option key={x} value={x} />
            ))}
          </datalist>
          {field("username", "Username", "Nama pengguna")}
          {field("password", "Password", "Kata sandi", "password")}
          <button
            type="button"
            class="btn ghost"
            onClick={() => update("password", generatePassword())}
          >
            {t("Generate password", "Buat kata sandi")}
          </button>
          {field("totp", "TOTP seed or otpauth URI", "Seed TOTP atau URI otpauth", "password")}
          <div class="field">
            <label for="login-notes">{t("Notes", "Catatan")}</label>
            <textarea
              id="login-notes"
              value={login.notes}
              onInput={(e) => update("notes", e.currentTarget.value)}
            />
          </div>
          <div class="field">
            <label for="login-target">{t("Keyring", "Gantungan kunci")}</label>
            <select
              id="login-target"
              value={target}
              disabled={!!id}
              onChange={(e) => setTarget(e.currentTarget.value)}
            >
              <option value="">{t("Choose a keyring", "Pilih gantungan kunci")}</option>
              {targets.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.personal ? t("Personal", "Pribadi") : x.prefix}
                </option>
              ))}
            </select>
          </div>
          <button class="btn" type="submit" disabled={busy}>
            {t("Save", "Simpan")}
          </button>
        </form>
      )}
    </div>
  );
}
