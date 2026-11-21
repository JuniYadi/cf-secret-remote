import { useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import {
  failureText,
  formatWhen,
  LoadStatus,
  Notice,
  Pill,
  TechDetails,
  type Tone,
  useLoad,
} from "../components/Admin.tsx";
import { PageTitle } from "../components/shared.tsx";
import { ApiError, type AppDetail, type AppRow, api } from "../lib/api.ts";
import {
  appErrorText,
  appStatus,
  createApp,
  daysLeft,
  holdKit,
  KIT_LIFE,
  KitError,
  NAME_MAX,
  type NewAppForm,
  reissueKit,
  SESSION_LIFE,
  validateNewApp,
} from "../lib/apps.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { appKitPath, appPath, PATHS, pageCrumbs } from "../routes.ts";
import "../styles/admin.css";

const ADMIN_ONLY = t(
  "Only admins can manage apps and bots.",
  "Hanya admin yang bisa mengelola aplikasi dan bot.",
);

function StatusPill({ app }: { app: Pick<AppRow, "status" | "waiting"> }) {
  useLang();
  const s = appStatus(app);
  const tone: Tone = s === "active" ? "ok" : s === "waiting" ? "warn" : "";
  const text =
    s === "active"
      ? t("Active", "Aktif")
      : s === "waiting"
        ? t("Waiting for first sign-in", "Menunggu masuk pertama")
        : t("Disabled", "Dinonaktifkan");
  return <Pill tone={tone}>{text}</Pill>;
}

function kitLeft(expiresAt: number | null): string {
  const days = daysLeft(expiresAt, Math.floor(Date.now() / 1000));
  if (days === null) return t("No expiry", "Tanpa kedaluwarsa");
  if (days === 0) return t("Expires today", "Kedaluwarsa hari ini");
  return t(`${days} more days`, `${days} hari lagi`);
}

/** Apps and bots: each one signs in with its own kit (ADR 15). */
export function AppsPage() {
  useLang();
  const { me } = useSession();
  const isAdmin = me?.role === "admin";
  const apps = useLoad(() => api.apps(), "apps");

  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("apps")} />
      <div class="page-head">
        <p class="sub page-sub">
          {t(
            "Give your CI servers and AI agents their own identity, so everything they do can be traced back to them.",
            "Beri server CI dan agen AI identitas sendiri, supaya semua yang mereka lakukan bisa dilacak.",
          )}
        </p>
        {isAdmin && (
          <div class="actions">
            <Link class="btn" href={PATHS.appNew}>
              {t("+ New app or bot", "+ Aplikasi atau bot baru")}
            </Link>
          </div>
        )}
      </div>

      {!isAdmin && <Notice tone="info">{ADMIN_ONLY}</Notice>}
      {isAdmin && <LoadStatus state={apps} />}

      {isAdmin && apps.data && apps.data.length === 0 && (
        <div class="card empty">
          <h2>{t("No apps or bots yet", "Belum ada aplikasi atau bot")}</h2>
          <p class="note">
            {t(
              "Make one for a CI job or a server. It gets its own kit to sign in with.",
              "Buat satu untuk job CI atau server. Ia mendapat kit sendiri untuk masuk.",
            )}
          </p>
        </div>
      )}

      {isAdmin && apps.data && apps.data.length > 0 && (
        <div class="card tw">
          <table>
            <thead>
              <tr>
                <th scope="col">{t("Name", "Nama")}</th>
                <th scope="col">{t("Status", "Status")}</th>
                <th scope="col">{t("Kit", "Kit")}</th>
                <th scope="col">{t("Last used", "Terakhir dipakai")}</th>
                <th scope="col">
                  <span class="visually-hidden">{t("Open", "Buka")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {apps.data.map((app) => (
                <tr key={app.id}>
                  <td>
                    <Link class="strong-link" href={appPath(app.id)}>
                      {app.name}
                    </Link>
                  </td>
                  <td>
                    <StatusPill app={app} />
                  </td>
                  <td>{kitLeft(app.expiresAt)}</td>
                  <td>
                    {app.lastLoginAt ? formatWhen(app.lastLoginAt) : t("Never", "Belum pernah")}
                  </td>
                  <td class="right">
                    <Link class="btn ghost sm" href={appPath(app.id)}>
                      {t("Open", "Buka")}
                      <span class="visually-hidden"> {app.name}</span>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {isAdmin && (
        <p class="note">
          {t(
            "Each app or bot signs in with its own kit. Open one to see its sessions and activity, or to issue a new kit.",
            "Tiap aplikasi atau bot masuk dengan kitnya sendiri. Buka salah satu untuk melihat sesi dan aktivitasnya, atau menerbitkan kit baru.",
          )}
        </p>
      )}
    </div>
  );
}

/** New app or bot: the browser makes the key pair; only the public key is sent (ADR 15). */
export function AppNewPage() {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const policies = useLoad(() => api.policies(), "app-policies");
  const groups = useLoad(() => api.keyrings(), "app-groups");
  const [form, setForm] = useState<NewAppForm>({
    name: "",
    sessionSeconds: SESSION_LIFE[0]?.seconds ?? 3600,
    kitDays: KIT_LIFE[1]?.days ?? 30,
    maxUses: "",
    network: "",
    policyId: "",
    prefixes: [],
  });
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (me === null) return null;
  if (me.role !== "admin")
    return (
      <div class="page">
        <PageTitle crumbs={pageCrumbs("appNew")} />
        <Notice tone="info">{ADMIN_ONLY}</Notice>
      </div>
    );

  const check = validateNewApp(form);
  const set = <K extends keyof NewAppForm>(key: K, value: NewAppForm[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  async function onSubmit(event: Event) {
    event.preventDefault();
    setTried(true);
    if (!check.valid || busy) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createApp(form);
      holdKit(created);
      navigate(appKitPath(created.id));
    } catch (err) {
      setBusy(false);
      setError(
        err instanceof ApiError && err.kind === "conflict"
          ? t(
              "An app or bot with this name already exists.",
              "Aplikasi atau bot dengan nama ini sudah ada.",
            )
          : failureText(err),
      );
    }
  }

  const nameErr = tried && check.errors.name;
  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("appNew")} />
      <p class="sub page-sub">
        {t(
          "Give a server or an AI agent its own identity, so it can use secrets without borrowing yours.",
          "Beri server atau agen AI identitasnya sendiri, supaya bisa memakai secret tanpa meminjam akunmu.",
        )}
      </p>
      <div class="cols">
        <form class="card form-stack col-main" onSubmit={onSubmit} aria-labelledby="app-new-title">
          <h2 id="app-new-title" class="visually-hidden">
            {t("New app or bot", "Aplikasi atau bot baru")}
          </h2>
          <div class="field">
            <label for="app-name">{t("Name", "Nama")}</label>
            <input
              id="app-name"
              type="text"
              value={form.name}
              maxLength={NAME_MAX}
              onInput={(e) => set("name", e.currentTarget.value)}
              aria-invalid={nameErr ? "true" : undefined}
              aria-describedby="app-name-help"
              autocomplete="off"
            />
            <span id="app-name-help" class="note">
              {t(
                "Shown in Activity next to everything it does.",
                "Ditampilkan di Aktivitas di samping semua yang dilakukannya.",
              )}
            </span>
            {nameErr && (
              <span class="field-error" role="alert">
                {appErrorText(check.errors.name ?? "")}
              </span>
            )}
          </div>

          <div class="form-grid">
            <div class="field">
              <label for="app-permission">{t("Permissions", "Izin")}</label>
              <select
                id="app-permission"
                class="select"
                value={form.policyId}
                onChange={(e) => set("policyId", e.currentTarget.value)}
              >
                <option value="">{t("None yet", "Belum ada")}</option>
                {(policies.data ?? []).map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <span class="note">
                {t("Which secrets it may ask for.", "Secret mana yang boleh diminta.")}
              </span>
            </div>

            <fieldset class="field fieldset">
              <legend>{t("Groups it can open", "Grup yang bisa dibukanya")}</legend>
              <ul class="picker">
                {(groups.data ?? []).map((g) => (
                  <li key={g.prefix}>
                    <label class="pick">
                      <input
                        type="checkbox"
                        checked={form.prefixes.includes(g.prefix)}
                        onChange={() =>
                          set(
                            "prefixes",
                            form.prefixes.includes(g.prefix)
                              ? form.prefixes.filter((p) => p !== g.prefix)
                              : [...form.prefixes, g.prefix],
                          )
                        }
                      />
                      <span class="pick-name">{g.prefix}</span>
                    </label>
                  </li>
                ))}
              </ul>
              <span class="note">
                {t(
                  "It can only open values in these groups.",
                  "Ia hanya bisa membuka nilai di grup ini.",
                )}
              </span>
            </fieldset>
          </div>

          <h2 class="section-title">{t("Limits", "Batas")}</h2>
          <div class="form-grid">
            <div class="field">
              <label for="app-kit-life">{t("Kit expires after", "Kit kedaluwarsa setelah")}</label>
              <select
                id="app-kit-life"
                class="select"
                value={String(form.kitDays)}
                onChange={(e) => set("kitDays", Number(e.currentTarget.value))}
              >
                {KIT_LIFE.map((k) => (
                  <option key={k.days} value={String(k.days)}>
                    {t(k.en, k.id)}
                  </option>
                ))}
              </select>
              <span class="note">
                {t("After this you issue a new kit.", "Setelah itu kamu menerbitkan kit baru.")}
              </span>
            </div>
            <div class="field">
              <label for="app-session">{t("Each session lasts", "Tiap sesi berlangsung")}</label>
              <select
                id="app-session"
                class="select"
                value={String(form.sessionSeconds)}
                onChange={(e) => set("sessionSeconds", Number(e.currentTarget.value))}
              >
                {SESSION_LIFE.map((s) => (
                  <option key={s.seconds} value={String(s.seconds)}>
                    {t(s.en, s.id)}
                  </option>
                ))}
              </select>
            </div>
            <div class="field">
              <label for="app-uses">{t("Maximum uses", "Maksimum pemakaian")}</label>
              <input
                id="app-uses"
                type="text"
                inputMode="numeric"
                value={form.maxUses}
                placeholder={t("No limit", "Tanpa batas")}
                onInput={(e) => set("maxUses", e.currentTarget.value)}
                aria-invalid={tried && check.errors.maxUses ? "true" : undefined}
                autocomplete="off"
              />
              {tried && check.errors.maxUses && (
                <span class="field-error" role="alert">
                  {t(
                    "Use a whole number, 1 or more, or leave it empty.",
                    "Pakai angka bulat, 1 atau lebih, atau kosongkan.",
                  )}
                </span>
              )}
            </div>
            <div class="field">
              <label for="app-network">
                {t("Only from this network", "Hanya dari jaringan ini")}
              </label>
              <input
                id="app-network"
                type="text"
                value={form.network}
                placeholder="34.120.0.0/16"
                aria-describedby="app-network-help"
                aria-invalid={tried && check.errors.network ? "true" : undefined}
                onInput={(e) => set("network", e.currentTarget.value)}
                autocomplete="off"
                class="mono-input"
              />
              <span id="app-network-help" class="note">
                {t(
                  "Leave empty to allow any network.",
                  "Kosongkan untuk mengizinkan jaringan mana pun.",
                )}
              </span>
              {tried && check.errors.network && (
                <span class="field-error" role="alert">
                  {t(
                    "Use an IP address or a range like 34.120.0.0/16.",
                    "Pakai alamat IP atau rentang seperti 34.120.0.0/16.",
                  )}
                </span>
              )}
            </div>
          </div>

          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}
          <div class="form-foot">
            <Link class="btn ghost" href={PATHS.apps}>
              {t("Cancel", "Batal")}
            </Link>
            <button type="submit" class="btn" disabled={busy}>
              {busy
                ? t("Making the key...", "Membuat kunci...")
                : t("Create and get kit", "Buat dan ambil kit")}
            </button>
          </div>
        </form>

        <aside class="card side-note col-side" aria-labelledby="get-title">
          <h2 id="get-title">{t("What you'll get", "Yang akan kamu dapat")}</h2>
          <p>
            {t(
              "A kit: one piece of text that works like a password for the bot. Here's how it goes:",
              "Sebuah kit: satu teks yang bekerja seperti password untuk bot. Begini alurnya:",
            )}
          </p>
          <ol class="plain-steps">
            <li>
              {t(
                "You copy the kit. It's shown only once.",
                "Kamu menyalin kit. Hanya ditampilkan sekali.",
              )}
            </li>
            <li>
              {t(
                "You put it in the bot's environment as CFS_KIT, like a CI secret.",
                "Kamu menaruhnya di environment bot sebagai CFS_KIT, seperti secret CI.",
              )}
            </li>
            <li>
              {t(
                "The bot signs in and opens only what you allowed. Every action shows in Activity.",
                "Bot masuk dan hanya membuka yang kamu izinkan. Setiap aksi muncul di Aktivitas.",
              )}
            </li>
          </ol>
          <Notice tone="info">
            {t(
              "Giving the bot access to a group needs your vault unlocked. This happens in your browser, so the server never sees the values.",
              "Memberi bot akses ke grup butuh vault-mu terbuka. Ini terjadi di browsermu, jadi server tidak pernah melihat nilainya.",
            )}
          </Notice>
        </aside>
      </div>
    </div>
  );
}

/** App detail: overview, sessions, recent activity, and the actions (ADR 15). */
export function AppDetailPage({ id }: { id: string }) {
  useLang();
  const { me } = useSession();
  const isAdmin = me?.role === "admin";
  const app = useLoad(() => api.app(id), `app:${id}`);
  const [confirm, setConfirm] = useState<null | "disable">(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reissue, setReissue] = useState(false);
  const [pasted, setPasted] = useState("");
  const [, navigate] = useLocation();
  const [rotated, setRotated] = useState<{ roleId: string; secretId: string } | null>(null);

  const data: AppDetail | null = app.data;
  const crumbs = pageCrumbs("appDetail", data?.name ?? "");

  async function disable() {
    if (!data) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.disableApp(data.id);
      setConfirm(null);
      app.reload();
    } catch (err) {
      setActionError(failureText(err));
    } finally {
      setBusy(false);
    }
  }

  async function makeKit(event: Event) {
    event.preventDefault();
    if (!data || busy) return;
    setBusy(true);
    setActionError(null);
    try {
      const created = await reissueKit(pasted, {
        id: data.id,
        name: data.name,
        roleId: data.roleId,
      });
      setPasted("");
      holdKit(created);
      navigate(appKitPath(data.id));
    } catch (err) {
      setBusy(false);
      setActionError(
        err instanceof KitError
          ? err.code === "otherApp"
            ? t("That kit is for a different app or bot.", "Kit itu untuk aplikasi atau bot lain.")
            : t(
                "That doesn't look like a cfs kit. Paste the whole kit, starting with cfskit1_.",
                "Itu bukan kit cfs. Tempel seluruh kit, mulai dari cfskit1_.",
              )
          : failureText(err),
      );
    }
  }

  async function rotate() {
    if (!data) return;
    setBusy(true);
    setActionError(null);
    try {
      setRotated(await api.rotateApp(data.id));
    } catch (err) {
      setActionError(failureText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="page">
      <PageTitle crumbs={crumbs} />
      <LoadStatus state={app} />
      {data && (
        <>
          <div class="page-head">
            <div class="pill-row">
              <Pill tone="acc">{t("App or bot", "Aplikasi atau bot")}</Pill>
              <StatusPill app={data} />
              {data.expiresAt !== null && <Pill>{kitLeft(data.expiresAt)}</Pill>}
            </div>
            {isAdmin && data.status === "active" && (
              <div class="actions">
                <button
                  type="button"
                  class="btn ghost"
                  disabled={busy}
                  onClick={() => setReissue((v) => !v)}
                >
                  {t("Issue new kit", "Terbitkan kit baru")}
                </button>
                <button type="button" class="btn ghost" disabled={busy} onClick={rotate}>
                  {t("Rotate secret ID", "Ganti secret ID")}
                </button>
                <button
                  type="button"
                  class="btn danger"
                  disabled={busy}
                  onClick={() => setConfirm("disable")}
                >
                  {t("Disable", "Nonaktifkan")}
                </button>
              </div>
            )}
          </div>

          {data.waiting && (
            <Notice tone="info" title={t("Waiting for first sign-in.", "Menunggu masuk pertama.")}>
              {t(
                "This turns green when the bot signs in for the first time.",
                "Ini berubah hijau saat bot masuk untuk pertama kali.",
              )}
            </Notice>
          )}
          {actionError && (
            <p class="field-error" role="alert">
              {actionError}
            </p>
          )}

          {confirm === "disable" && (
            <Notice tone="danger" title={t(`Disable ${data.name}?`, `Nonaktifkan ${data.name}?`)}>
              {t(
                "It can't sign in again and its sessions end now. Re-enabling is not possible from here.",
                "Ia tidak bisa masuk lagi dan sesinya berakhir sekarang. Mengaktifkan lagi tidak bisa dari sini.",
              )}{" "}
              <span class="inline-actions">
                <button type="button" class="btn danger sm" disabled={busy} onClick={disable}>
                  {t("Disable now", "Nonaktifkan sekarang")}
                </button>
                <button type="button" class="btn ghost sm" onClick={() => setConfirm(null)}>
                  {t("Cancel", "Batal")}
                </button>
              </span>
            </Notice>
          )}

          {reissue && (
            <form class="card form-stack" onSubmit={makeKit} aria-labelledby="reissue-title">
              <h2 id="reissue-title">{t("Issue a new kit", "Terbitkan kit baru")}</h2>
              <p class="note">
                {t(
                  "Paste the kit you saved. The browser reads the private key from it and builds a new kit with a new secret ID. The private key stays here.",
                  "Tempel kit yang kamu simpan. Browser membaca private key darinya dan membuat kit baru dengan secret ID baru. Private key tetap di sini.",
                )}
              </p>
              <div class="field">
                <label for="reissue-kit">{t("Your current kit", "Kit kamu sekarang")}</label>
                <textarea
                  id="reissue-kit"
                  class="kit-input"
                  rows={3}
                  value={pasted}
                  onInput={(e) => setPasted(e.currentTarget.value)}
                  autocomplete="off"
                  spellcheck={false}
                />
              </div>
              <div class="form-foot">
                <button type="button" class="btn ghost" onClick={() => setReissue(false)}>
                  {t("Cancel", "Batal")}
                </button>
                <button type="submit" class="btn" disabled={busy || pasted.trim() === ""}>
                  {t("Make new kit", "Buat kit baru")}
                </button>
              </div>
            </form>
          )}

          {rotated && (
            <Notice tone="warn" title={t("Shown once.", "Sekali tampil.")}>
              {t(
                "The secret ID changed. Your old kit no longer signs in. Use Issue new kit with your saved kit.",
                "Secret ID sudah berganti. Kit lama tidak bisa masuk lagi. Pakai Terbitkan kit baru dengan kit yang kamu simpan.",
              )}
              <TechDetails>
                role_id: {rotated.roleId}
                {"\n"}
                secret_id: {rotated.secretId}
              </TechDetails>
            </Notice>
          )}

          <div class="cols">
            <section class="card col-side" aria-labelledby="overview-title">
              <h2 id="overview-title">{t("Overview", "Ringkasan")}</h2>
              <dl class="kv">
                <dt>{t("Created", "Dibuat")}</dt>
                <dd>
                  {formatWhen(data.createdAt)}
                  {data.owner ? ` · ${data.owner}` : ""}
                </dd>
                <dt>{t("Kit expires", "Kit kedaluwarsa")}</dt>
                <dd>{kitLeft(data.expiresAt)}</dd>
                <dt>{t("Only from", "Hanya dari")}</dt>
                <dd>
                  {data.cidr && data.cidr.length > 0
                    ? data.cidr.join(", ")
                    : t("Any network", "Jaringan mana pun")}
                </dd>
                <dt>{t("Each session lasts", "Tiap sesi berlangsung")}</dt>
                <dd>
                  {Math.round(data.tokenTtl / 60)} {t("min", "mnt")}
                </dd>
                <dt>{t("Maximum uses", "Maksimum pemakaian")}</dt>
                <dd>
                  {data.maxUses === null
                    ? t("No limit", "Tanpa batas")
                    : `${data.uses} / ${data.maxUses}`}
                </dd>
                <dt>{t("Last used", "Terakhir dipakai")}</dt>
                <dd>
                  {data.lastLoginAt ? formatWhen(data.lastLoginAt) : t("Never", "Belum pernah")}
                  {data.lastIp ? ` · ${data.lastIp}` : ""}
                </dd>
              </dl>
              <TechDetails>
                role_id: {data.roleId}
                {"\n"}
                {t("Name", "Nama")}: {data.name}
              </TechDetails>
            </section>

            <section class="card tw col-main" aria-labelledby="sessions-title">
              <h2 id="sessions-title" class="table-title">
                {t("Active sessions", "Sesi aktif")} <Pill>{String(data.sessions.length)}</Pill>
              </h2>
              {data.sessions.length === 0 ? (
                <p class="note table-empty">{t("No active sessions.", "Tidak ada sesi aktif.")}</p>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th scope="col">{t("Started", "Mulai")}</th>
                      <th scope="col">{t("Ends", "Berakhir")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.sessions.map((s) => (
                      <tr key={s.id}>
                        <td>{formatWhen(s.createdAt)}</td>
                        <td>{formatWhen(s.expiresAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          </div>

          <section class="card tw" aria-labelledby="activity-title">
            <div class="row-between table-head">
              <h2 id="activity-title" class="table-title">
                {t("Recent activity", "Aktivitas terbaru")}
              </h2>
              <Link href={PATHS.activity}>{t("See all", "Lihat semua")}</Link>
            </div>
            {data.activity.length === 0 ? (
              <p class="note table-empty">{t("Nothing yet.", "Belum ada.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t("Time", "Waktu")}</th>
                    <th scope="col">{t("What", "Apa")}</th>
                    <th scope="col">{t("Reason", "Alasan")}</th>
                    <th scope="col">{t("Result", "Hasil")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.activity.map((a) => (
                    <tr key={`${a.at}-${a.action}-${a.note ?? ""}`}>
                      <td>{formatWhen(a.at)}</td>
                      <td>{activityLabel(a.action)}</td>
                      <td>{a.note ?? "—"}</td>
                      <td>
                        {a.result === "ok" ? (
                          <Pill tone="ok">{t("Allowed", "Diizinkan")}</Pill>
                        ) : (
                          <Pill tone="bad">{t("Blocked", "Diblokir")}</Pill>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}
    </div>
  );
}

/** Plain words for audit actions the app detail shows. Anything else is shown as it is. */
export function activityLabel(action: string): string {
  switch (action) {
    case "secret.read":
      return t("Opened a value", "Membuka nilai");
    case "auth.login":
    case "approle.login":
      return t("Signed in", "Masuk");
    case "auth.denied":
      return t("Sign-in refused", "Masuk ditolak");
    default:
      return action;
  }
}
