import { useEffect, useState } from "preact/hooks";
import { Link } from "wouter-preact";
import { ErrorNote, SettingsTabs } from "../components/parts.tsx";
import { Icon, PageTitle } from "../components/shared.tsx";
import { formatTime } from "../lib/activity.ts";
import { api, type BackupHistory } from "../lib/api.ts";
import { backupFileName, formatBytes, passphraseProblem } from "../lib/backup.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

/**
 * Settings, Backup tab (design board Settings-Backup). A manual download, optionally sealed with a passphrase.
 * The passphrase goes in the X-Backup-Passphrase header (api.downloadBackup), never in the URL (ADR 23).
 */
export function SettingsBackupPage() {
  useLang();
  const { me } = useSession();
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [tooShort, setTooShort] = useState(false);
  const [history, setHistory] = useState<BackupHistory | null>(null);
  const isAdmin = me?.role === "admin";

  function loadHistory() {
    // The list is a convenience: if it can't load, the download below still works.
    api
      .backupHistory()
      .then(setHistory)
      .catch(() => setHistory(null));
  }
  useEffect(() => {
    if (isAdmin) loadHistory();
  }, [isAdmin]);

  if (me?.role !== "admin") {
    return (
      <div class="page-plain settings-page">
        <PageTitle crumbs={pageCrumbs("settingsBackup")} />
        <p class="sub">{t("Only admins can see this.", "Hanya admin yang bisa melihat ini.")}</p>
      </div>
    );
  }

  async function onDownload(event: Event) {
    event.preventDefault();
    if (busy) return;
    if (passphraseProblem(passphrase) !== null) {
      setTooShort(true);
      return;
    }
    setTooShort(false);
    setBusy(true);
    setError(null);
    try {
      const blob = await api.downloadBackup(passphrase === "" ? undefined : passphrase);
      saveBlob(blob, backupFileName(new Date()));
      setPassphrase("");
      loadHistory();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="page-plain settings-page">
      <div>
        <PageTitle crumbs={pageCrumbs("settingsBackup")} />
        <p class="sub">
          {t(
            "A copy of your vault you can keep somewhere else, in case something goes wrong with your Cloudflare account. You can always download one by hand. Automatic daily backups need Cloudflare R2, which is optional.",
            "Salinan vault yang bisa kamu simpan di tempat lain, kalau ada masalah dengan akun Cloudflare-mu. Kamu selalu bisa mengunduhnya sendiri. Cadangan harian otomatis butuh Cloudflare R2, yang opsional.",
          )}
        </p>
      </div>
      <SettingsTabs current="backup" />

      <BackupList history={history} />

      <section class="card settings-card" aria-labelledby="schedule-title">
        <h2 id="schedule-title" class="card-title">
          {t("Schedule and storage", "Jadwal dan penyimpanan")}
        </h2>
        <dl class="kv">
          <div class="kv-row">
            <dt>{t("Schedule", "Jadwal")}</dt>
            <dd>
              {t(
                "Every day around 00:05 UTC, if Cloudflare R2 is connected. Otherwise, download one by hand.",
                "Setiap hari sekitar pukul 00:05 UTC, jika Cloudflare R2 terhubung. Jika tidak, unduh sendiri.",
              )}
            </dd>
          </div>
          <div class="kv-row">
            <dt>{t("Stored in", "Disimpan di")}</dt>
            <dd>
              {t("Your R2 storage, or download it yourself", "R2 milikmu, atau unduh sendiri")}
            </dd>
          </div>
        </dl>
      </section>

      <section class="card settings-card" aria-labelledby="download-title">
        <h2 id="download-title" class="card-title">
          {t("Download a backup now", "Unduh cadangan sekarang")}
        </h2>
        <form class="form-stack" onSubmit={onDownload}>
          <div class="field">
            <label for="backup-passphrase">
              {t("Passphrase (optional)", "Passphrase (opsional)")}
            </label>
            <input
              id="backup-passphrase"
              type="password"
              autocomplete="new-password"
              value={passphrase}
              onInput={(e) => setPassphrase(e.currentTarget.value)}
              aria-describedby="backup-passphrase-help"
              aria-invalid={tooShort ? "true" : undefined}
            />
            <span id="backup-passphrase-help" class="note">
              {t(
                "At least 8 characters. Leave it empty for a plain file. Keep the passphrase: without it a sealed file cannot be opened.",
                "Minimal 8 karakter. Kosongkan untuk file biasa. Simpan passphrase-nya: tanpa itu file tersegel tidak bisa dibuka.",
              )}
            </span>
            {tooShort ? (
              <span class="field-error" role="alert">
                {t(
                  "The passphrase needs at least 8 characters.",
                  "Passphrase perlu minimal 8 karakter.",
                )}
              </span>
            ) : null}
          </div>
          <ErrorNote error={error} />
          <button type="submit" class="btn pri" disabled={busy}>
            {busy
              ? t("Preparing...", "Menyiapkan...")
              : t("Download a backup now", "Unduh cadangan sekarang")}
          </button>
        </form>

        <div class="info-box">
          <h3 class="sub-title">
            {t("What is and isn't encrypted", "Apa yang terenkripsi dan tidak")}
          </h3>
          <ul class="plain-list">
            <li>
              {t(
                "Secret values stay locked with your group keys. Nobody can read them from the file, not even us.",
                "Isi secret tetap terkunci dengan kunci grupmu. Tidak ada yang bisa membacanya dari file ini, termasuk kami.",
              )}
            </li>
            <li>
              {t(
                "Names, paths, emails and dates are in clear, so you can see what the file holds.",
                "Nama, path, email, dan tanggal tampak jelas, supaya kamu bisa melihat isi file.",
              )}
            </li>
            <li>
              {t(
                "With a passphrase, the whole file is sealed (AES-256-GCM, key from PBKDF2). Then nothing in it is readable without the passphrase.",
                "Dengan passphrase, seluruh file tersegel (AES-256-GCM, kunci dari PBKDF2). Lalu tidak ada yang bisa dibaca tanpa passphrase.",
              )}
            </li>
          </ul>
        </div>
      </section>

      <section class="card side-card" aria-labelledby="safe-title">
        <h2 id="safe-title" class="card-title">
          {t("Is it safe to keep?", "Aman disimpan?")}
        </h2>
        <p class="sub">
          {t(
            "Yes. A backup only holds locked data. Without people's vault passwords, nobody can open what's inside it, not even us.",
            "Ya. Cadangan hanya berisi data terkunci. Tanpa vault password orang-orangnya, tidak ada yang bisa membuka isinya, termasuk kami.",
          )}
        </p>
        <p class="sub">
          {t(
            "That also means it doesn't replace your recovery keys. Keep those safe too.",
            "Itu juga berarti cadangan tidak menggantikan kunci pemulihan. Simpan juga itu dengan aman.",
          )}
        </p>
        <div class="row-actions">
          <Icon name="lock" size={16} />
          <Link href={PATHS.restore}>{t("Restore from a backup", "Pulihkan dari cadangan")}</Link>
        </div>
      </section>
    </div>
  );
}

/** Saves a blob through a temporary object URL. The URL is revoked straight after the click. */
export function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** The newest backup, then the list. Manual downloads show no size, because the log records only when they happened. */
function BackupList({ history }: { history: BackupHistory | null }) {
  const lang = useLang();
  if (history === null) return null;
  const latest = history.copies[0];
  return (
    <section class="card settings-card" aria-labelledby="latest-title">
      <h2 id="latest-title" class="card-title">
        {t("Latest backup", "Cadangan terbaru")}
      </h2>
      {latest === undefined ? (
        <p class="note">
          {t(
            "No backup has been made yet. Download one below.",
            "Belum ada cadangan. Unduh satu di bawah.",
          )}
        </p>
      ) : (
        <p class="sub">
          {t("Made ", "Dibuat ")}
          <time dateTime={new Date(latest.at * 1000).toISOString()}>
            {formatTime(latest.at, lang)}
          </time>
          {" · "}
          {latest.type === "auto" ? t("Automatic", "Otomatis") : t("Manual", "Manual")}
        </p>
      )}
      {!history.r2 && (
        <p class="note">
          {t(
            "Automatic daily backups are off. They need a Cloudflare R2 bucket named BACKUP.",
            "Cadangan harian otomatis mati. Butuh bucket Cloudflare R2 bernama BACKUP.",
          )}
        </p>
      )}
      {history.copies.length > 0 && (
        <div class="tw">
          <table class="log-table">
            <caption class="visually-hidden">{t("Backups", "Cadangan")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("Made", "Dibuat")}</th>
                <th scope="col">{t("Size", "Ukuran")}</th>
                <th scope="col">{t("Type", "Tipe")}</th>
              </tr>
            </thead>
            <tbody>
              {history.copies.map((c) => (
                <tr key={`${c.type}-${c.at}`}>
                  <td>
                    <time dateTime={new Date(c.at * 1000).toISOString()}>
                      {formatTime(c.at, lang)}
                    </time>
                  </td>
                  <td>{c.size === null ? "-" : formatBytes(c.size)}</td>
                  <td>{c.type === "auto" ? t("Automatic", "Otomatis") : t("Manual", "Manual")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
