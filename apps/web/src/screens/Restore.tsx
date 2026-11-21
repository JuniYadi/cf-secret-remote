import { useState } from "preact/hooks";
import { ErrorNote, KeyRow, SettingsTabs } from "../components/parts.tsx";
import { Icon, PageTitle } from "../components/shared.tsx";
import { ApiError, api, type RestoreCheck } from "../lib/api.ts";
import { canReplace, hostMatches, needsPassphrase } from "../lib/backup.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { checkPassed, restoreView } from "../lib/restore-view.ts";
import { signOut } from "../lib/session.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

/**
 * Restore (design board Restore). Choose a file, check it (changes nothing), then type this server's host
 * name and acknowledge the loss to replace the vault (ADR 23). The server re-checks everything on restore.
 */
export function RestorePage() {
  useLang();
  const { me } = useSession();
  const [file, setFile] = useState<Uint8Array | null>(null);
  const [fileName, setFileName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [check, setCheck] = useState<RestoreCheck | null>(null);
  const [typedHost, setTypedHost] = useState("");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState<{ restoredAt: number } | null>(null);

  if (me?.role !== "admin") {
    return (
      <div class="page-plain settings-page">
        <PageTitle crumbs={pageCrumbs("restore")} />
        <p class="sub">{t("Only admins can see this.", "Hanya admin yang bisa melihat ini.")}</p>
      </div>
    );
  }

  const sealed = file !== null && needsPassphrase(file);
  const view = check ? restoreView(check) : null;
  const passed = check !== null && checkPassed(check);
  const replaceReady = check !== null && canReplace(typedHost, check, ack);

  async function onChoose(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const picked = input.files?.[0];
    setCheck(null);
    setError(null);
    setDone(null);
    if (!picked) {
      setFile(null);
      setFileName("");
      return;
    }
    setFile(new Uint8Array(await picked.arrayBuffer()));
    setFileName(picked.name);
  }

  async function onCheck() {
    if (!file || busy) return;
    setBusy(true);
    setError(null);
    try {
      setCheck(await api.restoreCheck(file, sealed ? passphrase : undefined));
    } catch (err) {
      setCheck(null);
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function onReplace(event: Event) {
    event.preventDefault();
    if (!file || !check || !replaceReady || busy) return;
    setBusy(true);
    setError(null);
    try {
      const out = await api.restoreApply(file, check.host, sealed ? passphrase : undefined);
      setDone({ restoredAt: out.restoredAt });
      setFile(null);
      setPassphrase("");
      setCheck(null);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  const step = done ? 3 : passed ? 3 : check ? 2 : 1;

  if (done) {
    return (
      <div class="page-plain settings-page">
        <PageTitle crumbs={pageCrumbs("restore")} />
        <div class="card settings-card" role="status">
          <p class="sub">
            {t(
              "Your vault was replaced with the backup. Everyone signs in again.",
              "Vault-mu sudah diganti dengan cadangan. Semua orang harus masuk lagi.",
            )}
          </p>
          <div class="row-actions">
            <button type="button" class="btn pri" onClick={() => signOut()}>
              {t("Sign out", "Keluar")}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div class="page-plain settings-page">
      <div>
        <PageTitle crumbs={pageCrumbs("restore")} />
        <p class="sub">
          {t(
            "Replace what's in your vault now with the contents of a backup. We check the file first and show you what will change.",
            "Ganti isi vault-mu sekarang dengan isi cadangan. Kami memeriksa file dulu dan menunjukkan apa yang akan berubah.",
          )}
        </p>
      </div>
      <SettingsTabs current="backup" />

      <ol class="restore-steps" aria-label={t("Restore steps", "Langkah pemulihan")}>
        <li
          class={step >= 1 ? (step === 1 ? "st now" : "st done") : "st"}
          aria-current={step === 1 ? "step" : undefined}
        >
          <i aria-hidden="true">1</i> {t("Choose file", "Pilih file")}
        </li>
        <li
          class={step >= 2 ? (step === 2 ? "st now" : "st done") : "st"}
          aria-current={step === 2 ? "step" : undefined}
        >
          <i aria-hidden="true">2</i> {t("Check", "Periksa")}
        </li>
        <li class={step === 3 ? "st now" : "st"} aria-current={step === 3 ? "step" : undefined}>
          <i aria-hidden="true">3</i> {t("Replace", "Ganti")}
        </li>
      </ol>

      <section class="card settings-card" aria-labelledby="choose-title">
        <h2 id="choose-title" class="card-title">
          {t("Choose file", "Pilih file")}
        </h2>
        <div class="field">
          <label for="restore-file">
            {t("Backup file (.cfsbackup)", "File cadangan (.cfsbackup)")}
          </label>
          <input
            id="restore-file"
            type="file"
            accept=".cfsbackup,.gz,application/octet-stream"
            onChange={onChoose}
          />
          {fileName ? <span class="note">{fileName}</span> : null}
        </div>
        {sealed ? (
          <div class="field">
            <label for="restore-passphrase">
              {t("Passphrase for this file", "Passphrase untuk file ini")}
            </label>
            <input
              id="restore-passphrase"
              type="password"
              autocomplete="off"
              value={passphrase}
              onInput={(e) => setPassphrase(e.currentTarget.value)}
            />
          </div>
        ) : null}
        <ErrorNote error={error} />
        <div class="row-actions">
          <button
            type="button"
            class="btn pri"
            disabled={!file || busy || (sealed && passphrase === "")}
            onClick={onCheck}
          >
            {busy ? t("Checking...", "Memeriksa...") : t("Check file", "Periksa file")}
          </button>
        </div>
      </section>

      {check && view ? (
        <section class="card settings-card" aria-labelledby="found-title">
          <div class="card-head">
            <h2 id="found-title" class="card-title">
              {t("What's in this backup", "Isi cadangan ini")}
            </h2>
            <span class={passed ? "pill ok" : "pill warn"}>
              {passed ? t("File is valid", "File valid") : t("Not valid", "Tidak valid")}
            </span>
          </div>
          <dl class="kv">
            <KeyRow label={t("Made", "Dibuat")}>
              <span class="mono">{view.madeAt}</span>
              <span class="note">
                {" "}
                {t(
                  `${view.gap.days} d ${view.gap.hours} h ${view.gap.minutes} min ago`,
                  `${view.gap.days} hr ${view.gap.hours} j ${view.gap.minutes} mnt lalu`,
                )}
              </span>
            </KeyRow>
            <KeyRow label={t("Secrets", "Secret")}>{view.secrets.toLocaleString("en-US")}</KeyRow>
            <KeyRow label={t("People", "Orang")}>{view.people.toLocaleString("en-US")}</KeyRow>
            <KeyRow label={t("Log entries", "Entri log")}>
              {view.logEntries.toLocaleString("en-US")}
            </KeyRow>
            <KeyRow label={t("Log chain", "Rantai log")}>
              {view.chainOk && view.checkpointsOk
                ? t("Verified", "Terverifikasi")
                : t("Broken", "Rusak")}
            </KeyRow>
          </dl>
        </section>
      ) : null}

      {passed && view ? (
        <section class="card settings-card" aria-labelledby="lose-title">
          <h2 id="lose-title" class="card-title">
            {t("What replacing changes", "Yang berubah saat diganti")}
          </h2>
          <ul class="plain-list">
            <li>
              {t(
                `Your vault now holds ${view.currentSecrets} secrets and ${view.currentLogEntries} log entries. After the restore it holds what the backup holds.`,
                `Vault-mu sekarang berisi ${view.currentSecrets} secret dan ${view.currentLogEntries} entri log. Setelah pemulihan, isinya seperti cadangan.`,
              )}
            </li>
            <li>
              {t(
                "Anything that happened after this backup is lost, including the access history inside it.",
                "Apa pun yang terjadi setelah cadangan ini hilang, termasuk riwayat akses di dalamnya.",
              )}
            </li>
            <li>
              {t(
                "Everyone is signed out. The vault is closed for writes while the restore runs.",
                "Semua orang keluar. Vault ditutup untuk penulisan selama pemulihan berjalan.",
              )}
            </li>
          </ul>

          <form class="form-stack" onSubmit={onReplace}>
            <div class="field">
              <label for="restore-host">
                {t(
                  `Type this server's host name to confirm: ${check?.host ?? ""}`,
                  `Ketik nama host server ini untuk konfirmasi: ${check?.host ?? ""}`,
                )}
              </label>
              <input
                id="restore-host"
                type="text"
                autocomplete="off"
                autocapitalize="none"
                spellcheck={false}
                value={typedHost}
                onInput={(e) => setTypedHost(e.currentTarget.value)}
                aria-invalid={
                  typedHost !== "" && !hostMatches(typedHost, check?.host ?? "")
                    ? "true"
                    : undefined
                }
              />
            </div>
            <label class="check">
              <input
                type="checkbox"
                checked={ack}
                onChange={(e) => setAck(e.currentTarget.checked)}
              />
              {t(
                "I understand this replaces my current vault",
                "Saya mengerti ini menggantikan vault saya saat ini",
              )}
            </label>
            <ErrorNote error={error} />
            <div class="row-between">
              <a class="link-btn" href={PATHS.settingsBackup}>
                {t("Cancel", "Batal")}
              </a>
              <button type="submit" class="btn danger" disabled={!replaceReady || busy}>
                {busy
                  ? t("Replacing...", "Mengganti...")
                  : t("Replace my vault", "Ganti vault saya")}
              </button>
            </div>
          </form>
        </section>
      ) : null}

      {error instanceof ApiError && error.kind === "invalid" ? (
        <p class="note">
          <Icon name="warning" size={14} />{" "}
          {t(
            "The file is not a valid backup, the passphrase is wrong, or the file was changed.",
            "File ini bukan cadangan yang valid, passphrase salah, atau file sudah diubah.",
          )}
        </p>
      ) : null}
    </div>
  );
}
