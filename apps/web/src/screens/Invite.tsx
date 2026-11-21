import { useState } from "preact/hooks";
import { Link } from "wouter-preact";
import { failureText, Notice, TechDetails } from "../components/Admin.tsx";
import { PageTitle } from "../components/shared.tsx";
import { api } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/admin.css";

const EMAIL_RE = /^[^@\s]+@[^@\s]+$/;

/** Invite a teammate (ADR 4, DESIGN.md). An invite creates the person; group access is given later. */
export function InvitePage() {
  useLang();
  const { me } = useSession();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"member" | "admin">("member");
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (me === null) return null;
  if (me.role !== "admin")
    return (
      <div class="page">
        <PageTitle crumbs={pageCrumbs("invite")} />
        <Notice tone="info">
          {t("Only admins can invite people.", "Hanya admin yang bisa mengundang orang.")}
        </Notice>
      </div>
    );

  const clean = email.trim().toLowerCase();
  const emailOk = EMAIL_RE.test(clean);

  async function onSubmit(event: Event) {
    event.preventDefault();
    setTried(true);
    setSent(null);
    if (!emailOk || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.invite(clean, role);
      setSent(clean);
      setEmail("");
      setTried(false);
    } catch (err) {
      setError(failureText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("invite")} />
      <p class="sub page-sub">
        {t(
          "Bring someone on without handing over any passwords. They get access to the project, not to the secrets themselves.",
          "Ajak seseorang tanpa menyerahkan password apa pun. Mereka mendapat akses ke proyek, bukan ke secret-nya.",
        )}
      </p>
      <div class="cols">
        <form class="card form-stack col-main" onSubmit={onSubmit} aria-labelledby="invite-title">
          <h2 id="invite-title">{t("Who are you inviting?", "Siapa yang kamu undang?")}</h2>
          <div class="field">
            <label for="invite-email">{t("Work email", "Email kerja")}</label>
            <input
              id="invite-email"
              type="text"
              inputMode="email"
              value={email}
              onInput={(e) => setEmail(e.currentTarget.value)}
              aria-invalid={tried && !emailOk ? "true" : undefined}
              aria-describedby={tried && !emailOk ? "invite-email-err" : undefined}
              autocomplete="off"
            />
            {tried && !emailOk && (
              <span id="invite-email-err" class="field-error" role="alert">
                {t(
                  "Type an email address, like name@company.com.",
                  "Ketik alamat email, misalnya nama@perusahaan.com.",
                )}
              </span>
            )}
          </div>
          <div class="field">
            <label for="invite-role">{t("Role", "Peran")}</label>
            <select
              id="invite-role"
              class="select"
              value={role}
              onChange={(e) => setRole(e.currentTarget.value === "admin" ? "admin" : "member")}
            >
              <option value="member">{t("Member", "Anggota")}</option>
              <option value="admin">{t("Admin", "Admin")}</option>
            </select>
          </div>
          {sent && (
            <Notice tone="info" title={t("Invite saved.", "Undangan tersimpan.")}>
              {t(
                `${sent} can sign in with their company account now. Give them access from Groups once they've set up their vault password.`,
                `${sent} sekarang bisa masuk dengan akun perusahaan. Beri akses dari Grup setelah mereka membuat vault password.`,
              )}
            </Notice>
          )}
          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}
          <div class="form-foot">
            <Link class="btn ghost" href={PATHS.groups}>
              {t("Cancel", "Batal")}
            </Link>
            <button type="submit" class="btn" disabled={busy}>
              {t("Send invite", "Kirim undangan")}
            </button>
          </div>
          <p class="note">
            {t(
              "They sign in with their company account. You'll get a notification to give them access once they've set up their vault password.",
              "Mereka masuk dengan akun perusahaan. Kamu mendapat notifikasi untuk memberi akses setelah mereka membuat vault password.",
            )}
          </p>
        </form>

        <aside class="card side-note col-side" aria-labelledby="they-do">
          <h2 id="they-do">{t("What they'll do", "Yang akan mereka lakukan")}</h2>
          <p class="note">
            {t(
              "We send them these steps by email. About five minutes.",
              "Kami kirim langkah ini lewat email. Sekitar lima menit.",
            )}
          </p>
          <ol class="plain-steps">
            <li>
              {t("Install cfs.", "Pasang cfs.")}
              <div class="code">$ brew install cfs</div>
            </li>
            <li>
              {t(
                "Sign in. A browser opens and asks them to confirm a short code.",
                "Masuk. Browser terbuka dan meminta mereka mencocokkan kode pendek.",
              )}
              <div class="code">$ cfs login --host https://vault.myorg.com</div>
            </li>
            <li>
              {t(
                "Create their vault password in the browser.",
                "Membuat vault password di browser.",
              )}
            </li>
            <li>
              {t(
                "You give them access to the group. It takes one click.",
                "Kamu memberi mereka akses ke grup. Cukup satu klik.",
              )}
            </li>
            <li>
              {t(
                "Run the project. cfs fetches the secrets and never writes them to disk.",
                "Jalankan proyek. cfs mengambil secret dan tidak pernah menulisnya ke disk.",
              )}
              <div class="code">$ cfs unlock{"\n"}$ cfs run -- bun run dev</div>
            </li>
          </ol>
          <TechDetails>
            {t(
              "This file in the project repo tells cfs where to look:",
              "File ini di repo proyek memberi tahu cfs ke mana mencari:",
            )}
            {"\n"}
            {'{ "host": "https://vault.myorg.com", "project": "myapp" }'}
          </TechDetails>
        </aside>
      </div>
    </div>
  );
}
