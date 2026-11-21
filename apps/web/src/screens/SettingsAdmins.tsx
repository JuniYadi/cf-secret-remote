import { useState } from "preact/hooks";
import { ErrorNote, SettingsTabs } from "../components/parts.tsx";
import { Icon, PageTitle } from "../components/shared.tsx";
import { adminSummary, hasRecoveryKey } from "../lib/admins.ts";
import { ApiError, api, type Identity } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { useLoad } from "../lib/use-load.ts";
import { pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

/**
 * Settings, Admins tab (design board Settings-Admins). Two admins must hold a vault, so one can give the
 * other access again (ADR 20). The server refuses a demotion that breaks that; this screen checks first.
 */
export function SettingsAdminsPage() {
  useLang();
  const { me } = useSession();
  const directory = useLoad(() => api.identities(), "identities");
  const [showCandidates, setShowCandidates] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  if (me?.role !== "admin") {
    return (
      <div class="page-plain settings-page">
        <PageTitle crumbs={pageCrumbs("settingsAdmins")} />
        <p class="sub">{t("Only admins can see this.", "Hanya admin yang bisa melihat ini.")}</p>
      </div>
    );
  }

  const summary = directory.data ? adminSummary(directory.data) : null;

  async function change(person: Identity, role: "admin" | "member") {
    setBusy(person.id);
    setError(null);
    setNotice(null);
    try {
      await api.setRole(person.id, role);
      setNotice(
        role === "admin"
          ? t(`${person.name} is an admin now.`, `${person.name} sekarang admin.`)
          : t(`${person.name} is a member now.`, `${person.name} sekarang anggota.`),
      );
      directory.reload();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setNotice(
          t(
            "At least two admins must hold a vault. Make another admin first, then try again.",
            "Minimal dua admin harus memegang vault. Jadikan admin lain dulu, lalu coba lagi.",
          ),
        );
      } else setError(err);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div class="page-plain settings-page">
      <div>
        <PageTitle crumbs={pageCrumbs("settingsAdmins")} />
        <p class="sub">
          {t(
            "Admins manage groups, permissions and bots. They also hold keys, so it matters who they are and whether they can get back in.",
            "Admin mengelola grup, izin, dan bot. Mereka juga memegang kunci, jadi penting siapa mereka dan apakah mereka bisa masuk kembali.",
          )}
        </p>
      </div>
      <SettingsTabs current="admins" />

      {summary && !summary.twoAdminsOk ? (
        <div class="warn-box" role="status">
          <Icon name="warning" size={18} />
          <span>
            <b>
              {t("Only one admin can open the vault", "Hanya satu admin yang bisa membuka vault")}
            </b>{" "}
            {t(
              "If that admin forgets their vault password and has no recovery key, nobody can manage this vault again. Add at least one more admin.",
              "Jika admin itu lupa vault password dan tidak punya kunci pemulihan, tidak ada yang bisa mengelola vault ini lagi. Tambahkan setidaknya satu admin lagi.",
            )}
          </span>
        </div>
      ) : null}

      <ErrorNote error={directory.error ?? error} />
      {notice ? (
        <p class="notice" role="status">
          {notice}
        </p>
      ) : null}

      <section class="card settings-card" aria-labelledby="current-admins">
        <div class="card-head">
          <h2 id="current-admins" class="card-title">
            {t("Current admins", "Admin saat ini")}
          </h2>
          <button
            type="button"
            class="btn ghost sm"
            aria-expanded={showCandidates}
            onClick={() => setShowCandidates((v) => !v)}
          >
            {t("Add another admin", "Tambah admin lagi")}
          </button>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">{t("Person", "Orang")}</th>
              <th scope="col">{t("Vault key", "Kunci vault")}</th>
              <th scope="col">{t("Recovery key", "Kunci pemulihan")}</th>
              <th scope="col">
                <span class="visually-hidden">{t("Action", "Aksi")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {(summary?.admins ?? []).map((a) => {
              const holdsVault = a.publicKey !== null;
              // Demoting a vault holder leaves one fewer admin with a vault. Two must remain.
              const blocked = holdsVault && (summary?.withVault.length ?? 0) <= 2;
              return (
                <tr key={a.id}>
                  <td>
                    <span class="person-cell">
                      <span class="ava" aria-hidden="true">
                        {a.name.charAt(0).toUpperCase()}
                      </span>
                      {a.name}
                      {me.id === a.id ? <span class="chip">{t("You", "Kamu")}</span> : null}
                    </span>
                  </td>
                  <td>
                    {holdsVault ? t("Ready", "Siap") : t("Hasn't set up", "Belum menyiapkan")}
                  </td>
                  <td>{hasRecoveryKey(a) ? t("Saved", "Tersimpan") : t("None", "Tidak ada")}</td>
                  <td class="right">
                    <button
                      type="button"
                      class="btn ghost sm"
                      disabled={blocked || busy === a.id}
                      aria-describedby={blocked ? `keep-${a.id}` : undefined}
                      onClick={() => change(a, "member")}
                    >
                      {t("Make member", "Jadikan anggota")}
                    </button>
                    {blocked ? (
                      <span id={`keep-${a.id}`} class="note">
                        {t(
                          "Stays admin: two admins must hold a vault.",
                          "Tetap admin: dua admin harus memegang vault.",
                        )}
                      </span>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      {showCandidates && summary ? (
        <section class="card settings-card" aria-labelledby="candidates">
          <h2 id="candidates" class="card-title">
            {t("Make someone an admin", "Jadikan seseorang admin")}
          </h2>
          {summary.candidates.length === 0 ? (
            <p class="sub">
              {t("Nobody else to make admin yet.", "Belum ada orang lain untuk dijadikan admin.")}
            </p>
          ) : (
            <table class="data-table">
              <tbody>
                {summary.candidates.map((c) => (
                  <tr key={c.id}>
                    <td>{c.name}</td>
                    <td>
                      {c.publicKey !== null
                        ? t("Ready", "Siap")
                        : t("Hasn't set up", "Belum menyiapkan")}
                    </td>
                    <td class="right">
                      {c.publicKey !== null ? (
                        <button
                          type="button"
                          class="btn pri sm"
                          disabled={busy === c.id}
                          onClick={() => change(c, "admin")}
                        >
                          {t("Make admin", "Jadikan admin")}
                        </button>
                      ) : (
                        <span class="note">
                          {t("They set up their vault first.", "Mereka menyiapkan vault dulu.")}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      ) : null}

      <section class="card side-card" aria-labelledby="why-two">
        <h2 id="why-two" class="card-title">
          {t("Why two?", "Kenapa dua?")}
        </h2>
        <ul class="plain-list">
          <li>
            {t(
              "Your secrets are locked with keys that only people hold. We can't reset them for you.",
              "Secret-mu dikunci dengan kunci yang hanya dipegang orang. Kami tidak bisa mengatur ulangnya untukmu.",
            )}
          </li>
          <li>
            {t(
              "A second admin can give the first one access again if they forget their password.",
              "Admin kedua bisa memberi admin pertama akses lagi jika ia lupa password.",
            )}
          </li>
        </ul>
      </section>
    </div>
  );
}
