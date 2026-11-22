import { useEffect, useState } from "preact/hooks";
import { PageTitle } from "../components/shared.tsx";
import { formatTime } from "../lib/activity.ts";
import { api, type SignedInDevice } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { durationText, messageFor } from "../lib/messages.ts";
import { pageCrumbs } from "../routes.ts";
import "../styles/activity.css";

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Marks the "sign out everywhere" button as the armed one. Never a real session id. */
const ALL = "*";

/**
 * Signed-in devices (ADR 27, DESIGN "Signed-in devices"). Each row is a CLI session. Signing out ends that
 * session on the server. The browser's own Access session is not listed here; it ends with Sign out in the sidebar.
 */
export function DevicesPage() {
  const lang = useLang();
  const [devices, setDevices] = useState<SignedInDevice[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [armed, setArmed] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function reload() {
    try {
      setDevices(await api.sessions());
      setError(null);
    } catch (err) {
      setError(messageFor(err));
    }
  }

  useEffect(() => {
    void reload();
  }, []);

  async function signOutAll() {
    // Same two presses as a single device.
    if (armed !== ALL) {
      setArmed(ALL);
      setNotice(null);
      return;
    }
    setBusy(ALL);
    setError(null);
    try {
      const out = await api.signOutAllDevices();
      setArmed(null);
      setNotice(
        t(
          `Signed out of ${out.ended} ${out.ended === 1 ? "device" : "devices"}.`,
          `Keluar dari ${out.ended} perangkat.`,
        ),
      );
      await reload();
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  async function signOut(device: SignedInDevice) {
    // The first press arms the row, the second one ends the session. Nothing is lost by a stray click.
    if (armed !== device.id) {
      setArmed(device.id);
      setNotice(null);
      return;
    }
    setBusy(device.id);
    setError(null);
    try {
      await api.signOutDevice(device.id);
      setArmed(null);
      setNotice(t(`Signed out of ${deviceName(device)}.`, `Keluar dari ${deviceName(device)}.`));
      await reload();
    } catch (err) {
      setError(messageFor(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div class="page-plain activity-page">
      <PageTitle crumbs={pageCrumbs("devices")} />
      <p class="sub activity-sub">
        {t(
          "Every computer where you've signed in to cfs. Sign out of any you don't recognize or no longer use.",
          "Semua komputer tempat kamu masuk ke cfs. Keluarkan yang tidak kamu kenali atau tidak lagi dipakai.",
        )}
      </p>

      {notice !== null && (
        <p class="note" role="status">
          {notice}
        </p>
      )}
      {error !== null && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}

      <section
        class="card activity-card"
        aria-label={t("Signed-in devices", "Perangkat yang masuk")}
      >
        {devices === null && <p class="note">{t("Loading...", "Memuat...")}</p>}
        {devices !== null && devices.length === 0 && (
          <p class="note">{t("No devices are signed in.", "Tidak ada perangkat yang masuk.")}</p>
        )}
        {devices !== null && devices.length > 0 && (
          <div class="row-between">
            <span class="note">
              {t(`${devices.length} signed in`, `${devices.length} perangkat masuk`)}
            </span>
            <button
              type="button"
              class="btn danger-outline sm"
              disabled={busy !== null}
              onClick={() => void signOutAll()}
            >
              {busy === ALL
                ? t("Signing out...", "Keluar...")
                : armed === ALL
                  ? t("Confirm: sign out everywhere", "Konfirmasi: keluar di mana saja")
                  : t("Sign out everywhere", "Keluar di mana saja")}
            </button>
          </div>
        )}
        {devices !== null && devices.length > 0 && (
          <div class="tw">
            <table class="log-table">
              <thead>
                <tr>
                  <th scope="col">{t("Device", "Perangkat")}</th>
                  <th scope="col">{t("Signed in", "Masuk")}</th>
                  <th scope="col">{t("Last used", "Terakhir dipakai")}</th>
                  <th scope="col">{t("Ends", "Berakhir")}</th>
                  <th scope="col">
                    <span class="visually-hidden">{t("Actions", "Aksi")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => (
                  <tr key={device.id}>
                    <td>
                      <div class="device-name">{deviceName(device)}</div>
                      <div class="note">{t("Command line (cfs)", "Baris perintah (cfs)")}</div>
                    </td>
                    <td>
                      <time dateTime={new Date(device.createdAt * 1000).toISOString()}>
                        {formatTime(device.createdAt, lang)}
                      </time>
                    </td>
                    <td>
                      {device.lastUsedAt === null ? (
                        "-"
                      ) : (
                        <time dateTime={new Date(device.lastUsedAt * 1000).toISOString()}>
                          {formatTime(device.lastUsedAt, lang)}
                        </time>
                      )}
                    </td>
                    <td>
                      {t(
                        `in ${durationText(device.expiresAt - nowSeconds(), "en")}`,
                        `dalam ${durationText(device.expiresAt - nowSeconds(), "id")}`,
                      )}
                    </td>
                    <td class="actions-cell">
                      <button
                        type="button"
                        class="btn danger-outline sm"
                        disabled={busy !== null}
                        aria-label={
                          armed === device.id
                            ? t(
                                `Confirm sign out of ${deviceName(device)}`,
                                `Konfirmasi keluar dari ${deviceName(device)}`,
                              )
                            : t(
                                `Sign out of ${deviceName(device)}`,
                                `Keluar dari ${deviceName(device)}`,
                              )
                        }
                        onClick={() => void signOut(device)}
                      >
                        {busy === device.id
                          ? t("Signing out...", "Keluar...")
                          : armed === device.id
                            ? t("Confirm sign out", "Konfirmasi keluar")
                            : t("Sign out", "Keluarkan")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p class="note tw-note">
          {t(
            "Signing out ends the session right away. A vault already unlocked on that device locks itself within an hour.",
            "Keluar mengakhiri sesi seketika. Vault yang sudah terbuka di perangkat itu terkunci sendiri dalam satu jam.",
          )}
        </p>
      </section>
    </div>
  );
}

/** The device name the CLI sent at login, or a plain label when it sent none. Never a token or id. */
function deviceName(device: SignedInDevice): string {
  return device.device.trim() !== "" ? device.device : t("Unnamed device", "Perangkat tanpa nama");
}
