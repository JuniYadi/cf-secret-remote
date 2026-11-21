import { useEffect, useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { ErrorNote } from "../components/parts.tsx";
import { PageTitle } from "../components/shared.tsx";
import { ApiError, api, type RecoveryDetail } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { getPrivateKey, getPublicKey } from "../lib/keystore.ts";
import { codeMatches, splitWords } from "../lib/recovery-code.ts";
import { regrantKeys } from "../lib/regrant.ts";
import { useLoad } from "../lib/use-load.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

/** Give access again (ADR 20, design board Regrant). The admin types the four-word code the person sent. */
export function RegrantPage({ id }: { id?: string }) {
  useLang();
  const { me } = useSession();
  if (me?.role !== "admin") {
    return (
      <div class="page-plain">
        <PageTitle crumbs={pageCrumbs("regrant")} />
        <p class="sub">{t("Only admins can see this.", "Hanya admin yang bisa melihat ini.")}</p>
      </div>
    );
  }
  return id ? <RegrantOne id={id} /> : <PendingList />;
}

/** The requests waiting for an admin. Names and times only. */
function PendingList() {
  useLang();
  const pending = useLoad(() => api.pendingRecoveries(), "pending");
  return (
    <div class="page-plain regrant-page">
      <div>
        <PageTitle crumbs={pageCrumbs("regrant")} />
        <p class="sub">
          {t(
            "People who forgot their vault password and asked for access again. Check the code they send you before you give access.",
            "Orang yang lupa vault password dan meminta akses lagi. Periksa kode yang mereka kirim sebelum memberi akses.",
          )}
        </p>
      </div>
      <ErrorNote error={pending.error} />
      <section class="card settings-card" aria-labelledby="waiting-title">
        <h2 id="waiting-title" class="card-title">
          {t("Waiting for you", "Menunggu kamu")}
        </h2>
        {pending.data && pending.data.length === 0 ? (
          <p class="sub">{t("Nobody is waiting for access.", "Tidak ada yang menunggu akses.")}</p>
        ) : (
          <table class="data-table">
            <thead>
              <tr>
                <th scope="col">{t("Person", "Orang")}</th>
                <th scope="col">{t("Requested", "Diminta")}</th>
                <th scope="col">
                  <span class="visually-hidden">{t("Open", "Buka")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {(pending.data ?? []).map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td>
                    {new Date(r.createdAt * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC
                  </td>
                  <td class="right">
                    <Link
                      href={`${PATHS.regrant}/${encodeURIComponent(r.id)}`}
                      class="btn ghost sm"
                    >
                      {t("Open", "Buka")}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

function RegrantOne({ id }: { id: string }) {
  useLang();
  const [, navigate] = useLocation();
  const detail = useLoad(() => api.recoveryDetail(id), id);
  const [typed, setTyped] = useState("");
  const [codeOk, setCodeOk] = useState(false);
  const [unchecked, setUnchecked] = useState<Set<string>>(() => new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState<{ granted: string[]; notRewrapped: string[] } | null>(null);
  const req: RecoveryDetail | null = detail.data;

  // Recomputed as the admin types, so the give button only enables on a match (ADR 20).
  useEffect(() => {
    let current = true;
    if (!req || typed.trim() === "") {
      setCodeOk(false);
      return;
    }
    void codeMatches(typed, req.publicKey).then((ok) => {
      if (current) setCodeOk(ok);
    });
    return () => {
      current = false;
    };
  }, [typed, req]);

  const selected = (req?.groups ?? []).filter((g) => !unchecked.has(g));
  const locked = req !== null && (req.status === "locked" || req.attemptsLeft <= 0);

  /** Sends the typed words to the server. A wrong code is counted there (5 tries, then the request locks). */
  async function submitWords(keys: { prefix: string; version: number; wrappedKey: string }[]) {
    const words = splitWords(typed).join(" ");
    return api.grantRecovery(id, words, keys);
  }

  /**
   * Counts a wrong code on the server without giving anything: no keys are sent. A matching code is never
   * sent this way, because the server would then re-key the person with no groups.
   */
  async function onCheck() {
    if (busy || !req || typed.trim() === "") return;
    if (await codeMatches(typed, req.publicKey)) return;
    setBusy(true);
    setError(null);
    try {
      await submitWords([]);
    } catch {
      // The refusal is the expected answer to a wrong code: the server counts it. Show the count, not an error.
    } finally {
      detail.reload();
      setBusy(false);
    }
  }

  async function onGive() {
    const privateKey = getPrivateKey();
    const publicKey = getPublicKey();
    if (!req || !codeOk || !privateKey || !publicKey || selected.length === 0 || busy) return;
    setBusy(true);
    setError(null);
    try {
      const re = await regrantKeys(
        { groupKey: (prefix) => api.groupKey(prefix) },
        { groups: selected, publicKey: req.publicKey },
        { privateKey, publicKey },
      );
      const out = await submitWords(re.keys);
      setDone({ granted: out.groups, notRewrapped: re.notRewrapped });
    } catch (err) {
      setError(err);
      if (err instanceof ApiError) detail.reload();
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div class="page-plain regrant-page">
        <PageTitle crumbs={pageCrumbs("regrant")} />
        <section class="card settings-card" role="status">
          <p class="sub">
            {t(
              `Access given again for ${done.granted.length} group(s). ${req?.name ?? "They"} can unlock with their new password now.`,
              `Akses diberikan lagi untuk ${done.granted.length} grup. ${req?.name ?? "Mereka"} bisa membuka dengan password baru sekarang.`,
            )}
          </p>
          {done.notRewrapped.length > 0 ? (
            <p class="note">
              {t(
                `Not given (you are not in them): ${done.notRewrapped.join(", ")}. Another admin must give access to those.`,
                `Tidak diberikan (kamu tidak ada di dalamnya): ${done.notRewrapped.join(", ")}. Admin lain harus memberi akses untuk grup itu.`,
              )}
            </p>
          ) : null}
          <div class="row-actions">
            <button type="button" class="btn ghost" onClick={() => navigate(PATHS.regrant)}>
              {t("Back to the list", "Kembali ke daftar")}
            </button>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div class="page-plain regrant-page">
      <div>
        <PageTitle crumbs={pageCrumbs("regrant")} />
        <p class="sub">
          {req
            ? t(
                `${req.name} set a new vault password and can't open their groups until someone gives them access again.`,
                `${req.name} membuat vault password baru dan belum bisa membuka grupnya sampai seseorang memberinya akses lagi.`,
              )
            : t("Loading...", "Memuat...")}
        </p>
      </div>
      <ErrorNote error={detail.error} />

      {req ? (
        <>
          <section class="card settings-card" aria-labelledby="verify-title">
            <h2 id="verify-title" class="card-title">
              {t(
                `First, check it's really ${req.name}`,
                `Pertama, pastikan itu benar-benar ${req.name}`,
              )}
            </h2>
            <p class="sub">
              {t(
                "Their screen shows a four-word code. They should send it to you by DM, chat, or by voice, not through this request. Type it here exactly as you received it.",
                "Layar mereka menampilkan kode empat kata. Mereka harus mengirimnya kepadamu lewat DM, chat, atau suara, bukan lewat permintaan ini. Ketik di sini persis seperti yang kamu terima.",
              )}
            </p>
            <div class="field">
              <label for="regrant-code">
                {t("The code they sent you", "Kode yang mereka kirim kepadamu")}
              </label>
              <input
                id="regrant-code"
                type="text"
                autocomplete="off"
                autocapitalize="none"
                spellcheck={false}
                value={typed}
                disabled={locked || busy}
                aria-describedby="regrant-attempts"
                onInput={(e) => setTyped(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !codeOk) {
                    e.preventDefault();
                    void onCheck();
                  }
                }}
              />
            </div>
            <p id="regrant-attempts" class="note" aria-live="polite">
              {locked
                ? t(
                    "Too many wrong codes. The request is locked; they must start again.",
                    "Terlalu banyak kode salah. Permintaan dikunci; mereka harus mulai lagi.",
                  )
                : typed !== "" && !codeOk
                  ? t(
                      `The code doesn't match yet. ${req.attemptsLeft} attempts left.`,
                      `Kode belum cocok. Sisa ${req.attemptsLeft} percobaan.`,
                    )
                  : null}
            </p>
            {codeOk ? (
              <p class="chip" role="status">
                {t("The code matches their new key", "Kode cocok dengan kunci barunya")}
              </p>
            ) : null}
            {typed !== "" && !codeOk && !locked ? (
              <button type="button" class="btn ghost sm" disabled={busy} onClick={onCheck}>
                {t("Check the code", "Periksa kode")}
              </button>
            ) : null}
          </section>

          <section class="card settings-card" aria-labelledby="groups-title">
            <h2 id="groups-title" class="card-title">
              {t("Which groups should they get back?", "Grup mana yang dikembalikan?")}
            </h2>
            {req.groups.length === 0 ? (
              <p class="sub">
                {t("They were not in any group.", "Mereka tidak ada di grup mana pun.")}
              </p>
            ) : (
              <ul class="plain-list">
                {req.groups.map((g) => (
                  <li key={g}>
                    <label class="check">
                      <input
                        type="checkbox"
                        checked={!unchecked.has(g)}
                        disabled={busy}
                        onChange={(e) => {
                          const on = e.currentTarget.checked;
                          setUnchecked((s) => {
                            const next = new Set(s);
                            if (on) next.delete(g);
                            else next.add(g);
                            return next;
                          });
                        }}
                      />
                      {g} <span class="note">{t("They were a member", "Mereka dulu anggota")}</span>
                    </label>
                  </li>
                ))}
              </ul>
            )}
            <p class="note">
              {t(
                "Your browser shares each group's key with their new key. Groups you are not in are skipped and another admin must give them access.",
                "Browsermu membagikan kunci tiap grup ke kunci baru mereka. Grup yang tidak kamu ikuti dilewati dan admin lain harus memberi aksesnya.",
              )}
            </p>
            <ErrorNote error={error} />
            <div class="row-between">
              <Link href={PATHS.regrant} class="link-btn">
                {t("Cancel", "Batal")}
              </Link>
              <button
                type="button"
                class="btn pri"
                disabled={!codeOk || busy || locked || selected.length === 0}
                onClick={onGive}
              >
                {busy
                  ? t("Giving access...", "Memberi akses...")
                  : t("Give access again", "Beri akses lagi")}
              </button>
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
