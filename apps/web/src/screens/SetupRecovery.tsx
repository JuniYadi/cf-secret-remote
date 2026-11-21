import { useEffect, useState } from "preact/hooks";
import { useLocation } from "wouter-preact";
import { Stepper } from "../components/Stepper.tsx";
import { BrandRow, Icon, LangToggle, PageTitle } from "../components/shared.tsx";
import { api } from "../lib/api.ts";
import { useKeyStatus, useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { getPrivateKey } from "../lib/keystore.ts";
import { CHALLENGE_SIZE, checkChallenge, pickChallenge } from "../lib/recovery-check.ts";
import { createRecoveryKey, lockRecovery, type NewRecoveryKey } from "../lib/vault.ts";
import { PATHS, pageCrumbs } from "../routes.ts";

/** Clipboard entries with the phrase are cleared after this long, where the browser allows (ADR 24). */
const CLIPBOARD_CLEAR_MS = 30_000;

/**
 * Step 3 of 4: the optional recovery key. The 24 words are shown once. The person types three random
 * words back to confirm they saved them. Skipping is allowed; an admin can then give access again (ADR 20).
 */
export function SetupRecoveryPage() {
  useLang();
  const [, navigate] = useLocation();
  const { unlocked } = useKeyStatus();
  const [recovery, setRecovery] = useState<NewRecoveryKey | null>(null);
  const [positions] = useState(() => pickChallenge());
  const [answers, setAnswers] = useState<string[]>(() => positions.map(() => ""));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Created once per visit. The words stay in this component only.
  useEffect(() => {
    let cancelled = false;
    void createRecoveryKey().then((key) => {
      if (!cancelled) setRecovery(key);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const words = recovery?.phrase.split(" ") ?? [];
  const confirmed = recovery !== null && checkChallenge(words, positions, answers);

  async function onSave() {
    const privateKey = getPrivateKey();
    if (!recovery || !privateKey || !confirmed || busy) return;
    setBusy(true);
    setError(null);
    try {
      const lockedKey = await lockRecovery(privateKey, recovery.entropy);
      await api.setRecoveryKey(lockedKey);
      navigate(PATHS.secrets);
    } catch {
      setBusy(false);
      setError(
        t(
          "The recovery key wasn't saved. Try again.",
          "Kunci pemulihan belum tersimpan. Coba lagi.",
        ),
      );
    }
  }

  async function onCopy() {
    if (!recovery) return;
    try {
      await navigator.clipboard.writeText(recovery.phrase);
      setCopied(true);
      // Clears the clipboard, which may also drop something the person copied later. Browsers that
      // refuse the write leave the clipboard alone.
      setTimeout(() => {
        void navigator.clipboard.writeText("").catch(() => undefined);
        setCopied(false);
      }, CLIPBOARD_CLEAR_MS);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div class="setup-page">
      <div class="setup-top">
        <BrandRow />
        <div class="setup-steps">
          <Stepper current={3} />
          <LangToggle />
        </div>
      </div>

      <div class="setup-grid recovery">
        <section class="card form-card" aria-labelledby="recovery-words-title">
          <div>
            <PageTitle crumbs={pageCrumbs("setupRecovery")} />
            <p class="sub">
              {t(
                "If you ever forget your vault password, these 24 words let you get back in on your own, without asking an admin.",
                "Jika kamu lupa vault password, 24 kata ini memungkinkan kamu masuk lagi sendiri, tanpa meminta admin.",
              )}
            </p>
          </div>

          <h2 id="recovery-words-title" class="visually-hidden">
            {t("Recovery words", "Kata pemulihan")}
          </h2>
          {recovery === null ? (
            <p class="sub">{t("Making your recovery key...", "Membuat kunci pemulihan...")}</p>
          ) : (
            <ol class="words" aria-label={t("Recovery words", "Kata pemulihan")}>
              {words.map((word, i) => (
                <li key={`${i}-${word}`} class="w">
                  <small aria-hidden="true">{i + 1}</small>
                  <span>{word}</span>
                </li>
              ))}
            </ol>
          )}

          <div class="row-actions">
            <button type="button" class="btn ghost sm" onClick={onCopy} disabled={!recovery}>
              {copied ? t("Copied", "Tersalin") : t("Copy", "Salin")}
            </button>
          </div>

          <div class="warn-box">
            <Icon name="warning" size={18} />
            <span>
              <b>
                {t(
                  "Anyone with these words can open your vault.",
                  "Siapa pun yang punya kata ini bisa membuka vault-mu.",
                )}
              </b>{" "}
              {t(
                "Store them like a password: in a password manager or on paper in a safe place. We can't show them again.",
                "Simpan seperti password: di password manager atau di kertas di tempat aman. Kami tidak bisa menampilkannya lagi.",
              )}
            </span>
          </div>

          <fieldset class="confirm">
            <legend>{t("Confirm: type these words back", "Konfirmasi: ketik kata berikut")}</legend>
            {positions.slice(0, CHALLENGE_SIZE).map((pos, i) => (
              <div class="field" key={pos}>
                <label for={`recovery-word-${pos}`}>
                  {t(`Word ${pos + 1}`, `Kata ke-${pos + 1}`)}
                </label>
                <input
                  id={`recovery-word-${pos}`}
                  type="text"
                  autocomplete="off"
                  autocapitalize="none"
                  spellcheck={false}
                  value={answers[i] ?? ""}
                  onInput={(e) => {
                    const next = [...answers];
                    next[i] = e.currentTarget.value;
                    setAnswers(next);
                  }}
                />
              </div>
            ))}
          </fieldset>

          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}

          <div class="row-between">
            <button type="button" class="link-btn" onClick={() => navigate(PATHS.secrets)}>
              {t("Skip for now", "Lewati dulu")}
            </button>
            <button
              type="button"
              class="btn pri"
              disabled={!confirmed || busy || !unlocked}
              onClick={onSave}
            >
              {busy ? t("Saving...", "Menyimpan...") : t("Continue", "Lanjut")}
            </button>
          </div>
        </section>

        <aside class="card side-card" aria-labelledby="why-title">
          <h2 id="why-title" class="card-title">
            {t("Why have one?", "Kenapa perlu?")}
          </h2>
          <ol class="steps-list">
            <li>
              <b>1</b>
              <span>
                {t(
                  "Forgot your password? Paste these words and pick a new one. No admin needed.",
                  "Lupa password? Tempel kata ini dan pilih yang baru. Tanpa admin.",
                )}
              </span>
            </li>
            <li>
              <b>2</b>
              <span>
                {t(
                  "It only works for you. Without the words, nobody can open your vault.",
                  "Hanya berlaku untukmu. Tanpa kata ini, tidak ada yang bisa membuka vault-mu.",
                )}
              </span>
            </li>
            <li>
              <b>3</b>
              <span>
                {t(
                  "You can make a new one any time, and the old one stops working.",
                  "Kamu bisa membuat yang baru kapan saja, dan yang lama berhenti berlaku.",
                )}
              </span>
            </li>
          </ol>
          <p class="note">
            {t(
              "This step is optional. If you skip it, an admin can give you access again if you forget your password.",
              "Langkah ini opsional. Jika dilewati, admin bisa memberimu akses lagi kalau kamu lupa password.",
            )}
          </p>
        </aside>
      </div>
    </div>
  );
}
