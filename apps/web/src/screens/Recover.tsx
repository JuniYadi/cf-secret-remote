import { useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { RecoveryKeyDownload } from "../components/RecoveryKeyDownload.tsx";
import { Icon, PageTitle, Standalone } from "../components/shared.tsx";
import { ApiError, api } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { unlock } from "../lib/keystore.ts";
import { isAcceptablePassword, MIN_PASSWORD_LENGTH } from "../lib/password.ts";
import { checkChallenge, pickChallenge } from "../lib/recovery-check.ts";
import { validRecoveryPhrase } from "../lib/recovery-code.ts";
import { markVaultReady } from "../lib/session.ts";
import { useLoad } from "../lib/use-load.ts";
import {
  createRecoveryKey,
  lockRecovery,
  lockWithPassword,
  openWithRecoveryKey,
} from "../lib/vault.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/settings.css";

type Stage = "form" | "working" | "new-key";

/**
 * Use your recovery key (design board Recover, ADR 20). The 24 words open the private key, then the person picks
 * a new vault password and gets a new recovery key. The old recovery key stops working.
 */
export function RecoverPage() {
  useLang();
  const [, navigate] = useLocation();
  const status = useLoad(() => api.recoveryKeyStatus(), "recovery-status");
  const [words, setWords] = useState("");
  const [pw, setPw] = useState("");
  const [again, setAgain] = useState("");
  const [stage, setStage] = useState<Stage>("form");
  const [error, setError] = useState<"words" | "wrong-words" | "failed" | "network" | null>(null);
  const [newPhrase, setNewPhrase] = useState("");
  const [positions] = useState(() => pickChallenge());
  const [answers, setAnswers] = useState<string[]>(() => positions.map(() => ""));
  const confirmed = newPhrase !== "" && checkChallenge(newPhrase.split(" "), positions, answers);

  const canSubmit =
    words.trim() !== "" && isAcceptablePassword(pw) && pw === again && stage === "form";

  async function onSubmit(event: Event) {
    event.preventDefault();
    if (!canSubmit || !status.data?.lockedKey) return;
    setError(null);
    const phrase = await validRecoveryPhrase(words);
    if (phrase === null) {
      setError("words");
      return;
    }
    setStage("working");
    try {
      let privateKey: string;
      try {
        privateKey = await openWithRecoveryKey(status.data.lockedKey, phrase);
      } catch {
        setStage("form");
        setError("wrong-words");
        return;
      }
      const who = await api.whoami();
      if (!who.publicKey) throw new Error("no vault");
      const lockedKey = await lockWithPassword(privateKey, pw);
      await api.changeVaultPassword(lockedKey);

      // A new recovery key replaces the used one. Its 24 words are shown once, on the next step.
      const fresh = await createRecoveryKey();
      await api.setRecoveryKey(await lockRecovery(privateKey, fresh.entropy));

      unlock({ publicKey: who.publicKey, privateKey });
      markVaultReady(who.publicKey, lockedKey);
      setPw("");
      setAgain("");
      setWords("");
      setNewPhrase(fresh.phrase);
      setStage("new-key");
    } catch (err) {
      setStage("form");
      setError(err instanceof ApiError && err.kind === "network" ? "network" : "failed");
    }
  }

  if (stage === "new-key") {
    return (
      <Standalone>
        <div class="card forgot-card">
          <PageTitle
            crumbs={[{ label: t("Save your recovery key", "Simpan kunci pemulihanmu") }]}
          />
          <p class="sub">
            {t(
              "These words are your new recovery key. Save them now. We can't show them again.",
              "Ini kata kunci pemulihan barumu. Simpan sekarang. Kami tidak bisa menampilkannya lagi.",
            )}
          </p>
          <ol class="words" aria-label={t("Recovery words", "Kata pemulihan")}>
            {newPhrase.split(" ").map((word, i) => (
              <li key={`${i}-${word}`} class="w">
                <small aria-hidden="true">{i + 1}</small>
                <span>{word}</span>
              </li>
            ))}
          </ol>
          <div class="row-actions">
            <RecoveryKeyDownload phrase={newPhrase} />
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
                "Store them like a password. The old recovery key no longer works.",
                "Simpan seperti password. Kunci pemulihan lama tidak berlaku lagi.",
              )}
            </span>
          </div>
          <fieldset class="confirm">
            <legend>{t("Confirm: type these words back", "Konfirmasi: ketik kata berikut")}</legend>
            {positions.map((pos, i) => (
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
                    const value = e.currentTarget.value;
                    setAnswers((previous) => {
                      const next = [...previous];
                      next[i] = value;
                      return next;
                    });
                  }}
                />
              </div>
            ))}
          </fieldset>
          <button
            type="button"
            class="btn pri block"
            disabled={!confirmed}
            onClick={() => navigate(PATHS.secrets)}
          >
            {t("Continue", "Lanjut")}
          </button>
        </div>
      </Standalone>
    );
  }

  const noKey = status.data !== null && !status.data.set;

  return (
    <Standalone>
      <div class="card forgot-card">
        <div>
          <PageTitle crumbs={pageCrumbs("recover")} />
          <p class="sub">
            {t(
              "Enter the 24 words you saved when you set up your vault, then choose a new vault password.",
              "Masukkan 24 kata yang kamu simpan saat menyiapkan vault, lalu pilih vault password baru.",
            )}
          </p>
        </div>

        {status.error ? (
          <p class="field-error" role="alert">
            {t(
              "We couldn't check your recovery key. Sign in again and retry.",
              "Kami tidak bisa memeriksa kunci pemulihanmu. Masuk lagi lalu coba.",
            )}
          </p>
        ) : null}

        {noKey ? (
          <div class="warn-box">
            <Icon name="warning" size={18} />
            <span>
              {t(
                "You don't have a recovery key saved. Ask an admin to give you access instead.",
                "Kamu belum punya kunci pemulihan yang tersimpan. Minta admin memberimu akses saja.",
              )}
            </span>
          </div>
        ) : (
          <form class="form-stack" onSubmit={onSubmit}>
            <div class="field">
              <label for="recover-words">
                {t("Your 24 recovery words", "24 kata pemulihanmu")}
              </label>
              <textarea
                id="recover-words"
                class="words-input"
                rows={4}
                autocomplete="off"
                autocapitalize="none"
                spellcheck={false}
                value={words}
                disabled={stage !== "form"}
                onInput={(e) => setWords(e.currentTarget.value)}
                aria-invalid={error === "words" || error === "wrong-words" ? "true" : undefined}
                aria-describedby="recover-words-help"
              />
              <span id="recover-words-help" class="note">
                {t(
                  "Separate them with spaces. Order matters.",
                  "Pisahkan dengan spasi. Urutan penting.",
                )}
              </span>
            </div>
            <div class="field">
              <label for="recover-password">{t("New vault password", "Vault password baru")}</label>
              <input
                id="recover-password"
                type="password"
                autocomplete="new-password"
                value={pw}
                onInput={(e) => setPw(e.currentTarget.value)}
                aria-describedby="recover-password-help"
              />
              <span id="recover-password-help" class="note">
                {t(
                  `At least ${MIN_PASSWORD_LENGTH} characters`,
                  `Minimal ${MIN_PASSWORD_LENGTH} karakter`,
                )}
              </span>
            </div>
            <div class="field">
              <label for="recover-again">{t("Type it again", "Ketik ulang")}</label>
              <input
                id="recover-again"
                type="password"
                autocomplete="new-password"
                value={again}
                onInput={(e) => setAgain(e.currentTarget.value)}
              />
              {again !== "" && again !== pw ? (
                <span class="field-error" role="alert">
                  {t("The two passwords don't match.", "Kedua password tidak sama.")}
                </span>
              ) : null}
            </div>
            {error ? (
              <p class="field-error" role="alert">
                {error === "words"
                  ? t(
                      "That doesn't look like your 24 words. Check the spelling and the order.",
                      "Itu tidak terlihat seperti 24 kata-mu. Periksa ejaan dan urutannya.",
                    )
                  : error === "wrong-words"
                    ? t("These words don't open your vault.", "Kata ini tidak membuka vault-mu.")
                    : error === "network"
                      ? t(
                          "We couldn't reach the server. Check your connection and try again.",
                          "Kami tidak bisa menghubungi server. Periksa koneksi lalu coba lagi.",
                        )
                      : t(
                          "Your vault wasn't recovered. Try again.",
                          "Vault-mu belum pulih. Coba lagi.",
                        )}
              </p>
            ) : null}
            <button type="submit" class="btn pri block" disabled={!canSubmit || status.loading}>
              {stage === "working"
                ? t("Recovering...", "Memulihkan...")
                : t("Recover my vault", "Pulihkan vault saya")}
            </button>
          </form>
        )}

        <ul class="plain-list">
          <li>
            {t(
              "Your groups and secrets stay exactly as they were. Nobody needs to share anything again.",
              "Grup dan secret-mu tetap seperti semula. Tidak ada yang perlu membagikan ulang.",
            )}
          </li>
          <li>
            {t(
              "These words are used up. You'll get a new recovery key to save.",
              "Kata ini sudah terpakai. Kamu akan mendapat kunci pemulihan baru untuk disimpan.",
            )}
          </li>
        </ul>
        <div class="help">
          <Link href={PATHS.forgot}>
            {t(
              "Don't have it? Ask an admin to give you access instead",
              "Tidak punya? Minta admin memberimu akses saja",
            )}
          </Link>
        </div>
      </div>
    </Standalone>
  );
}
