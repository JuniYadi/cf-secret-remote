// Import, step 1 of 2: paste or drop a .env or JSON file. Parsing happens here in the browser, and nothing is
// saved yet. Step 2 (SecretImportReview) shows what was found and does the save.

import { useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { WarnBox } from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { getImportHint, setImportDraft } from "../lib/import-draft.ts";
import { parseImportText, validName } from "../lib/secrets.ts";
import { PATHS, pageCrumbs } from "../routes.ts";

const EXAMPLE = `# paste your .env here
DATABASE_URL="postgres://…"
DEBUG_MODE=true
MAX_CONNECTIONS=20`;

export function SecretImportPage() {
  useLang();
  const [, navigate] = useLocation();
  const [text, setText] = useState("");
  const [errors, setErrors] = useState<string[]>([]);
  const [dragging, setDragging] = useState(false);

  const readFile = async (file: File | undefined) => {
    if (!file) return;
    setText(await file.text());
    setErrors([]);
  };

  const next = () => {
    const parsed = parseImportText(text);
    if ("error" in parsed) {
      setErrors([parsed.error]);
      return;
    }
    if (parsed.errors.length > 0) {
      setErrors(parsed.errors);
      return;
    }
    const names = Object.keys(parsed.values);
    if (names.length === 0 && parsed.empty.length === 0) {
      setErrors([
        t(
          "Nothing to import. Paste a .env file or a JSON object.",
          "Tidak ada yang bisa diimpor. Tempel file .env atau objek JSON.",
        ),
      ]);
      return;
    }
    const invalid = names.filter((n) => !validName(n));
    const values = Object.fromEntries(
      names.filter((n) => validName(n)).map((n) => [n, parsed.values[n] as string]),
    );
    const hint = getImportHint();
    setImportDraft({
      source: parsed.source,
      values,
      empty: parsed.empty,
      invalid,
      errors: [],
      target: hint ?? { mode: "new", path: "" },
      strategy: "overwrite",
    });
    navigate(PATHS.secretsImportReview);
  };

  return (
    <div class="secrets-page import-page">
      <Steps current={1} />
      <div>
        <PageTitle crumbs={pageCrumbs("secretsImport")} />
        <p class="sub">
          {t(
            "Paste it or drop the file. You'll check what we found on the next screen before anything is saved.",
            "Tempel atau jatuhkan filenya. Kamu akan memeriksa hasilnya di layar berikutnya sebelum apa pun disimpan.",
          )}
        </p>
      </div>

      <div class={`card import-card${dragging ? " dragging" : ""}`}>
        <label class="visually-hidden" for="import-text">
          {t("Paste a .env file or JSON", "Tempel file .env atau JSON")}
        </label>
        <textarea
          id="import-text"
          class="env-text"
          spellcheck={false}
          autocomplete="off"
          value={text}
          placeholder={EXAMPLE}
          onInput={(e) => setText(e.currentTarget.value)}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            void readFile(e.dataTransfer?.files?.[0]);
          }}
          rows={12}
        />
        <div class="drop">
          <label>
            {t("or drop a .env or .json file here", "atau jatuhkan file .env atau .json di sini")}
            <input
              class="visually-hidden"
              type="file"
              accept=".env,.json,text/plain,application/json"
              onChange={(e) => void readFile(e.currentTarget.files?.[0])}
            />
          </label>
        </div>
        <span class="note">
          {t(
            "Read locally in your browser. The file is never uploaded as-is.",
            "Dibaca lokal di browsermu. File tidak pernah diunggah apa adanya.",
          )}
        </span>
      </div>

      {errors.length > 0 && (
        <WarnBox>
          <ul class="error-list">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </WarnBox>
      )}

      <div class="form-actions">
        <Link class="btn ghost" href={PATHS.secrets}>
          {t("Cancel", "Batal")}
        </Link>
        <button type="button" class="btn" onClick={next} disabled={text.trim() === ""}>
          {t("Continue", "Lanjut")}
        </button>
      </div>
    </div>
  );
}

/** The two steps of an import (the board's step indicator). */
export function Steps({ current }: { current: 1 | 2 }) {
  useLang();
  return (
    <ol class="wiz-steps" aria-label={t("Steps", "Langkah")}>
      <li
        class={`wiz-step${current === 1 ? " on" : " done"}`}
        aria-current={current === 1 ? "step" : undefined}
      >
        <i aria-hidden="true">{current === 2 ? "✓" : "1"}</i>
        {t("Add file", "Tambah file")}
      </li>
      <li
        class={`wiz-step${current === 2 ? " on" : ""}`}
        aria-current={current === 2 ? "step" : undefined}
      >
        <i aria-hidden="true">2</i>
        {t("Review and save", "Tinjau dan simpan")}
      </li>
    </ol>
  );
}
