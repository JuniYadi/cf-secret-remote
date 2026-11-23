// New secret: a name, and how to start (empty, import a .env file, or paste JSON). The group is the first
// segment of the name, as on the server (keyring prefix), so it is shown, not chosen.

import { useEffect, useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { InfoBox, WarnBox } from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { api } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { setImportHint } from "../lib/import-draft.ts";
import {
  groupKeyFor,
  isConflict,
  isNoKey,
  saveValues,
  secretConflictMessage,
} from "../lib/secret-store.ts";
import { groupOf, validSecretPath } from "../lib/secrets.ts";
import { PATHS, pageCrumbs, SECRET_TABS, secretHref } from "../routes.ts";

type Start = "empty" | "import" | "json";

export function SecretNewPage() {
  useLang();
  const [, navigate] = useLocation();
  const [name, setName] = useState("");
  const [start, setStart] = useState<Start>("empty");
  const [existing, setExisting] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .secrets()
      .then((rows) => {
        if (live && Array.isArray(rows)) setExisting(rows.map((r) => r.path));
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);

  const path = name.trim();
  const group = validSecretPath(path) ? groupOf(path) : "";

  const create = async () => {
    if (busy) return;
    if (!validSecretPath(path)) {
      setError(
        t(
          "Use letters, numbers, dots, dashes and underscores, with a slash between parts, such as myapp/dev.",
          "Pakai huruf, angka, titik, tanda hubung, dan garis bawah, dengan garis miring di antara bagian, mis. myapp/dev.",
        ),
      );
      return;
    }
    if (existing.includes(path)) {
      setError(t("A secret with this name already exists.", "Secret dengan nama ini sudah ada."));
      return;
    }
    setError(null);
    if (start !== "empty") {
      setImportHint({ mode: "new", path });
      navigate(PATHS.secretsImport);
      return;
    }
    setBusy(true);
    try {
      const { groupKey, keyVersion } = await groupKeyFor(group);
      await saveValues({ path, values: {}, currentVersion: 0, groupKey, keyVersion });
      navigate(`${secretHref(path)}${SECRET_TABS.edit}`);
    } catch (err) {
      setBusy(false);
      if (isNoKey(err)) {
        setError(
          t(
            `You don't have a key for the group ${group}. Ask someone in the group to give you access first.`,
            `Kamu tidak punya kunci untuk grup ${group}. Minta anggota grup memberimu akses dulu.`,
          ),
        );
      } else if (secretConflictMessage(err)) {
        setError(secretConflictMessage(err) as string);
      } else if (isConflict(err)) {
        setError(
          t(
            "That name was just taken. Pick another.",
            "Nama itu baru saja dipakai. Pilih nama lain.",
          ),
        );
      } else {
        setError(
          t(
            "We couldn't create the secret. Check your connection and try again.",
            "Secret tidak bisa dibuat. Periksa koneksi lalu coba lagi.",
          ),
        );
      }
    }
  };

  const options: { id: Start; title: string; sub: string }[] = [
    {
      id: "empty",
      title: t("Empty", "Kosong"),
      sub: t("Add items one by one.", "Tambah item satu per satu."),
    },
    {
      id: "import",
      title: t("Import a .env file", "Impor file .env"),
      sub: t(
        "Paste or drop it. You'll review it first.",
        "Tempel atau jatuhkan. Kamu akan meninjaunya dulu.",
      ),
    },
    {
      id: "json",
      title: t("Paste JSON", "Tempel JSON"),
      sub: t(
        "Keeps true/false and numbers as real types.",
        "Menjaga benar/salah dan angka tetap bertipe.",
      ),
    },
  ];

  return (
    <div class="secrets-page">
      <div>
        <PageTitle crumbs={pageCrumbs("secretsNew")} />
        <p class="sub">
          {t(
            "A secret holds a set of items, like the values in a .env file. Choose a name and who can open it.",
            "Sebuah secret berisi sekumpulan item, seperti isi file .env. Pilih nama dan siapa yang bisa membukanya.",
          )}
        </p>
      </div>

      <div class="new-split">
        <form
          class="card new-form"
          onSubmit={(e) => {
            e.preventDefault();
            void create();
          }}
        >
          <div class="f">
            <label for="secret-name">{t("Name", "Nama")}</label>
            <input
              id="secret-name"
              type="text"
              value={name}
              autocomplete="off"
              spellcheck={false}
              placeholder="myapp/staging"
              aria-describedby="secret-name-help"
              aria-invalid={error !== null ? "true" : undefined}
              onInput={(e) => setName(e.currentTarget.value)}
            />
            <small id="secret-name-help">
              {t(
                "Use a slash to organize it: project/environment.",
                "Pakai garis miring untuk mengaturnya: proyek/environment.",
              )}
            </small>
          </div>

          <div class="f">
            <span class="label">{t("Who can open it", "Siapa yang bisa membukanya")}</span>
            <div class="box" aria-live="polite">
              <span>
                {group
                  ? `${t("Group", "Grup")}: ${group}`
                  : t("Group from the name", "Grup dari nama")}
              </span>
            </div>
            <small>
              {t(
                "Everyone in this group can open the values. Others only see the name.",
                "Semua orang di grup ini bisa membuka nilainya. Yang lain hanya melihat namanya.",
              )}
            </small>
          </div>

          <fieldset class="f start-fieldset">
            <legend class="label">{t("How do you want to start?", "Mau mulai dari mana?")}</legend>
            {options.map((o) => (
              <label key={o.id} class={`opt${start === o.id ? " on" : ""}`}>
                <input
                  type="radio"
                  name="start"
                  value={o.id}
                  checked={start === o.id}
                  onChange={() => setStart(o.id)}
                />
                <span>
                  {o.title}
                  <small>{o.sub}</small>
                </span>
              </label>
            ))}
          </fieldset>

          {error && <WarnBox>{error}</WarnBox>}

          <div class="form-actions">
            <Link class="btn ghost" href={PATHS.secrets}>
              {t("Cancel", "Batal")}
            </Link>
            <button type="submit" class="btn" disabled={busy || path === ""}>
              {t("Create and add items", "Buat dan tambah item")}
            </button>
          </div>
        </form>

        <div class="new-side">
          <div class="card side-card">
            <h2>{t("Naming tips", "Tips penamaan")}</h2>
            <p class="note">
              {t(
                "The first part is the project, the last part is the environment.",
                "Bagian pertama adalah proyek, bagian terakhir adalah environment.",
              )}
            </p>
            <div class="ex">
              <b>myapp/dev</b>
              <span>{t("local development", "pengembangan lokal")}</span>
            </div>
            <div class="ex">
              <b>myapp/prod</b>
              <span>{t("production", "produksi")}</span>
            </div>
            <div class="ex">
              <b>backend/payments/dev</b>
              <span>{t("a service inside a project", "layanan dalam proyek")}</span>
            </div>
          </div>
          <div class="card side-card">
            <h2>{t("Why it matters", "Kenapa ini penting")}</h2>
            <p class="note">
              {t(
                "With a name like myapp/staging, teammates load it by environment:",
                "Dengan nama seperti myapp/staging, rekan memuatnya per environment:",
              )}
            </p>
            <div class="code">$ cfs run --env staging -- bun run dev</div>
          </div>
          <InfoBox>
            {t(
              "Creating a secret writes version 1. You can add items right after.",
              "Membuat secret menulis versi 1. Kamu bisa langsung menambah item.",
            )}
          </InfoBox>
        </div>
      </div>
    </div>
  );
}
