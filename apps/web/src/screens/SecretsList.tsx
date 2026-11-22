// Secrets: the list (names only), with search, groups, the empty state, and owner and rotate-by badges.
// The list comes from GET /secrets, which holds names and metadata and never values (ADR 22).

import { useEffect, useState } from "preact/hooks";
import { Link } from "wouter-preact";
import { InfoBox, Pill } from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { api, type SecretSummary } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { currentLang, t } from "../lib/i18n.ts";
import {
  filterSecrets,
  groupCounts,
  groupOf,
  relativeTime,
  rotationStatus,
  todayIso,
} from "../lib/secrets.ts";
import { PATHS, pageCrumbs, secretHref } from "../routes.ts";

export function SecretsListPage() {
  useLang();
  const [list, setList] = useState<SecretSummary[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [query, setQuery] = useState("");
  const [group, setGroup] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setFailed(false);
    api
      .secrets()
      .then((rows) => {
        if (!live) return;
        if (Array.isArray(rows)) setList(rows);
        else setFailed(true);
      })
      .catch(() => {
        if (live) setFailed(true);
      });
    return () => {
      live = false;
    };
  }, [attempt]);

  const crumbs = pageCrumbs("secrets");
  const head = (
    <div class="top">
      <div>
        <PageTitle crumbs={crumbs} />
        <p class="sub">
          {t(
            "You can see the names. The values open only for people in the right group.",
            "Nama terlihat oleh semua. Isinya hanya terbuka untuk orang di grup yang tepat.",
          )}
        </p>
      </div>
      <div class="row-actions">
        <Pill tone="ok">{t("Unlocked", "Terbuka")}</Pill>
        <Link class="btn ghost" href={PATHS.secretsImport}>
          {t("Import .env", "Impor .env")}
        </Link>
        <Link class="btn" href={PATHS.secretsNew}>
          {t("+ New secret", "+ Secret baru")}
        </Link>
      </div>
    </div>
  );

  if (failed) {
    return (
      <div class="secrets-page">
        {head}
        <div class="card center narrow">
          <p class="sub">
            {t(
              "We couldn't load your secrets. Check your connection and try again.",
              "Secret-mu tidak bisa dimuat. Periksa koneksi lalu coba lagi.",
            )}
          </p>
          <button type="button" class="btn" onClick={() => setAttempt((n) => n + 1)}>
            {t("Try again", "Coba lagi")}
          </button>
        </div>
      </div>
    );
  }

  if (list === null) {
    return (
      <div class="secrets-page">
        {head}
        <p class="sub" role="status">
          {t("Loading...", "Memuat...")}
        </p>
      </div>
    );
  }

  if (list.length === 0) {
    return (
      <div class="secrets-page">
        {head}
        <SecretsEmpty />
      </div>
    );
  }

  const shown = filterSecrets(list, { query, group });
  const groups = groupCounts(list);
  const today = todayIso();
  const lang = currentLang();
  const now = Date.now();

  return (
    <div class="secrets-page">
      {head}
      <div class="secrets-split">
        <nav class="card tree" aria-label={t("Groups", "Grup")}>
          <button
            type="button"
            class={group === null ? "on" : ""}
            aria-pressed={group === null}
            onClick={() => setGroup(null)}
          >
            <span>{t("All secrets", "Semua secret")}</span>
            <small>{list.length}</small>
          </button>
          {groups.map((g) => (
            <button
              key={g.group}
              type="button"
              class={group === g.group ? "on" : ""}
              aria-pressed={group === g.group}
              onClick={() => setGroup(g.group)}
            >
              <span>{g.group}</span>
              <small>{g.count}</small>
            </button>
          ))}
        </nav>

        <div class="secrets-main">
          <div class="field">
            <label class="visually-hidden" for="secret-search">
              {t("Search secrets", "Cari secret")}
            </label>
            <input
              id="secret-search"
              type="search"
              placeholder={t("Search secrets", "Cari secret")}
              value={query}
              onInput={(e) => setQuery(e.currentTarget.value)}
            />
          </div>

          <div class="card tw">
            {shown.length === 0 ? (
              <p class="sub center-line" role="status">
                {t("No secret matches your search.", "Tidak ada secret yang cocok.")}
              </p>
            ) : (
              <table class="tbl">
                <thead>
                  <tr>
                    <th scope="col">{t("Name", "Nama")}</th>
                    <th scope="col">{t("Items", "Isi")}</th>
                    <th scope="col">{t("Group", "Grup")}</th>
                    <th scope="col">{t("Updated", "Diubah")}</th>
                    <th scope="col">{t("Owner and rotation", "Pemilik dan rotasi")}</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((s) => {
                    const rotation = rotationStatus(s.meta, today);
                    return (
                      <tr key={s.path}>
                        <td>
                          <Link class="p" href={secretHref(s.path)}>
                            {s.path}
                          </Link>
                        </td>
                        <td>{s.names.length}</td>
                        <td>
                          <Pill tone="acc">{groupOf(s.path)}</Pill>
                        </td>
                        <td>{relativeTime(s.updatedAt, now, lang)}</td>
                        <td class="badges">
                          {s.meta.owner && (
                            <Pill>
                              {t("Owner", "Pemilik")}: {s.meta.owner}
                            </Pill>
                          )}
                          {rotation === "overdue" && (
                            <Pill tone="warn">{t("Rotation overdue", "Rotasi terlewat")}</Pill>
                          )}
                          {rotation === "due" && (
                            <Pill>
                              {t("Rotate by", "Ganti sebelum")} {s.meta.rotateBy}
                            </Pill>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          <InfoBox>
            {t(
              "“Rotation overdue” comes from the rotate-by date you set on a secret. It does not mean the value leaked.",
              "“Rotasi terlewat” berasal dari tanggal ganti sebelum yang kamu atur pada secret. Itu tidak berarti nilainya bocor.",
            )}
          </InfoBox>
        </div>
      </div>
    </div>
  );
}

/** The first-run state: no secrets yet, with three ways to start (the board's Secrets-Empty). */
export function SecretsEmpty() {
  useLang();
  const starts = [
    {
      href: PATHS.groups,
      title: t("Create a group", "Buat grup"),
      text: t(
        "Decide who can open your secrets. You're the first member.",
        "Tentukan siapa yang bisa membuka secret-mu. Kamu anggota pertamanya.",
      ),
    },
    {
      href: PATHS.secretsNew,
      title: t("Add a secret", "Tambah secret"),
      text: t(
        "Start from scratch and add items one by one.",
        "Mulai dari nol dan tambah item satu per satu.",
      ),
    },
    {
      href: PATHS.secretsImport,
      title: t("Import a .env file", "Impor file .env"),
      text: t(
        "Already have one? Bring it in and review it first.",
        "Sudah punya? Masukkan dan tinjau dulu.",
      ),
    },
  ];
  return (
    <div class="secrets-empty">
      <div class="card empty-card">
        <div class="empty-icon" aria-hidden="true">
          <svg
            width="26"
            height="26"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
            focusable="false"
          >
            <path d="M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3" />
          </svg>
        </div>
        <h2>{t("No secrets yet", "Belum ada secret")}</h2>
        <p class="lead">
          {t(
            "Your vault is ready. Start by creating a group, then add your first secret. About three minutes.",
            "Vault-mu siap. Mulai dengan membuat grup, lalu tambahkan secret pertamamu. Sekitar tiga menit.",
          )}
        </p>
      </div>
      <div class="start-grid">
        {starts.map((s, i) => (
          <Link key={s.href} class="start" href={s.href}>
            <b>
              <span class="num">{i + 1}</span>
              {s.title}
            </b>
            <span>{s.text}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
