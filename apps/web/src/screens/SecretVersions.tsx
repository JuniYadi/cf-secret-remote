// Versions tab (DESIGN.md "Versi secret", ADR 22): the list of versions, a name-level diff between two of
// them (from fingerprints, never values), and restore. A restore writes the old values as a NEW version;
// nothing in history is edited. Restoring can bring back a value that leaked, so the page says so.

import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import { ReasonForm } from "../components/reason-form.tsx";
import { InfoBox, Pill, SecretTabs, WarnBox } from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { ApiError, api, type VersionRow } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { currentLang, t } from "../lib/i18n.ts";
import { isConflict, loadSecret, saveValues, secretConflictMessage } from "../lib/secret-store.ts";
import { type DiffKind, diffRows, relativeTime } from "../lib/secrets.ts";
import { pageCrumbs, secretHref } from "../routes.ts";

export function SecretVersionsPage({ name }: { name: string }) {
  useLang();
  const [versions, setVersions] = useState<VersionRow[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    let live = true;
    setFailed(false);
    api
      .secretVersions(name)
      .then((rows) => {
        if (!live) return;
        if (Array.isArray(rows) && rows.length > 0) setVersions(rows);
        else setFailed(true);
      })
      .catch(() => {
        if (live) setFailed(true);
      });
    return () => {
      live = false;
    };
  }, [name, attempt]);

  const head = (
    <div>
      <PageTitle crumbs={pageCrumbs("secretVersions", name)} />
      <p class="sub">
        {t(
          "Every save makes a new version. See what changed between two of them, and bring an older one back if you need to.",
          "Setiap penyimpanan membuat versi baru. Lihat apa yang berubah di antara dua versi, dan pulihkan yang lama jika perlu.",
        )}
      </p>
      <SecretTabs name={name} active="versions" />
    </div>
  );

  if (versions === null) {
    return (
      <div class="secrets-page">
        {head}
        {failed ? (
          <div class="card center narrow">
            <p class="sub">{t("We couldn't load the versions.", "Versi tidak bisa dimuat.")}</p>
            <button type="button" class="btn" onClick={() => setAttempt((n) => n + 1)}>
              {t("Try again", "Coba lagi")}
            </button>
          </div>
        ) : (
          <p class="sub" role="status">
            {t("Loading...", "Memuat...")}
          </p>
        )}
      </div>
    );
  }

  return (
    <VersionsBody
      name={name}
      versions={versions}
      selected={selected}
      onSelect={setSelected}
      head={head}
      onReload={() => setAttempt((n) => n + 1)}
    />
  );
}

function VersionsBody({
  name,
  versions,
  selected,
  onSelect,
  head,
  onReload,
}: {
  name: string;
  versions: VersionRow[];
  selected: number | null;
  onSelect: (v: number) => void;
  head: ComponentChildren;
  onReload: () => void;
}) {
  useLang();
  const current = versions[0] as VersionRow;
  const chosen = versions.find((v) => v.version === selected) ?? versions[1] ?? current;
  const older = chosen.version < current.version ? chosen : null;
  const rows = older ? diffRows(older.fps, current.fps) : null;
  const lang = currentLang();
  const now = Date.now();

  return (
    <div class="secrets-page">
      {head}
      <div class="versions-split">
        <div class="card version-list">
          <h2>{t("All versions", "Semua versi")}</h2>
          <ul>
            {versions.map((v) => (
              <li key={v.version}>
                <button
                  type="button"
                  class={`ver${v.version === chosen.version ? " sel" : ""}${v.version === current.version ? " cur" : ""}`}
                  aria-pressed={v.version === chosen.version}
                  onClick={() => onSelect(v.version)}
                >
                  <span class="ver-title">
                    {t("Version", "Versi")} {v.version}
                    {v.version === current.version && (
                      <Pill tone="ok">{t("current", "aktif")}</Pill>
                    )}
                  </span>
                  <small>
                    {v.createdBy} · {relativeTime(v.createdAt, now, lang)}
                  </small>
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div class="versions-main">
          <div class="card compare">
            <div class="compare-head">
              <h2>
                {older
                  ? t(
                      `Version ${current.version} compared with version ${older.version}`,
                      `Versi ${current.version} dibandingkan dengan versi ${older.version}`,
                    )
                  : t("Compare", "Bandingkan")}
              </h2>
              <span class="note">
                {t("Names only, no values shown", "Hanya nama, tanpa nilai")}
              </span>
            </div>
            {!older && (
              <p class="note">
                {t(
                  "Pick an older version in the list to see what changed since then.",
                  "Pilih versi lama di daftar untuk melihat apa yang berubah sejak itu.",
                )}
              </p>
            )}
            {older && rows === null && (
              <p class="note">
                {t(
                  "One of these versions was saved before fingerprints existed, so names can't be compared.",
                  "Salah satu versi ini disimpan sebelum sidik jari ada, jadi nama tidak bisa dibandingkan.",
                )}
              </p>
            )}
            {older && rows !== null && rows.length === 0 && (
              <p class="note">
                {t("No names in either version.", "Tidak ada nama di kedua versi.")}
              </p>
            )}
            {older &&
              rows?.map((r) => (
                <div class="diff-row" key={r.name}>
                  <span class="name">{r.name}</span>
                  <Pill tone={kindTone(r.kind)}>{kindLabel(r.kind)}</Pill>
                </div>
              ))}
          </div>

          {older && (
            <RestoreCard
              name={name}
              from={older.version}
              current={current.version}
              onConflict={onReload}
            />
          )}
        </div>
      </div>
      <InfoBox>
        <Link href={secretHref(name)}>{t("Back to the values", "Kembali ke nilai")}</Link>
      </InfoBox>
    </div>
  );
}

function RestoreCard({
  name,
  from,
  current,
  onConflict,
}: {
  name: string;
  from: number;
  current: number;
  onConflict: () => void;
}) {
  useLang();
  const [, navigate] = useLocation();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [needsReason, setNeedsReason] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const next = current + 1;

  const restore = async (reason?: string) => {
    setBusy(true);
    setError(null);
    try {
      const old = await loadSecret(name, from, reason);
      await saveValues({
        path: name,
        values: old.values,
        currentVersion: current,
        groupKey: old.groupKey,
        keyVersion: old.keyVersion,
      });
      navigate(secretHref(name));
    } catch (err) {
      setBusy(false);
      setConfirming(false);
      if (err instanceof ApiError && err.kind === "reason-required") {
        setNeedsReason(true);
      } else if (secretConflictMessage(err)) {
        setError(secretConflictMessage(err) as string);
      } else if (isConflict(err)) {
        setError(
          t(
            "The secret changed while you were restoring. We reloaded the versions. Nothing was restored.",
            "Secret berubah saat kamu memulihkan. Daftar versi kami muat ulang. Tidak ada yang dipulihkan.",
          ),
        );
        onConflict();
      } else {
        setError(
          t(
            "We couldn't restore it. Nothing was changed.",
            "Tidak bisa dipulihkan. Tidak ada yang berubah.",
          ),
        );
      }
    }
  };

  return (
    <div class="card restore-card">
      <h2>{t(`Bring back version ${from}`, `Pulihkan versi ${from}`)}</h2>
      <p class="restore-text">
        {t(
          `This saves version ${from}'s values as a new version, ${next}. Nothing is deleted. Version ${current} stays in the history.`,
          `Ini menyimpan nilai versi ${from} sebagai versi baru, yaitu ${next}. Tidak ada yang dihapus. Versi ${current} tetap di riwayat.`,
        )}
      </p>
      <WarnBox>
        <b>{t("Careful with old values.", "Hati-hati dengan nilai lama.")}</b>{" "}
        {t(
          "If you changed them because a password leaked, restoring puts the leaked one back.",
          "Jika kamu menggantinya karena password bocor, memulihkan akan mengembalikan yang bocor.",
        )}
      </WarnBox>
      {error && (
        <p class="field-error" role="alert">
          {error}
        </p>
      )}
      {needsReason ? (
        <ReasonForm
          onSubmit={(reason) => {
            setNeedsReason(false);
            void restore(reason);
          }}
        />
      ) : confirming ? (
        <div class="row-actions">
          <button
            type="button"
            class="btn ghost"
            onClick={() => setConfirming(false)}
            disabled={busy}
          >
            {t("Cancel", "Batal")}
          </button>
          <button type="button" class="btn" onClick={() => void restore()} disabled={busy}>
            {t(`Yes, save as version ${next}`, `Ya, simpan sebagai versi ${next}`)}
          </button>
        </div>
      ) : (
        <div class="row-actions">
          <button type="button" class="btn" onClick={() => setConfirming(true)} disabled={busy}>
            {t(
              `Restore version ${from} as version ${next}`,
              `Pulihkan versi ${from} sebagai versi ${next}`,
            )}
          </button>
        </div>
      )}
    </div>
  );
}

function kindLabel(kind: DiffKind): string {
  switch (kind) {
    case "added":
      return t("Added", "Ditambah");
    case "changed":
      return t("Changed", "Diubah");
    case "removed":
      return t("Removed", "Dihapus");
    case "same":
      return t("Same", "Sama");
  }
}

function kindTone(kind: DiffKind): "add" | "chg" | "rem" | "" {
  switch (kind) {
    case "added":
      return "add";
    case "changed":
      return "chg";
    case "removed":
      return "rem";
    case "same":
      return "";
  }
}
