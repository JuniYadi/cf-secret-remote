// A secret's Values tab (ADR 24, DESIGN.md "Riwayat akses"). Values stay as dots until the person presses
// Show, and hide again after 30 seconds. Copy clears the clipboard later (clipboard.ts).
// When the person has no key for the group, the names show and the values stay locked.

import { useEffect, useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import {
  CopyButton,
  InfoBox,
  MASK,
  Pill,
  SecretTabs,
  typeLabel,
  useReveal,
  WarnBox,
} from "../components/secrets-ui.tsx";
import { PageTitle } from "../components/shared.tsx";
import { api, type Meta, type SecretRecord } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import type { OpenedSecret } from "../lib/secret-store.ts";
import {
  groupOf,
  rotationStatus,
  todayIso,
  toEnvText,
  typeOf,
  type ValueType,
} from "../lib/secrets.ts";
import { type SecretState, useSecret } from "../lib/use-secret.ts";
import { PATHS, pageCrumbs, SECRET_TABS, secretHref } from "../routes.ts";

/** Cleartext metadata for one secret, from GET /secrets (GET /secret does not carry it). */
export function useMeta(path: string): Meta {
  const [meta, setMeta] = useState<Meta>({});
  useEffect(() => {
    let live = true;
    api
      .secrets()
      .then((rows) => {
        const row = Array.isArray(rows) ? rows.find((r) => r.path === path) : undefined;
        if (live && row) setMeta(row.meta);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [path]);
  return meta;
}

/** The Values tab for one secret. */
export function SecretDetailPage({ name }: { name: string }) {
  useLang();
  const [, navigate] = useLocation();
  const { state, reload } = useSecret(name);
  const meta = useMeta(name);

  useEffect(() => {
    if (state.status === "denied") navigate(`/denied/${name}`);
  }, [state.status, name, navigate]);

  if (state.status === "loading" || state.status === "denied") {
    return (
      <div class="secrets-page">
        <PageTitle crumbs={pageCrumbs("secretDetail", name)} />
        <p class="sub" role="status">
          {t("Loading...", "Memuat...")}
        </p>
      </div>
    );
  }
  if (state.status === "nokey") return <NoKeyView name={name} record={state.record} />;
  if (state.status === "ready") {
    return <ValuesView name={name} secret={state.secret} meta={meta} />;
  }
  return <SecretProblem name={name} state={state} onRetry={reload} />;
}

export function SecretProblem({
  name,
  state,
  onRetry,
}: {
  name: string;
  state: SecretState;
  onRetry: () => void;
}) {
  useLang();
  const crumbs = pageCrumbs("secretDetail", name);
  const message =
    state.status === "missing"
      ? t(
          "This secret doesn't exist, or it was deleted.",
          "Secret ini tidak ada, atau sudah dihapus.",
        )
      : state.status === "expired"
        ? t(
            "Your access to this group has expired. Ask someone in the group to give you access again.",
            "Aksesmu ke grup ini sudah habis. Minta anggota grup memberimu akses lagi.",
          )
        : t(
            "We couldn't open this secret. Check your connection and try again.",
            "Secret ini tidak bisa dibuka. Periksa koneksi lalu coba lagi.",
          );
  return (
    <div class="secrets-page">
      <PageTitle crumbs={crumbs} />
      <div class="card center narrow">
        <p class="sub">{message}</p>
        {state.status === "error" ? (
          <button type="button" class="btn" onClick={onRetry}>
            {t("Try again", "Coba lagi")}
          </button>
        ) : (
          <Link class="btn ghost" href={PATHS.secrets}>
            {t("Back to Secrets", "Kembali ke Secret")}
          </Link>
        )}
      </div>
    </div>
  );
}

function ValuesView({ name, secret, meta }: { name: string; secret: OpenedSecret; meta: Meta }) {
  useLang();
  const entries = Object.entries(secret.values);
  const rotation = rotationStatus(meta, todayIso());

  return (
    <div class="secrets-page">
      <div class="top">
        <div>
          <PageTitle crumbs={pageCrumbs("secretDetail", name)} />
          <p class="header-pills">
            <Pill tone="acc">
              {t("Group", "Grup")}: {groupOf(name)}
            </Pill>
            <Pill>
              {t("Version", "Versi")} {secret.version} · {t("current", "aktif")}
            </Pill>
            {meta.owner && (
              <Pill>
                {t("Owner", "Pemilik")}: {meta.owner}
              </Pill>
            )}
            {rotation === "overdue" && (
              <Pill tone="warn">{t("Rotation overdue", "Rotasi terlewat")}</Pill>
            )}
            {rotation === "due" && (
              <Pill>
                {t("Rotate by", "Ganti sebelum")} {meta.rotateBy}
              </Pill>
            )}
          </p>
        </div>
        <div class="row-actions">
          <CopyButton
            text={toEnvText(secret.values)}
            label={t("Copy as .env", "Salin sebagai .env")}
          />
          <Link class="btn" href={`${secretHref(name)}${SECRET_TABS.edit}`}>
            {t("Edit", "Ubah")}
          </Link>
        </div>
      </div>

      <SecretTabs name={name} active="values" />

      {entries.length === 0 ? (
        <div class="card center narrow">
          <p class="sub">{t("This secret has no items yet.", "Secret ini belum punya isi.")}</p>
          <Link class="btn" href={`${secretHref(name)}${SECRET_TABS.edit}`}>
            {t("Add items", "Tambah item")}
          </Link>
        </div>
      ) : (
        <div class="card tw">
          <table class="tbl">
            <thead>
              <tr>
                <th scope="col">{t("Name", "Nama")}</th>
                <th scope="col">{t("Value", "Nilai")}</th>
                <th scope="col">{t("Type", "Tipe")}</th>
                <th scope="col">
                  <span class="visually-hidden">{t("Actions", "Aksi")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {entries.map(([key, value]) => (
                <ValueRow key={key} name={key} value={value} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div class="card details-card">
        <details>
          <summary>{t("Use it in the terminal", "Pakai di terminal")}</summary>
          <p class="note">
            {t(
              "Runs your app with these values, without showing them or saving them to a file.",
              "Menjalankan aplikasimu dengan nilai ini, tanpa menampilkannya atau menyimpannya ke file.",
            )}
          </p>
          <div class="code">$ cfs run {name} -- bun run dev</div>
        </details>
      </div>

      <InfoBox>
        {t(
          "“Opened” counts when the locked values are fetched. Your app's use of them is not visible to us.",
          "“Dibuka” dihitung saat nilai terkunci diambil. Pemakaian nilai oleh aplikasimu tidak terlihat oleh kami.",
        )}
      </InfoBox>
    </div>
  );
}

/** One item. Shown values are cleared by the timer in useReveal. */
function ValueRow({ name, value }: { name: string; value: string }) {
  useLang();
  const reveal = useReveal();
  const type: ValueType = typeOf(value);
  return (
    <tr>
      <td class="name">{name}</td>
      <td>
        {reveal.shown ? (
          <span class="clear">{value}</span>
        ) : (
          <span class="mask">
            <span class="visually-hidden">{t("Hidden value", "Nilai tersembunyi")}</span>
            <span aria-hidden="true">{MASK}</span>
          </span>
        )}
        {reveal.shown && (
          <div class="reveal-hint">
            {t("Hides again in 30 seconds", "Tersembunyi lagi dalam 30 detik")}
          </div>
        )}
      </td>
      <td class="tag">{typeLabel(type)}</td>
      <td class="actions">
        {reveal.shown ? (
          <button type="button" class="btn ghost sm" onClick={reveal.hide}>
            {t("Hide", "Sembunyikan")}
          </button>
        ) : (
          <button type="button" class="btn ghost sm" onClick={reveal.show}>
            {t("Show", "Tampilkan")}
          </button>
        )}{" "}
        <CopyButton text={value} label={t("Copy", "Salin")} />
      </td>
    </tr>
  );
}

/** The person is on the list but has no key for the group. Names only, values locked (ADR 2). */
export function NoKeyView({ name, record }: { name: string; record: SecretRecord }) {
  useLang();
  return (
    <div class="secrets-page">
      <div>
        <PageTitle crumbs={pageCrumbs("secretDetail", name)} />
        <p class="header-pills">
          <Pill tone="acc">
            {t("Group", "Grup")}: {groupOf(name)}
          </Pill>
        </p>
      </div>

      <div class="banner-warn" role="status">
        <div>
          <div class="banner-title">
            {t("You're not in this group yet", "Kamu belum ada di grup ini")}
          </div>
          <div class="banner-text">
            {t(
              "You're allowed to see that this secret exists, but only members of its group can open the values. Ask someone to give you access.",
              "Kamu boleh melihat bahwa secret ini ada, tapi hanya anggota grupnya yang bisa membuka nilainya. Minta seseorang memberimu akses.",
            )}
          </div>
        </div>
        <Link class="btn" href={PATHS.groups}>
          {t("Ask for access", "Minta akses")}
        </Link>
      </div>

      <div class="card tw">
        <table class="tbl">
          <thead>
            <tr>
              <th scope="col">{t("Name", "Nama")}</th>
              <th scope="col">{t("Value", "Nilai")}</th>
            </tr>
          </thead>
          <tbody>
            {record.names.map((n) => (
              <tr key={n}>
                <td class="name">{n}</td>
                <td>
                  <span class="locked">{t("Locked for you", "Terkunci untukmu")}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <WarnBox>
        {t(
          "Nothing is shown until someone in the group gives you access.",
          "Tidak ada yang ditampilkan sampai anggota grup memberimu akses.",
        )}
      </WarnBox>
    </div>
  );
}
