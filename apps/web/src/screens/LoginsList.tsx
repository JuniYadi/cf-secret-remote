import { useEffect, useState } from "preact/hooks";
import { Link } from "wouter-preact";
import { PageTitle } from "../components/shared.tsx";
import { api, type KeyringRow } from "../lib/api.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import {
  decryptLoginList,
  filterLogins,
  loginClient,
  loginKeyFor,
  type OpenedLogin,
} from "../lib/logins.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/secrets.css";

export function LoginsListPage() {
  useLang();
  const [rows, setRows] = useState<OpenedLogin[] | null>(null);
  const [groups, setGroups] = useState<KeyringRow[]>([]);
  const [personalId, setPersonalId] = useState("");
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [query, setQuery] = useState("");
  const [keyring, setKeyring] = useState("");
  const [environment, setEnvironment] = useState("");
  const [role, setRole] = useState("");
  useEffect(() => {
    let live = true;
    setFailed(false);
    setRows(null);
    Promise.all([loginClient.list(), api.keyrings(), api.personalKeyring()])
      .then(async ([records, nextGroups, personal]) => {
        const opened = await decryptLoginList(records, loginKeyFor);
        if (live) {
          setRows(opened);
          setGroups(nextGroups);
          setPersonalId(personal?.id ?? "");
        }
      })
      .catch(() => {
        if (live) setFailed(true);
      });
    return () => {
      live = false;
    };
  }, [attempt]);
  const options = (values: string[]) => [...new Set(values.filter(Boolean))].sort();
  const shown = rows && filterLogins(rows, { query, keyring, environment, role });
  return (
    <div class="secrets-page">
      <div class="top">
        <PageTitle crumbs={pageCrumbs("logins")} />
        <Link class="btn" href={`${PATHS.logins}/new`}>
          {t("+ New login", "+ Akun baru")}
        </Link>
      </div>
      {failed ? (
        <div class="card center narrow">
          <p role="alert">{t("Could not load logins.", "Akun tidak bisa dimuat.")}</p>
          <button type="button" class="btn" onClick={() => setAttempt((n) => n + 1)}>
            {t("Try again", "Coba lagi")}
          </button>
        </div>
      ) : rows === null ? (
        <p role="status">{t("Loading...", "Memuat...")}</p>
      ) : rows.length === 0 ? (
        <div class="card center">
          <h2>{t("No logins yet", "Belum ada akun")}</h2>
          <p>
            {t("Add your first login to get started.", "Tambahkan akun pertamamu untuk memulai.")}
          </p>
        </div>
      ) : (
        <>
          <div class="field">
            <label for="login-search">{t("Search logins", "Cari akun")}</label>
            <input
              id="login-search"
              type="search"
              value={query}
              onInput={(e) => setQuery(e.currentTarget.value)}
            />
          </div>
          <div class="row-actions">
            <label>
              {t("Keyring", "Gantungan kunci")}{" "}
              <select value={keyring} onChange={(e) => setKeyring(e.currentTarget.value)}>
                <option value="">{t("All", "Semua")}</option>
                {personalId && <option value={personalId}>{t("Personal", "Pribadi")}</option>}
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.prefix}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {t("Environment", "Lingkungan")}{" "}
              <select value={environment} onChange={(e) => setEnvironment(e.currentTarget.value)}>
                <option value="">{t("All", "Semua")}</option>
                {options(rows.map((r) => r.login.environment)).map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
            <label>
              {t("Role", "Peran")}{" "}
              <select value={role} onChange={(e) => setRole(e.currentTarget.value)}>
                <option value="">{t("All", "Semua")}</option>
                {options(rows.map((r) => r.login.role)).map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
          </div>
          <div class="card tw">
            {shown?.length === 0 ? (
              <p role="status">
                {t("No logins match your filters.", "Tidak ada akun yang cocok dengan filter.")}
              </p>
            ) : (
              <table class="tbl">
                <thead>
                  <tr>
                    <th scope="col">{t("Name", "Nama")}</th>
                    <th scope="col">URL</th>
                    <th scope="col">{t("Environment", "Lingkungan")}</th>
                    <th scope="col">{t("Role", "Peran")}</th>
                    <th scope="col">{t("Keyring", "Gantungan kunci")}</th>
                  </tr>
                </thead>
                <tbody>
                  {shown?.map(({ record, login }) => (
                    <tr key={record.id}>
                      <td>
                        <Link href={`${PATHS.logins}/${encodeURIComponent(record.id)}`}>
                          {login.name}
                        </Link>
                      </td>
                      <td>{login.url}</td>
                      <td>{login.environment}</td>
                      <td>{login.role}</td>
                      <td>
                        {record.keyringId === personalId
                          ? t("Personal", "Pribadi")
                          : groups.find((g) => g.id === record.keyringId)?.prefix}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}
