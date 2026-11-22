import type { Login } from "@cfs/core";
import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import {
  getSession,
  json,
  normalizeHost,
  openLogins,
  request,
  type Session,
  sync,
  unlock,
} from "./client.ts";
import { eligibleOrigin, fillPage } from "./fill.ts";
import "./style.css";

function App() {
  const [lang, setLang] = useState<"en" | "id">("en");
  const t = (en: string, id: string) => (lang === "en" ? en : id);
  const [host, setHost] = useState("");
  const [session, setSession] = useState<Session>();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [matches, setMatches] = useState<{ id: string; login: Login }[]>([]);
  useEffect(() => {
    void chrome.storage.local
      .get("host")
      .then((v) => setHost(typeof v.host === "string" ? v.host : ""));
    void getSession().then(setSession);
  }, []);
  useEffect(() => {
    if (!session?.unlockExpires) return;
    const timer = setTimeout(
      () => {
        void getSession().then(setSession);
      },
      Math.max(0, session.unlockExpires - Date.now()),
    );
    return () => clearTimeout(timer);
  }, [session]);
  async function login(event: Event) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const h = normalizeHost(host);
      const granted = await chrome.permissions.request({ origins: [`${h}/*`] });
      if (!granted) throw new Error("Permission denied");
      const old = await chrome.storage.local.get("host");
      if (old.host !== h) {
        await chrome.storage.local.clear();
        await chrome.storage.session.clear();
      }
      await chrome.storage.local.set({ host: h });
      setHost(h);
      const start = (await (
        await request(h, "/cli/start", json({ device: "Chrome", device_type: "extension" }))
      ).json()) as { deviceCode: string; userCode: string; interval: number; expiresIn: number };
      setCode(start.userCode);
      const end = Date.now() + start.expiresIn * 1000;
      while (Date.now() < end) {
        await new Promise((resolve) => setTimeout(resolve, start.interval * 1000));
        const res = await request(h, "/cli/poll", json({ deviceCode: start.deviceCode }));
        if (res.status === 202) continue;
        const result = (await res.json()) as { token: string; expiresIn: number };
        const next = { token: result.token, tokenExpires: Date.now() + result.expiresIn * 1000 };
        await chrome.storage.session.set({ session: next });
        setSession(next);
        setCode("");
        return;
      }
      throw new Error("Code expired");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error");
    } finally {
      setBusy(false);
    }
  }
  async function doUnlock(event: Event) {
    event.preventDefault();
    if (!session) return;
    setBusy(true);
    setError("");
    try {
      setSession(await unlock(host, session, password));
      setPassword("");
    } catch {
      setPassword("");
      setError(
        t(
          "Could not unlock vault or sync logins.",
          "Tidak dapat membuka vault atau menyinkronkan login.",
        ),
      );
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    if (!session?.privateKey) {
      setMatches([]);
      return;
    }
    let active = true;
    void (async () => {
      try {
        const current = await getSession();
        if (!current?.privateKey) {
          if (active) setSession(current);
          return;
        }
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) return;
        const items = await openLogins(host, current);
        if (active)
          setMatches(items.filter((item) => eligibleOrigin(tab.url as string, item.login.url)));
      } catch {
        if (active) setError(t("Could not open logins.", "Tidak dapat membuka login."));
      }
    })();
    return () => {
      active = false;
    };
  }, [host, session]);
  async function fill(item: { id: string; login: Login }) {
    setBusy(true);
    setError("");
    try {
      const current = await getSession();
      if (!current?.privateKey) {
        setSession(current);
        throw new Error("Locked");
      }
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id || !tab.url || !eligibleOrigin(tab.url, item.login.url))
        throw new Error("Origin mismatch");
      await request(host, `/logins/${encodeURIComponent(item.id)}/fill`, json({}, current.token));
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [0] },
        func: fillPage,
        args: [new URL(tab.url).origin, item.login.username, item.login.password],
      });
      if (!results[0]?.result) throw new Error("No eligible fields");
      window.close();
    } catch {
      setError(t("Could not fill this page.", "Tidak dapat mengisi halaman ini."));
    } finally {
      setBusy(false);
    }
  }
  async function refresh() {
    if (!session) return;
    setBusy(true);
    try {
      await sync(host, session.token);
      setSession({ ...session });
    } catch {
      setError(t("Refresh failed.", "Penyegaran gagal."));
    } finally {
      setBusy(false);
    }
  }
  async function lock() {
    if (!session) return;
    const next = { token: session.token, tokenExpires: session.tokenExpires };
    await chrome.storage.session.set({ session: next });
    setSession(next);
  }
  return (
    <main>
      <header>
        <h1>cfs</h1>
        <button type="button" onClick={() => setLang(lang === "en" ? "id" : "en")}>
          {lang === "en" ? "ID" : "EN"}
        </button>
      </header>
      {!session ? (
        <form onSubmit={login}>
          <label>
            {t("Worker host", "Host Worker")}
            <input
              required
              type="url"
              value={host}
              onInput={(e) => setHost(e.currentTarget.value)}
              placeholder="https://vault.example.com"
            />
          </label>
          <button type="submit" disabled={busy}>
            {t("Sign in", "Masuk")}
          </button>
          {code && (
            <p>
              {t(
                "Open the approval page and enter this code:",
                "Buka halaman persetujuan dan masukkan kode ini:",
              )}{" "}
              <strong>{code}</strong>{" "}
              <a href={`${host}/cli/authorize`} target="_blank" rel="noreferrer">
                {t("Open", "Buka")}
              </a>
            </p>
          )}
        </form>
      ) : !session.privateKey ? (
        <form onSubmit={doUnlock}>
          <label>
            {t("Vault password", "Kata sandi vault")}
            <input
              type="password"
              required
              value={password}
              onInput={(e) => setPassword(e.currentTarget.value)}
            />
          </label>
          <button type="submit" disabled={busy}>
            {t("Unlock", "Buka kunci")}
          </button>
        </form>
      ) : (
        <>
          <p>{t("Vault unlocked", "Vault terbuka")}</p>
          {matches.length === 0 ? (
            <p>{t("No matching logins.", "Tidak ada login yang cocok.")}</p>
          ) : (
            matches.map((item) => (
              <div key={item.id}>
                <button type="button" disabled={busy} onClick={() => void fill(item)}>
                  {t("Fill", "Isi")} {item.login.name} {item.login.environment} {item.login.role}
                </button>
              </div>
            ))
          )}
          <button type="button" disabled={busy} onClick={() => void refresh()}>
            {t("Refresh", "Segarkan")}
          </button>{" "}
          <button type="button" onClick={() => void lock()}>
            {t("Lock", "Kunci")}
          </button>
        </>
      )}
      {error && <p role="alert">{error}</p>}
    </main>
  );
}
render(<App />, document.getElementById("app") as HTMLElement);
