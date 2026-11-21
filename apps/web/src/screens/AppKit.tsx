import { useEffect, useState } from "preact/hooks";
import { Link } from "wouter-preact";
import { failureText, LoadStatus, Notice, Pill, useLoad } from "../components/Admin.tsx";
import { PageTitle } from "../components/shared.tsx";
import { api } from "../lib/api.ts";
import { type HeldKit, kitFileName, takeKit } from "../lib/apps.ts";
import { useLang } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import { appPath, pageCrumbs } from "../routes.ts";
import "../styles/admin.css";

/** How long a copied kit stays on the clipboard before it is cleared, where the browser allows (ADR 24). */
export const CLIPBOARD_CLEAR_MS = 30_000;
/** How often the page asks whether the bot has signed in yet. */
export const FIRST_LOGIN_POLL_MS = 5_000;

type Where = "gh" | "srv" | "ai" | "me";
const WHERES: readonly Where[] = ["gh", "srv", "ai", "me"];

interface Guide {
  steps: string[];
  snippet: string;
}

function guideFor(where: Where, appName: string): Guide {
  switch (where) {
    case "gh":
      return {
        steps: [
          t(
            "Open your repository, then Settings, Secrets and variables, Actions, New repository secret.",
            "Buka repositori, lalu Settings, Secrets and variables, Actions, New repository secret.",
          ),
          t(
            "Name it CFS_KIT and paste the kit as the value.",
            "Beri nama CFS_KIT dan tempel kit sebagai nilainya.",
          ),
          t(
            "In your workflow, pass it in and run your command through cfs.",
            "Di workflow, teruskan kit itu dan jalankan perintahmu lewat cfs.",
          ),
        ],
        snippet:
          "jobs:\n  billing:\n    runs-on: ubuntu-latest\n    env:\n      CFS_KIT: ${{ secrets.CFS_KIT }}\n    steps:\n      - uses: actions/checkout@v4\n      - run: cfs run -- node job.js",
      };
    case "srv":
      return {
        steps: [
          t(
            "Add CFS_KIT as an environment variable where your service starts: Docker, systemd, or your host's dashboard.",
            "Tambahkan CFS_KIT sebagai environment variable tempat layananmu dijalankan: Docker, systemd, atau dashboard hosting.",
          ),
          t(
            "Install cfs on that machine, or inside your image.",
            "Pasang cfs di mesin itu, atau di dalam image-mu.",
          ),
          t("Start your app through cfs.", "Jalankan aplikasimu lewat cfs."),
        ],
        snippet: "docker run -e CFS_KIT myorg/billing \\\n  cfs run -- node server.js",
      };
    case "ai":
      return {
        steps: [
          t(
            "Put CFS_KIT in the environment of the process that runs the agent. Never in its prompt or files.",
            "Taruh CFS_KIT di environment proses yang menjalankan agen. Jangan di prompt atau file-nya.",
          ),
          t(
            "Start the local helper next to the agent.",
            "Jalankan pembantu lokal di samping agen.",
          ),
          t(
            "Tell the agent to call the helper's address instead of the real website. The helper adds the key.",
            "Suruh agen memanggil alamat pembantu, bukan situs aslinya. Pembantu yang menambahkan key.",
          ),
        ],
        snippet: `$ export CFS_KIT=cfskit1_...\n$ cfs proxy --agent ${appName}\n\n# the agent now calls:\nhttp://127.0.0.1:8787/stripe/v1/charges`,
      };
    case "me":
      return {
        steps: [
          t("Run these two commands in your terminal.", "Jalankan dua perintah ini di terminalmu."),
          t("This signs in as the bot, not as you.", "Ini masuk sebagai bot, bukan sebagai kamu."),
          t(
            "Close the terminal when you're done. Nothing is saved.",
            "Tutup terminal setelah selesai. Tidak ada yang tersimpan.",
          ),
        ],
        snippet: "$ export CFS_KIT=cfskit1_...\n$ cfs run backend/payments/dev -- env",
      };
  }
}

function whereLabel(where: Where): string {
  switch (where) {
    case "gh":
      return "GitHub Actions";
    case "srv":
      return t("Server or Docker", "Server atau Docker");
    case "ai":
      return t("AI agent", "Agen AI");
    case "me":
      return t("My laptop (test)", "Laptop saya (uji)");
  }
}

/**
 * Kit ready. The kit is in memory only: it is taken once from the create flow, and a reload shows that it is gone.
 * The first-sign-in check polls the app until the bot has signed in (DESIGN.md, "Access kit").
 */
export function AppKitPage({ id }: { id: string }) {
  useLang();
  const [held] = useState<HeldKit | null>(() => takeKit(id));
  const app = useLoad(() => api.app(id), `kit-app:${id}`);
  const [where, setWhere] = useState<Where>("gh");
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const [waiting, setWaiting] = useState<boolean | null>(null);

  // Ask until the first sign-in is seen, then stop. The timer is cleared when the page is left.
  useEffect(() => {
    if (held === null) return;
    let live = true;
    let timer: ReturnType<typeof setInterval> | undefined;
    const stop = () => {
      if (timer !== undefined) clearInterval(timer);
      timer = undefined;
    };
    const check = async () => {
      try {
        const a = await api.app(id);
        if (!live) return;
        setWaiting(a.waiting);
        if (!a.waiting) stop();
      } catch {
        // A failed check is retried on the next tick. Nothing is shown for it.
      }
    };
    void check();
    timer = setInterval(() => void check(), FIRST_LOGIN_POLL_MS);
    return () => {
      live = false;
      stop();
    };
  }, [id, held]);

  // Without a held kit (after a reload) the name comes from the app itself.
  const name = held?.name ?? app.data?.name ?? "";

  async function copy() {
    if (held === null) return;
    setCopyFailed(false);
    try {
      await navigator.clipboard.writeText(held.kit);
      setCopied(true);
      // Clear it after 30 seconds. Some browsers refuse this, which is fine: the copy is still there.
      setTimeout(() => {
        navigator.clipboard?.writeText("").catch(() => undefined);
      }, CLIPBOARD_CLEAR_MS);
    } catch {
      setCopied(false);
      setCopyFailed(true);
    }
  }

  function download() {
    if (held === null) return;
    const blob = new Blob([`${held.kit}\n`], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = kitFileName(held.name);
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  if (held === null) {
    return (
      <div class="page">
        <PageTitle crumbs={pageCrumbs("appKit", name)} />
        <Notice
          tone="warn"
          title={t("This kit was shown once.", "Kit ini sudah ditampilkan sekali.")}
        >
          {t(
            "It isn't kept anywhere, so it can't be shown again. To get a working kit, paste the one you saved on the app page, or make a new app.",
            "Kit tidak disimpan di mana pun, jadi tidak bisa ditampilkan lagi. Untuk kit yang bisa dipakai, tempel kit yang kamu simpan di halaman aplikasi, atau buat aplikasi baru.",
          )}
        </Notice>
        <LoadStatus state={app} />
        <div class="form-foot">
          <Link class="btn" href={appPath(id)}>
            {t("Back to app", "Kembali ke aplikasi")}
          </Link>
        </div>
      </div>
    );
  }

  const guide = guideFor(where, held.name);
  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("appKit", held.name)} />
      <p class="sub page-sub">
        {t(
          "Copy its kit and put it where the bot runs. The kit is how the bot signs in.",
          "Salin kitnya dan taruh di tempat bot berjalan. Kit adalah cara bot masuk.",
        )}
      </p>

      {held.problems.length > 0 && (
        <Notice tone="warn" title={t("Not everything was set up.", "Belum semuanya diatur.")}>
          <ul class="plain-list">
            {held.problems.map((p) => (
              <li key={`${p.step}-${p.target}`}>
                {p.step === "group"
                  ? t(
                      `Not added to the group ${p.target}. Add it from that group's page.`,
                      `Belum ditambahkan ke grup ${p.target}. Tambahkan dari halaman grup itu.`,
                    )
                  : t(
                      "The permission set wasn't given. Assign it from Permissions.",
                      "Set izin belum diberikan. Berikan dari Izin.",
                    )}
              </li>
            ))}
          </ul>
        </Notice>
      )}

      <section class="card kit-card" aria-labelledby="kit-title">
        <div class="row-between">
          <h2 id="kit-title">{t("Copy your kit", "Salin kitmu")}</h2>
          <Pill tone="warn">{t("Shown once", "Sekali tampil")}</Pill>
        </div>
        <pre class="kit-text">{held.kit}</pre>
        <div class="actions">
          <button type="button" class="btn" onClick={copy}>
            {t("Copy kit", "Salin kit")}
          </button>
          <button type="button" class="btn ghost" onClick={download}>
            {t("Download as file", "Unduh sebagai file")}
          </button>
          <span class="note" role="status">
            {copied &&
              t(
                "Copied. It clears from the clipboard in 30 seconds.",
                "Tersalin. Hilang dari clipboard dalam 30 detik.",
              )}
            {copyFailed &&
              t(
                "Your browser blocked copying. Select the kit and copy it by hand.",
                "Browsermu memblokir penyalinan. Pilih kit lalu salin manual.",
              )}
          </span>
        </div>
        <Notice
          tone="warn"
          title={t("You can't see this again.", "Kamu tidak bisa melihat ini lagi.")}
        >
          {t(
            "If it's lost, issue a new kit and give the bot access again. We can't recover it.",
            "Kalau hilang, terbitkan kit baru dan beri bot akses lagi. Kami tidak bisa memulihkannya.",
          )}
        </Notice>
      </section>

      <section class="card" aria-labelledby="where-title">
        <div class="where-head">
          <h2 id="where-title">
            {t("Put the kit where the bot runs", "Taruh kit di tempat bot berjalan")}
          </h2>
          <p class="note">
            {t(
              "Pick where this bot will run. The kit goes in as a secret called CFS_KIT.",
              "Pilih tempat bot ini berjalan. Kit dimasukkan sebagai secret bernama CFS_KIT.",
            )}
          </p>
        </div>
        <div class="tabs" role="tablist" aria-label={t("Where it runs", "Tempat berjalan")}>
          {WHERES.map((w) => (
            <button
              key={w}
              type="button"
              role="tab"
              id={`where-tab-${w}`}
              aria-selected={w === where}
              aria-controls="where-panel"
              tabIndex={w === where ? 0 : -1}
              class={w === where ? "on" : ""}
              onClick={() => setWhere(w)}
            >
              {whereLabel(w)}
            </button>
          ))}
        </div>
        <div
          class="where-body"
          role="tabpanel"
          id="where-panel"
          aria-labelledby={`where-tab-${where}`}
        >
          <ol class="plain-steps">
            {guide.steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <pre class="code-block">{guide.snippet}</pre>
        </div>
      </section>

      <div class="cols">
        <section class="card col-main" aria-labelledby="check-title">
          <div class="row-between">
            <h2 id="check-title">{t("Check that it works", "Cek bahwa berhasil")}</h2>
            {waiting === false ? (
              <Pill tone="ok">{t("Signed in", "Sudah masuk")}</Pill>
            ) : (
              <Pill tone="warn">{t("Waiting for first sign-in…", "Menunggu masuk pertama…")}</Pill>
            )}
          </div>
          <p class="note">
            {t(
              "Run this on the bot's machine. When the bot signs in for the first time, this turns green.",
              "Jalankan ini di mesin bot. Saat bot masuk untuk pertama kali, status ini berubah hijau.",
            )}
          </p>
          <pre class="code-block">{`$ cfs whoami\n${held.name} · AI agent · signed in`}</pre>
          <p class="note">
            {t(
              "Nothing happens? Check that CFS_KIT is set and that the kit hasn't expired.",
              "Tidak terjadi apa-apa? Periksa bahwa CFS_KIT sudah diisi dan kit belum kedaluwarsa.",
            )}
          </p>
        </section>
        <div class="form-foot col-side">
          <Link class="btn" href={appPath(id)}>
            {t("Done", "Selesai")}
          </Link>
        </div>
      </div>
      {app.error !== null && <Notice tone="danger">{failureText(app.error)}</Notice>}
    </div>
  );
}
