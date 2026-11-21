import type { ComponentChildren } from "preact";
import { useEffect } from "preact/hooks";
import { Link } from "wouter-preact";
import { useLang } from "../lib/hooks.ts";
import { type Lang, setLang, t } from "../lib/i18n.ts";
import type { Crumb } from "../routes.ts";

/** The cfs mark (the bold key from design/brand, DESIGN.md "Merek"). Decorative: the name sits next to it. */
export function Mark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <g transform="translate(1.1 -1.7)">
        <circle cx="17" cy="32" r="10" fill="none" stroke="#fff" stroke-width="7" />
        <circle cx="40" cy="32" r="5.2" fill="#fff" />
        <circle cx="53" cy="32" r="5.2" fill="#fff" />
        <circle cx="53" cy="45" r="4" fill="#fff" />
      </g>
    </svg>
  );
}

const ICON_PATHS = {
  secrets:
    "M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3",
  groups:
    "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M23 21v-2a4 4 0 0 0-3-3.9 M16 3.1a4 4 0 0 1 0 7.8",
  permissions: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  apps: "M4 17l6-6-6-6 M12 19h8",
  activity: "M8 6h13 M8 12h13 M8 18h13 M3 6h.01 M3 12h.01 M3 18h.01",
  settings: "M4 21v-7 M4 10V3 M12 21v-9 M12 8V3 M20 21v-5 M20 12V3 M1 14h6 M9 8h6 M17 16h6",
  lock: "M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4",
  warning:
    "M12 9v4 M12 17h.01 M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  check: "M20 6L9 17l-5-5",
  clock: "M12 6v6l4 2 M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z",
} as const;

export type IconName = keyof typeof ICON_PATHS;

export function Icon({ name, size = 17 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={ICON_PATHS[name]} />
    </svg>
  );
}

/** Two buttons, EN and ID, as in the design boards. The choice is saved (i18n.ts). */
export function LangToggle() {
  const lang = useLang();
  const choose = (next: Lang) => () => setLang(next);
  return (
    <fieldset class="lang" aria-label="Language">
      <button
        type="button"
        aria-pressed={lang === "en"}
        class={lang === "en" ? "on" : ""}
        onClick={choose("en")}
      >
        EN
      </button>
      <button
        type="button"
        aria-pressed={lang === "id"}
        class={lang === "id" ? "on" : ""}
        onClick={choose("id")}
      >
        ID
      </button>
    </fieldset>
  );
}

/**
 * The page heading. Renders the breadcrumb when there is more than one crumb, and sets the document
 * title to the last crumb, which is the h1 (DESIGN.md title rules).
 */
export function PageTitle({ crumbs }: { crumbs: Crumb[] }) {
  const title = crumbs[crumbs.length - 1]?.label ?? "cfs";
  useEffect(() => {
    document.title = title;
  }, [title]);
  const parents = crumbs.slice(0, -1);
  return (
    <>
      {parents.length > 0 && (
        <nav aria-label={t("Breadcrumb", "Jejak")} class="crumbs">
          <ol>
            {parents.map((c) => (
              <li key={c.label}>{c.href ? <Link href={c.href}>{c.label}</Link> : c.label}</li>
            ))}
            <li aria-current="page">{title}</li>
          </ol>
        </nav>
      )}
      <h1>{title}</h1>
    </>
  );
}

/** The logo and name, as on the design boards. */
export function BrandRow({ size = 32 }: { size?: number }) {
  return (
    <div class="brand-row">
      <span class="logo">
        <Mark size={size - 4} />
      </span>
      <span class="brand-name">cfs</span>
    </div>
  );
}

/** A centered single-task card on the plain background (unlock, session ended, help pages). */
export function Standalone({ children }: { children: ComponentChildren }) {
  return (
    <div class="standalone">
      <div class="standalone-top">
        <BrandRow />
        <LangToggle />
      </div>
      <div class="standalone-body">
        <div class="standalone-col">{children}</div>
      </div>
    </div>
  );
}
