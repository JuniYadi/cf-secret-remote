// User-facing messages for API failures and relative times. The Worker's error text is never shown:
// ApiError keeps only the kind, so a response body cannot leak into the page (lib/api.ts).

import { ApiError } from "./api.ts";
import { t } from "./i18n.ts";

export function messageFor(err: unknown): string {
  if (!(err instanceof ApiError)) {
    return t("Something went wrong. Try again.", "Ada yang salah. Coba lagi.");
  }
  switch (err.kind) {
    case "network":
      return t(
        "We couldn't reach the server. Check your connection and try again.",
        "Kami tidak bisa menghubungi server. Periksa koneksi lalu coba lagi.",
      );
    case "unauthorized":
      return t("Your session ended. Sign in again.", "Sesimu berakhir. Masuk lagi.");
    case "forbidden":
      return t("You don't have access to this.", "Kamu tidak punya akses ke ini.");
    case "not-found":
      return t("We couldn't find that.", "Itu tidak ditemukan.");
    case "conflict":
      return t(
        "This changed while you were looking. Reload and try again.",
        "Ini berubah saat kamu melihatnya. Muat ulang lalu coba lagi.",
      );
    case "rate-limited":
      return t(
        "Too many attempts. Wait a few minutes and try again.",
        "Terlalu banyak percobaan. Tunggu beberapa menit lalu coba lagi.",
      );
    case "unavailable":
      return t(
        "The free daily limit is reached. Try again after 00:00 UTC.",
        "Batas harian paket gratis sudah tercapai. Coba lagi setelah 00:00 UTC.",
      );
    case "invalid":
      return t(
        "The server didn't accept that. Check the form.",
        "Server tidak menerima itu. Periksa formulir.",
      );
    default:
      return t("The server had a problem. Try again.", "Server bermasalah. Coba lagi.");
  }
}

/** A distance in words, such as "1 h 12 min", for a count of seconds. */
export function durationText(seconds: number, lang: "en" | "id"): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h === 0 && m === 0) return lang === "id" ? "kurang dari 1 menit" : "under 1 min";
  if (h === 0) return lang === "id" ? `${m} mnt` : `${m} min`;
  return lang === "id" ? `${h} j ${m} mnt` : `${h} h ${m} min`;
}

/** "in 1 h 12 min" before `untilSec`, or "Ended" once it has passed. Unix seconds. */
export function endsIn(untilSec: number, nowSec: number): string {
  if (untilSec <= nowSec) return t("Ended", "Berakhir");
  return t(
    `in ${durationText(untilSec - nowSec, "en")}`,
    `dalam ${durationText(untilSec - nowSec, "id")}`,
  );
}
