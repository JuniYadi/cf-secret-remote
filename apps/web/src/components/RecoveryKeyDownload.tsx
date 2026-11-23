import { t } from "../lib/i18n.ts";

/** Downloads the recovery phrase locally; it is never sent to the server. */
export function RecoveryKeyDownload({ phrase }: { phrase: string | null }) {
  function download() {
    if (!phrase) return;
    const explanation = t(
      "Recovery key: keep these words safe. Anyone with them can open your vault.",
      "Kunci pemulihan: simpan kata ini dengan aman. Siapa pun yang memilikinya bisa membuka vault-mu.",
    );
    const url = URL.createObjectURL(
      new Blob([`${explanation}\n\n${phrase}\n`], { type: "text/plain" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `cfs-recovery-key-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(link);
    try {
      link.click();
    } finally {
      link.remove();
      URL.revokeObjectURL(url);
    }
  }

  return (
    <button type="button" class="btn ghost sm" onClick={download} disabled={!phrase}>
      {t("Download as a file", "Unduh sebagai file")}
    </button>
  );
}
