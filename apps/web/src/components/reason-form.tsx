import { useState } from "preact/hooks";
import { t } from "../lib/i18n.ts";

/** A reason is written to the audit log when the rule requires it; never enter a secret value. */
export function ReasonForm({ onSubmit }: { onSubmit: (reason: string) => void }) {
  const [reason, setReason] = useState("");
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        if (reason.trim()) onSubmit(reason.trim());
      }}
    >
      <label for="secret-reason">
        {t("Why do you need to open this secret?", "Kenapa kamu perlu membuka secret ini?")}
      </label>
      <p class="note">
        {t(
          "This reason is recorded in the activity log. Do not include secret values.",
          "Alasan ini dicatat di log aktivitas. Jangan masukkan nilai secret.",
        )}
      </p>
      <input
        id="secret-reason"
        value={reason}
        maxLength={200}
        onInput={(event) => setReason(event.currentTarget.value)}
      />
      <button type="submit" class="btn" disabled={!reason.trim()}>
        {t("Open secret", "Buka secret")}
      </button>
    </form>
  );
}
