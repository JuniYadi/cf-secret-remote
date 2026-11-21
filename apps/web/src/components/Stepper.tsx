import { t } from "../lib/i18n.ts";

export type SetupStep = 1 | 2 | 3 | 4;

/** Progress through the setup: sign in, vault password, recovery key, done. */
export function Stepper({ current }: { current: SetupStep }) {
  const labels = [
    t("Sign in", "Masuk"),
    t("Vault password", "Vault password"),
    t("Recovery key", "Kunci pemulihan"),
    t("Done", "Selesai"),
  ];
  return (
    <ol class="steps" aria-label={t("Setup progress", "Progres pengaturan")}>
      {labels.map((label, i) => {
        const n = (i + 1) as SetupStep;
        const state = n < current ? "done" : n === current ? "on" : "";
        return (
          <li key={label} class={`step ${state}`} aria-current={n === current ? "step" : undefined}>
            <i aria-hidden="true">{n < current ? "✓" : n}</i>
            <span>{label}</span>
          </li>
        );
      })}
    </ol>
  );
}
