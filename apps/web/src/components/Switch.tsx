import { t } from "../lib/i18n.ts";

/**
 * An on/off switch. It is a button with role "switch", so screen readers get the name and the state, and the
 * words "On" and "Off" are printed, so the state is not shown by colour alone.
 */
export function Switch({
  label,
  checked,
  onChange,
  disabled = false,
}: {
  label: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked ? "true" : "false"}
      aria-label={label}
      class={`sw${checked ? " on" : ""}`}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <i aria-hidden="true" />
      <span>{checked ? t("On", "Aktif") : t("Off", "Mati")}</span>
    </button>
  );
}
