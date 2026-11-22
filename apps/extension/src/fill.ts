import { sameLoginOrigin } from "@cfs/core";

export function eligibleOrigin(page: string, login: string): boolean {
  try {
    const url = new URL(page);
    return (
      (url.protocol === "https:" ||
        (url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) &&
      sameLoginOrigin(page, login)
    );
  } catch {
    return false;
  }
}

/** Runs only in the top frame, rechecking the origin after the audit request. */
export function fillPage(expectedOrigin: string, username: string, password: string): number {
  if (window.top !== window || location.origin !== expectedOrigin) return 0;
  const visible = (input: HTMLInputElement) => {
    if (
      input.disabled ||
      input.readOnly ||
      input.type === "hidden" ||
      input.getClientRects().length === 0
    )
      return false;
    let element: HTMLElement | null = input;
    while (element) {
      const style = getComputedStyle(element);
      if (
        style.display === "none" ||
        style.visibility !== "visible" ||
        Number(style.opacity) === 0 ||
        element.hidden
      )
        return false;
      element = element.parentElement;
    }
    const rect = input.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  const fields = Array.from(document.querySelectorAll("input")).filter(visible);
  const pass = fields.find((input) => input.type === "password");
  if (!pass) return 0;
  const formFields = fields.filter((input) => input.form === pass.form);
  const user =
    formFields.find((input) => input.autocomplete === "username") ??
    formFields.find((input) => ["text", "email"].includes(input.type));
  const set = (input: HTMLInputElement, value: string) => {
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };
  if (user) set(user, username);
  set(pass, password);
  return user ? 2 : 1;
}
