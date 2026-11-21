import { Link } from "wouter-preact";

export interface TabItem {
  href: string;
  label: string;
}

/** The tab row of a section page. The current tab is marked with aria-current, not colour alone. */
export function Tabs({
  items,
  current,
  label,
}: {
  items: TabItem[];
  current: string;
  label: string;
}) {
  return (
    <nav class="tabs" aria-label={label}>
      {items.map((item) => {
        const on = item.href === current;
        return (
          <Link
            key={item.href}
            href={item.href}
            class={on ? "on" : ""}
            aria-current={on ? "page" : undefined}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
