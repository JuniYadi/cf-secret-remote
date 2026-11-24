// @vitest-environment happy-dom

import type { VNode } from "preact";
import { render } from "preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setLang } from "../lib/i18n.ts";
import { routeFetch } from "../test/route-fetch.ts";
import { CollectionDetailPage, CollectionNewPage, CollectionsPage } from "./Collections.tsx";

// ADR 36 screens, rendered against a fake API. Checks what a person sees and what the screen sends. Never a value.

let host: HTMLElement;
const flush = async () => {
  for (let i = 0; i < 6; i++) await new Promise((r) => setTimeout(r, 5));
};
const text = () => host.textContent ?? "";
async function mount(v: VNode) {
  render(v, host);
  await flush();
}

beforeEach(() => {
  host = document.createElement("div");
  document.body.appendChild(host);
  setLang("en", undefined);
  window.history.replaceState(null, "", "/");
});
afterEach(() => {
  render(null, host);
  host.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const summary = { name: "myapp", revision: 2, updatedAt: 1, envCount: 2, keyCount: 2 };
const definition = {
  name: "myapp",
  revision: 2,
  createdAt: 1,
  updatedAt: 1,
  envs: [
    { label: "dev", path: "myapp/dev" },
    { label: "prod", path: "myapp/prod" },
  ],
  keys: [
    { name: "API_KEY", description: "payments" },
    { name: "DATABASE_URL", description: null },
  ],
};
const compare = {
  name: "myapp",
  revision: 2,
  observedAt: 1,
  result: "incomplete",
  envs: [
    {
      label: "dev",
      path: "myapp/dev",
      status: "ok",
      version: 3,
      present: ["API_KEY"],
      missing: [],
      extra: ["EXTRA_FLAG"],
    },
    { label: "prod", path: "myapp/prod", status: "inaccessible" },
  ],
};

describe("Collections list", () => {
  it("lists the readable collections with their counts, and nothing else", async () => {
    vi.stubGlobal("fetch", routeFetch({ "GET /collections": { body: [summary] } }).fn);
    await mount(<CollectionsPage />);
    expect(text()).toContain("myapp");
    expect(text()).toContain("New collection");
  });

  it("explains the empty state", async () => {
    vi.stubGlobal("fetch", routeFetch({ "GET /collections": { body: [] } }).fn);
    await mount(<CollectionsPage />);
    expect(text()).toContain("No collections you can see yet");
  });
});

describe("Collection detail", () => {
  it("says incomplete, never clean, when an environment cannot be read", async () => {
    vi.stubGlobal(
      "fetch",
      routeFetch({
        "GET /collections/myapp": { body: definition },
        "GET /collections/myapp/compare": { body: compare },
      }).fn,
    );
    await mount(<CollectionDetailPage name="myapp" />);
    expect(text()).toContain("Incomplete");
    expect(text()).toContain("You cannot see this environment");
    expect(text()).toContain("EXTRA_FLAG");
    expect(text()).not.toContain("Clean");
    // Stored values are never part of a detail page.
    expect(text()).not.toMatch(/v1\./);
  });

  it("explains that deleting the declaration keeps every stored value", async () => {
    vi.stubGlobal(
      "fetch",
      routeFetch({
        "GET /collections/myapp": { body: definition },
        "GET /collections/myapp/compare": { body: compare },
      }).fn,
    );
    await mount(<CollectionDetailPage name="myapp" />);
    const del = Array.from(host.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Delete declaration"),
    );
    expect(del).toBeTruthy();
    del?.click();
    await flush();
    expect(text()).toContain("Stored values in every environment are kept");
  });
});

describe("New collection form", () => {
  it("previews before it saves, then creates with exactly the reviewed body", async () => {
    const routes = routeFetch({
      "POST /collections/preview": {
        body: {
          name: "newapp",
          exists: false,
          revision: null,
          changes: {
            addedKeys: ["A"],
            removedKeys: [],
            changedKeys: [],
            addedEnvs: [],
            removedEnvs: [],
            changedEnvs: [],
          },
          envs: [{ label: "dev", path: "newapp/dev", status: "missing_path" }],
        },
      },
      "POST /collections": { status: 201, body: { name: "newapp", revision: 1 } },
    });
    vi.stubGlobal("fetch", routes.fn);
    await mount(<CollectionNewPage />);

    const set = (id: string, value: string) => {
      const el = host.querySelector(`#${id}`) as HTMLInputElement;
      el.value = value;
      el.dispatchEvent(new Event("input", { bubbles: true }));
    };
    set("collection-name", "newapp");
    set("env-label-0", "dev");
    set("env-path-0", "newapp/dev");
    const addKey = Array.from(host.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Add key"),
    );
    addKey?.click();
    await flush();
    set("key-name-0", "A");
    await flush();

    const save = () => host.querySelector("form button[type=submit]") as HTMLButtonElement;
    expect(save().disabled).toBe(true);

    const preview = Array.from(host.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Preview changes"),
    );
    preview?.click();
    await flush();
    expect(routes.to("POST /collections/preview")).toHaveLength(1);
    expect(text()).toContain("This will be a new collection.");
    expect(text()).toContain("+ key A");
    expect(text()).toContain("does not exist yet");
    expect(save().disabled).toBe(false);

    save().click();
    await flush();
    const created = routes.to("POST /collections");
    expect(created).toHaveLength(1);
    expect(created[0]?.body).toEqual({
      name: "newapp",
      envs: [{ label: "dev", path: "newapp/dev" }],
      keys: [{ name: "A", description: null }],
    });
  });
});
