// @vitest-environment happy-dom
import {
  generateKeyPair,
  newGroupKey,
  openSecret,
  sealSecret,
  type Values,
  wrapGroupKey,
} from "@cfs/core";
import { render } from "preact";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearImportDraft, setImportDraft } from "../lib/import-draft.ts";
import { lock, unlock } from "../lib/keystore.ts";
import { resetSessionForTests } from "../lib/session.ts";
import { SecretDetailPage } from "./SecretDetail.tsx";
import { SecretEditPage } from "./SecretEdit.tsx";
import { SecretHistoryPage } from "./SecretHistory.tsx";
import { SecretImportReviewPage } from "./SecretImportReview.tsx";
import { SecretsListPage } from "./SecretsList.tsx";
import { SecretVersionsPage } from "./SecretVersions.tsx";

// Each screen is rendered with a fake API. Crypto is real: values are sealed with @cfs/core and opened
// by the screen the way it does in the browser, so the tests cover the whole path.

const PREFIX = "myapp";
const SECRET = "sk_live_PLAINTEXT_MARKER_42";

interface Stored {
  path: string;
  version: number;
  keyringVersion: number;
  names: string[];
  wrappedDek: string;
  ciphertext: string;
  createdAt: number;
  fps?: Record<string, string>;
  createdBy?: string;
}

interface World {
  groupKey: Uint8Array;
  wrappedKey: string;
  publicKey: string;
  privateKey: string;
  list: {
    path: string;
    version: number;
    updatedAt: number;
    names: string[];
    meta: Record<string, string>;
  }[];
  current: Stored | null;
  versions: Stored[];
  keyStatus: number;
  putStatus: number;
  puts: Record<string, unknown>[];
  gets: number;
  history: Record<string, unknown> | null;
}

let world: World;

async function seal(
  path: string,
  version: number,
  values: Values,
  fps?: Record<string, string>,
): Promise<Stored> {
  const sealed = await sealSecret(world.groupKey, path, version, values);
  return {
    path,
    version,
    keyringVersion: 1,
    names: Object.keys(values),
    wrappedDek: sealed.wrappedDek,
    ciphertext: sealed.ciphertext,
    createdAt: 1,
    fps,
    createdBy: "alice@myorg.com",
  };
}

async function world0(): Promise<World> {
  const pair = await generateKeyPair();
  const groupKey = await newGroupKey();
  const wrappedKey = await wrapGroupKey(groupKey, pair.publicKey, PREFIX, 1);
  return {
    groupKey,
    wrappedKey,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    list: [],
    current: null,
    versions: [],
    keyStatus: 200,
    putStatus: 200,
    puts: [],
    gets: 0,
    history: null,
  };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** The fake API. Each route answers from `world`. */
function serve() {
  const fetchMock = vi.fn(async (input: string, init: RequestInit = {}) => {
    const url = new URL(input, "https://cfs.test");
    const method = init.method ?? "GET";
    const p = url.pathname;
    if (p === "/api/v1/secrets" && method === "GET") return json(200, world.list);
    if (p === "/api/v1/secret" && method === "GET") {
      world.gets++;
      const want = url.searchParams.get("version");
      if (want !== null) {
        const v = world.versions.find((x) => x.version === Number(want));
        return v ? json(200, v) : json(404, { error: "not found" });
      }
      return world.current ? json(200, world.current) : json(404, { error: "not found" });
    }
    if (p === "/api/v1/secret" && method === "PUT") {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      world.puts.push(body);
      if (world.putStatus !== 200) return json(world.putStatus, { error: "version changed" });
      return json(200, { path: body.path, version: body.version });
    }
    if (p === "/api/v1/secret/versions") return json(200, world.versions);
    if (p === "/api/v1/secret/history") return json(200, world.history ?? {});
    if (p === `/api/v1/keyrings/${PREFIX}/key`) {
      return world.keyStatus === 200
        ? json(200, { wrappedKey: world.wrappedKey, version: 1 })
        : json(world.keyStatus, { error: "no key for you in this group" });
    }
    return json(500, {});
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

let host: HTMLElement;

/** Waits until the screen has finished loading (effects run after a frame, and the decrypt is async). */
const flush = async () => {
  for (let i = 0; i < 300; i++) {
    await new Promise((r) => setTimeout(r, 10));
    if (i >= 5 && !/Loading/.test(text())) return;
  }
};

const text = () => host.textContent ?? "";
const button = (label: string) =>
  Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.trim() === label) ?? null;
const input = (selector: string) => host.querySelector<HTMLInputElement>(selector);

/** Types into a field and lets Preact render the change, as a person's next click would come after it. */
async function type(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 10));
}

beforeEach(async () => {
  host = document.createElement("div");
  document.body.appendChild(host);
  lock();
  resetSessionForTests();
  clearImportDraft();
  world = await world0();
  unlock({ publicKey: world.publicKey, privateKey: world.privateKey });
});

afterEach(() => {
  render(null, host);
  host.remove();
  lock();
  clearImportDraft();
  if (vi.isFakeTimers()) {
    // Preact queues effects on a timer. Run what is pending before the clock goes back to real time,
    // or the queue stays stuck for the next test.
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
  }
  vi.unstubAllGlobals();
});

describe("secrets list", () => {
  it("shows names, items and owner badges, and never a value", async () => {
    world.list = [
      {
        path: "myapp/dev",
        version: 2,
        updatedAt: 1,
        names: ["A", "B"],
        meta: { owner: "alice@myorg.com", rotateBy: "2020-01-01" },
      },
      { path: "myapp/prod", version: 1, updatedAt: 1, names: ["X"], meta: {} },
    ];
    serve();
    render(<SecretsListPage />, host);
    await flush();
    expect(text()).toContain("myapp/dev");
    expect(text()).toContain("myapp/prod");
    expect(text()).toContain("Owner: alice@myorg.com");
    expect(text()).toContain("Rotation overdue");
    expect(text()).not.toContain(SECRET);
  });

  it("filters by search text", async () => {
    world.list = [
      { path: "myapp/dev", version: 1, updatedAt: 1, names: [], meta: {} },
      { path: "infra/cloudflare", version: 1, updatedAt: 1, names: [], meta: {} },
    ];
    serve();
    render(<SecretsListPage />, host);
    await flush();
    const search = input("#secret-search") as HTMLInputElement;
    await type(search, "infra");
    await flush();
    expect(text()).not.toContain("myapp/dev");
    expect(text()).toContain("infra/cloudflare");
  });

  it("shows the empty state with the three ways to start", async () => {
    serve();
    render(<SecretsListPage />, host);
    await flush();
    expect(text()).toContain("No secrets yet");
    expect(text()).toContain("Import a .env file");
    expect(text()).toContain("Add a secret");
  });
});

describe("secret detail", () => {
  beforeEach(async () => {
    world.current = await seal("myapp/dev", 3, {
      DATABASE_URL: "postgres://x",
      API_KEY: SECRET,
      DEBUG_MODE: "true",
    });
    world.list = [
      {
        path: "myapp/dev",
        version: 3,
        updatedAt: 1,
        names: ["DATABASE_URL", "API_KEY", "DEBUG_MODE"],
        meta: {},
      },
    ];
  });

  it("hides values as dots, shows one on Show, and hides it again after 30 seconds", async () => {
    serve();
    render(<SecretDetailPage name="myapp/dev" />, host);
    await flush();
    expect(text()).toContain("DATABASE_URL");
    expect(text()).not.toContain(SECRET);

    // The 30-second clock starts at Show. Fake timers go on after the (real) decrypt finished.
    vi.useFakeTimers();
    const showButtons = Array.from(host.querySelectorAll("button")).filter(
      (b) => b.textContent === "Show",
    );
    showButtons[1]?.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(text()).toContain(SECRET);

    await vi.advanceTimersByTimeAsync(29_000);
    expect(text()).toContain(SECRET);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(text()).not.toContain(SECRET);
  });

  it("shows the names but locks the values when the person has no key", async () => {
    world.keyStatus = 404;
    serve();
    render(<SecretDetailPage name="myapp/dev" />, host);
    await flush();
    expect(text()).toContain("You're not in this group yet");
    expect(text()).toContain("Locked for you");
    expect(text()).toContain("DATABASE_URL");
    expect(text()).not.toContain(SECRET);
    expect(button("Show")).toBeNull();
  });
});

describe("edit", () => {
  beforeEach(async () => {
    world.current = await seal("myapp/dev", 3, { DEBUG_MODE: "true", MAX: "20", WORD: "007" });
    world.list = [
      {
        path: "myapp/dev",
        version: 3,
        updatedAt: 1,
        names: ["DEBUG_MODE", "MAX", "WORD"],
        meta: {},
      },
    ];
  });

  it("types booleans and numbers in the JSON tab and saves them back as strings", async () => {
    serve();
    render(<SecretEditPage name="myapp/dev" />, host);
    await flush();
    button("JSON")?.click();
    await flush();
    const area = host.querySelector<HTMLTextAreaElement>("#json-text") as HTMLTextAreaElement;
    expect(area.value).toContain('"DEBUG_MODE": true');
    expect(area.value).toContain('"MAX": 20');
    expect(area.value).toContain('"WORD": "007"');

    await type(area, '{"DEBUG_MODE": false, "MAX": 21, "WORD": "007", "NEW": "x"}');
    button("Save as version 4")?.click();
    await flush();

    const put = world.puts[0] as {
      ciphertext: string;
      wrappedDek: string;
      version: number;
      fps: object;
    };
    expect(put.version).toBe(4);
    expect(Object.keys(put.fps)).toEqual(["DEBUG_MODE", "MAX", "WORD", "NEW"]);
    const opened = await openSecret(world.groupKey, "myapp/dev", 4, put.wrappedDek, put.ciphertext);
    expect(opened).toEqual({ DEBUG_MODE: "false", MAX: "21", WORD: "007", NEW: "x" });
  });

  it("never passes a plaintext value to fetch, only sealed envelopes", async () => {
    const fetchMock = serve();
    render(<SecretEditPage name="myapp/dev" />, host);
    await flush();
    const text_ = host.querySelector<HTMLInputElement>(
      'input[aria-label="WORD value"]',
    ) as HTMLInputElement;
    await type(text_, SECRET);
    button("Save as version 4")?.click();
    await flush();
    const bodies = fetchMock.mock.calls.map((c) => String((c[1] as RequestInit).body ?? ""));
    for (const b of bodies) expect(b).not.toContain(SECRET);
    expect(world.puts).toHaveLength(1);
  });

  it("on a version conflict, reloads the secret and tells the person what happened", async () => {
    world.putStatus = 409;
    serve();
    render(<SecretEditPage name="myapp/dev" />, host);
    await flush();
    const gets = world.gets;
    button("Save as version 4")?.click();
    await flush();
    expect(world.puts).toHaveLength(1);
    expect(text()).toContain("Someone else saved a new version while you were editing");
    expect(world.gets).toBeGreaterThan(gets);
  });
});

describe("import review", () => {
  it("shows what will happen to each name without values, then shows a value on Show", async () => {
    world.current = await seal("myapp/dev", 7, {
      DATABASE_URL: "old",
      API_KEY: "keep",
      DEBUG_MODE: "false",
    });
    world.list = [
      {
        path: "myapp/dev",
        version: 7,
        updatedAt: 1,
        names: ["DATABASE_URL", "API_KEY", "DEBUG_MODE"],
        meta: {},
      },
    ];
    setImportDraft({
      source: "env",
      values: { DATABASE_URL: "postgres://new", DEBUG_MODE: "true", FEATURE_BETA: "false" },
      empty: ["EMPTY_VAR"],
      invalid: [],
      errors: [],
      target: { mode: "existing", path: "myapp/dev" },
      strategy: "overwrite",
    });
    serve();
    render(<SecretImportReviewPage />, host);
    await flush();
    expect(text()).toContain("Replaces current");
    expect(text()).toContain("New");
    expect(text()).toContain("Skipped");
    expect(text()).toContain("Save as version 8");
    expect(text()).not.toContain("postgres://new");
    expect(text()).not.toContain(SECRET);

    const show = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Show");
    show?.click();
    await flush();
    expect(text()).toContain("postgres://new");
  });

  it("the merge strategy changes the save preview", async () => {
    world.current = await seal("myapp/dev", 1, { A: "1" });
    world.list = [{ path: "myapp/dev", version: 1, updatedAt: 1, names: ["A"], meta: {} }];
    setImportDraft({
      source: "env",
      values: { A: "2" },
      empty: [],
      invalid: [],
      errors: [],
      target: { mode: "existing", path: "myapp/dev" },
      strategy: "overwrite",
    });
    serve();
    render(<SecretImportReviewPage />, host);
    await flush();
    expect(text()).toContain("Replaces current");
    const keep = host.querySelector<HTMLInputElement>('input[name="strategy"][value="add"]');
    keep?.click();
    await flush();
    expect(text()).toContain("Keeps current");
  });
});

describe("versions", () => {
  it("compares two versions by name only, from their fingerprints", async () => {
    const v2 = await seal(
      "myapp/dev",
      2,
      { A: "1", B: "2" },
      { A: "aaaaaaaaaaaaaaaa", B: "bbbbbbbbbbbbbbbb" },
    );
    const v1 = await seal(
      "myapp/dev",
      1,
      { A: "0", C: "3" },
      { A: "0000000000000000", C: "cccccccccccccccc" },
    );
    world.versions = [v2, v1];
    world.current = v2;
    serve();
    render(<SecretVersionsPage name="myapp/dev" />, host);
    await flush();
    expect(text()).toContain("Version 2 compared with version 1");
    expect(text()).toContain("Changed");
    expect(text()).toContain("Added");
    expect(text()).toContain("Removed");
    expect(text()).toContain("Careful with old values.");
    expect(text()).toContain("Restore version 1 as version 3");
  });

  it("says so when a version has no fingerprints", async () => {
    const v2 = await seal("myapp/dev", 2, { A: "1" }, { A: "aaaaaaaaaaaaaaaa" });
    const v1 = await seal("myapp/dev", 1, { A: "0" });
    world.versions = [v2, v1];
    world.current = v2;
    serve();
    render(<SecretVersionsPage name="myapp/dev" />, host);
    await flush();
    expect(text()).toContain("saved before fingerprints existed");
  });
});

describe("access history", () => {
  it("shows the counts and a warning for people who lost access", async () => {
    world.history = {
      path: "myapp/dev",
      windowDays: 30,
      opens: 38,
      readers: 4,
      lastReader: { who: "Bob", at: 1, version: 7 },
      lostAccess: 1,
      people: [
        { name: "Bob", opens: 12, lastOpened: 1, lastVersion: 7, hasAccess: true },
        { name: "dewi@myorg.com", opens: 2, lastOpened: 1, lastVersion: 6, hasAccess: false },
      ],
    };
    serve();
    render(<SecretHistoryPage name="myapp/dev" />, host);
    await flush();
    expect(text()).toContain("38");
    expect(text()).toContain("Careful with old values.");
    expect(text()).toContain("Removed");
    expect(text()).toContain("Has access");
  });
});
