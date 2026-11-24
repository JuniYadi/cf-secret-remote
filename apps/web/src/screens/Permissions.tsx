import { useState } from "preact/hooks";
import { Link, useLocation } from "wouter-preact";
import {
  failureText,
  LoadStatus,
  Notice,
  Pill,
  TechDetails,
  useLoad,
} from "../components/Admin.tsx";
import { PageTitle } from "../components/shared.tsx";
import { ApiError, api, type Identity, type PolicyRow, type PolicyRule } from "../lib/api.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import {
  CAPS,
  COLLECTION_CAPS,
  type CollectionRuleDraft,
  capLabel,
  collectionCapLabel,
  collectionGlobError,
  describeRules,
  globError,
  type RuleDraft,
  rulesAsText,
  toCollectionRules,
  toggleCap,
  toRules,
  validatePermissionSet,
} from "../lib/permissions.ts";
import { PATHS, pageCrumbs } from "../routes.ts";
import "../styles/admin.css";

/** Permissions: who can reach what (ADR 5). Permissions do not open values; groups do (see the note). */
export function PermissionsPage() {
  useLang();
  const { me } = useSession();
  const isAdmin = me?.role === "admin";
  const policies = useLoad(() => api.policies(), "policies");

  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("permissions")} />
      <div class="page-head">
        <p class="sub page-sub">
          {t(
            "Choose who can do what. Anything not listed here is blocked.",
            "Pilih siapa boleh melakukan apa. Yang tidak tercantum di sini diblokir.",
          )}
        </p>
        {isAdmin && (
          <div class="actions">
            <Link class="btn ghost" href={PATHS.roleNew}>
              {t("+ New role", "+ Peran baru")}
            </Link>
            <Link class="btn" href={PATHS.permNew}>
              {t("+ New permission set", "+ Set izin baru")}
            </Link>
          </div>
        )}
      </div>

      <Notice tone="info">
        {t(
          "Permissions control who can reach a secret. To open its values, a person must also be in its group.",
          "Izin mengatur siapa yang bisa menjangkau secret. Untuk membuka nilainya, orang itu juga harus ada di grupnya.",
        )}{" "}
        <Link href={PATHS.groups}>{t("Go to Groups", "Buka Grup")}</Link>
      </Notice>

      <LoadStatus state={policies} />
      {policies.data && <PermissionTables policies={policies.data} />}
    </div>
  );
}

/** Two tables from the same data: who holds which set, and what each set allows. */
function PermissionTables({ policies }: { policies: PolicyRow[] }) {
  useLang();
  const byPerson = new Map<
    string,
    { name: string; kind: string; sets: string[]; expiresAt: number | null }
  >();
  for (const p of policies) {
    for (const a of p.assignees) {
      const row = byPerson.get(a.identityId) ?? {
        name: a.name,
        kind: a.kind,
        sets: [],
        expiresAt: null,
      };
      row.sets.push(p.name);
      if (a.expiresAt !== null) row.expiresAt = a.expiresAt;
      byPerson.set(a.identityId, row);
    }
  }
  const people = [...byPerson.values()].sort((a, b) => a.name.localeCompare(b.name));

  return (
    <>
      <section class="card tw" aria-labelledby="who-title">
        <h2 id="who-title" class="table-title">
          {t("Who", "Siapa")}
        </h2>
        {people.length === 0 ? (
          <p class="note table-empty">
            {t("No one has a permission set yet.", "Belum ada orang yang punya set izin.")}
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">{t("Person or bot", "Orang atau bot")}</th>
                <th scope="col">{t("Permission sets", "Set izin")}</th>
              </tr>
            </thead>
            <tbody>
              {people.map((row) => (
                <tr key={row.name}>
                  <td>
                    <span class="strong">{row.name}</span>{" "}
                    {row.kind === "app" && <Pill>{t("App", "Aplikasi")}</Pill>}
                  </td>
                  <td>
                    {row.sets.map((s) => (
                      <Pill key={s} tone="acc">
                        {s}
                      </Pill>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section class="card tw" aria-labelledby="sets-title">
        <h2 id="sets-title" class="table-title">
          {t("Permission sets", "Set izin")}
        </h2>
        {policies.length === 0 ? (
          <p class="note table-empty">{t("No permission sets yet.", "Belum ada set izin.")}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">{t("Name", "Nama")}</th>
                <th scope="col">{t("What it allows", "Yang diizinkan")}</th>
                <th scope="col">{t("Held by", "Dipegang oleh")}</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id}>
                  <td>
                    <span class="strong">{p.name}</span>
                  </td>
                  <td>
                    {describeRules(p.rules).length === 0 ? (
                      <span class="note">{t("Nothing yet", "Belum ada")}</span>
                    ) : (
                      <ul class="rule-list">
                        {describeRules(p.rules).map((line) => (
                          <li key={line}>{line}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td>
                    {p.assignees.length === 0
                      ? t("No one", "Tidak ada")
                      : String(p.assignees.length)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <TechDetails>
        {policies.map((p) => (
          <div key={p.id}>
            # {p.name}
            <br />
            {rulesAsText(p.rules)}
          </div>
        ))}
        {policies.length === 0 && t("No rules yet.", "Belum ada aturan.")}
      </TechDetails>
    </>
  );
}

/** Rows of path and capabilities, shared by the permission-set form. */
function RuleRows({
  rules,
  errors,
  onChange,
  onRemove,
}: {
  rules: RuleDraft[];
  errors: ReturnType<typeof validatePermissionSet>["errors"];
  onChange: (index: number, next: RuleDraft) => void;
  onRemove: (index: number) => void;
}) {
  useLang();
  return (
    <>
      {rules.map((rule, i) => {
        const row = errors.rules[i];
        const pathId = `rule-path-${i}`;
        return (
          <div class="rule-row" key={i}>
            <div class="field">
              <label for={pathId}>{t("Applies to", "Berlaku untuk")}</label>
              <input
                id={pathId}
                type="text"
                value={rule.path}
                onInput={(e) => onChange(i, { ...rule, path: e.currentTarget.value })}
                aria-invalid={row?.path ? "true" : undefined}
                aria-describedby={row?.path ? `${pathId}-err` : undefined}
                placeholder="myapp/*"
                autocomplete="off"
                class="mono-input"
              />
              {row?.path && (
                <span id={`${pathId}-err`} class="field-error" role="alert">
                  {globError(row.path)}
                </span>
              )}
            </div>
            <fieldset class="field fieldset">
              <legend>{t("What they can do", "Apa yang boleh dilakukan")}</legend>
              <div class="cap-toggles">
                {CAPS.map((cap) => {
                  const on = rule.caps.includes(cap);
                  return (
                    <button
                      key={cap}
                      type="button"
                      class={`cap ${on ? "on" : ""}`.trim()}
                      aria-pressed={on}
                      onClick={() => onChange(i, { ...rule, caps: toggleCap(rule.caps, cap) })}
                    >
                      <span aria-hidden="true">{on ? "✓" : ""}</span>
                      {capLabel(cap)}
                    </button>
                  );
                })}
              </div>
              {row?.caps && (
                <span class="field-error" role="alert">
                  {t(
                    "Pick at least one thing this applies to.",
                    "Pilih minimal satu hal yang diizinkan.",
                  )}
                </span>
              )}
            </fieldset>
            {rules.length > 1 && (
              <button type="button" class="link-btn" onClick={() => onRemove(i)}>
                {t("Remove this rule", "Hapus aturan ini")}
                <span class="visually-hidden"> {i + 1}</span>
              </button>
            )}
          </div>
        );
      })}
    </>
  );
}

/** ADR 36: rows for collection rules. A name glob with View or Manage. Separate from path rules. */
function CollectionRuleRows({
  rules,
  errors,
  onChange,
  onRemove,
}: {
  rules: CollectionRuleDraft[];
  errors: ReturnType<typeof validatePermissionSet>["errors"]["collections"];
  onChange: (index: number, next: CollectionRuleDraft) => void;
  onRemove: (index: number) => void;
}) {
  useLang();
  return (
    <>
      {rules.map((rule, i) => {
        const row = errors[i];
        const globId = `collection-rule-${i}`;
        return (
          <div class="rule-row" key={`c${i}`}>
            <div class="field">
              <label for={globId}>{t("Collections", "Koleksi")}</label>
              <input
                id={globId}
                type="text"
                value={rule.collection}
                onInput={(e) => onChange(i, { ...rule, collection: e.currentTarget.value })}
                aria-invalid={row?.collection ? "true" : undefined}
                aria-describedby={row?.collection ? `${globId}-err` : undefined}
                placeholder="myapp*"
                autocomplete="off"
                class="mono-input"
              />
              {row?.collection && (
                <span id={`${globId}-err`} class="field-error" role="alert">
                  {collectionGlobError(row.collection)}
                </span>
              )}
            </div>
            <fieldset class="field fieldset">
              <legend>{t("What they can do", "Apa yang boleh dilakukan")}</legend>
              <div class="cap-toggles">
                {COLLECTION_CAPS.map((cap) => {
                  const on = rule.caps.includes(cap);
                  return (
                    <button
                      key={cap}
                      type="button"
                      class={`cap ${on ? "on" : ""}`.trim()}
                      aria-pressed={on}
                      onClick={() =>
                        onChange(i, {
                          ...rule,
                          caps: on ? rule.caps.filter((c) => c !== cap) : [...rule.caps, cap],
                        })
                      }
                    >
                      <span aria-hidden="true">{on ? "✓" : ""}</span>
                      {collectionCapLabel(cap)}
                    </button>
                  );
                })}
              </div>
              {row?.caps && (
                <span class="field-error" role="alert">
                  {t(
                    "Pick at least one thing this applies to.",
                    "Pilih minimal satu hal yang diizinkan.",
                  )}
                </span>
              )}
            </fieldset>
            <button type="button" class="link-btn" onClick={() => onRemove(i)}>
              {t("Remove this rule", "Hapus aturan ini")}
              <span class="visually-hidden"> {i + 1}</span>
            </button>
          </div>
        );
      })}
    </>
  );
}

/** New permission set (ADR 5): path globs with the capabilities each one grants. Default deny. */
export function PermNewPage() {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const [name, setName] = useState("");
  const [rules, setRules] = useState<RuleDraft[]>([{ path: "", caps: [] }]);
  const [collections, setCollections] = useState<CollectionRuleDraft[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tried, setTried] = useState(false);

  if (me === null) return null;
  if (me.role !== "admin")
    return (
      <div class="page">
        <PageTitle crumbs={pageCrumbs("permNew")} />
        <Notice tone="info">
          {t("Only admins can change permissions.", "Hanya admin yang bisa mengubah izin.")}
        </Notice>
      </div>
    );

  const check = validatePermissionSet(name, rules, collections);
  const allows = describeRules([...toRules(rules), ...toCollectionRules(collections)]);

  async function onSubmit(event: Event) {
    event.preventDefault();
    setTried(true);
    if (!check.valid || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.createPolicy(name.trim(), [...toRules(rules), ...toCollectionRules(collections)]);
      navigate(PATHS.permissions);
    } catch (err) {
      setBusy(false);
      setError(
        err instanceof ApiError && err.kind === "conflict"
          ? t(
              "A permission set with this name already exists.",
              "Set izin dengan nama ini sudah ada.",
            )
          : failureText(err),
      );
    }
  }

  const nameError = tried && check.errors.name;
  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("permNew")} />
      <p class="sub page-sub">
        {t(
          "A permission set lists what is allowed, folder by folder. Anything you don't list is blocked.",
          "Set izin mendaftar apa yang diizinkan, folder demi folder. Yang tidak kamu daftarkan diblokir.",
        )}
      </p>
      <div class="cols">
        <form class="card form-stack col-main" onSubmit={onSubmit} aria-labelledby="perm-new-title">
          <h2 id="perm-new-title" class="visually-hidden">
            {t("New permission set", "Set izin baru")}
          </h2>
          <div class="field">
            <label for="perm-name">{t("Name", "Nama")}</label>
            <input
              id="perm-name"
              type="text"
              value={name}
              onInput={(e) => setName(e.currentTarget.value)}
              aria-invalid={nameError ? "true" : undefined}
              aria-describedby={nameError ? "perm-name-err" : undefined}
              autocomplete="off"
            />
            {nameError && (
              <span id="perm-name-err" class="field-error" role="alert">
                {nameError === "tooLong"
                  ? t("Keep the name under 80 characters.", "Buat nama kurang dari 80 karakter.")
                  : t("Give the set a name.", "Beri nama set ini.")}
              </span>
            )}
          </div>

          <h2 class="section-title">{t("Rules", "Aturan")}</h2>
          <RuleRows
            rules={rules}
            errors={check.errors}
            onChange={(i, next) => setRules(rules.map((r, j) => (j === i ? next : r)))}
            onRemove={(i) => setRules(rules.filter((_, j) => j !== i))}
          />
          <div>
            <button
              type="button"
              class="btn ghost sm"
              onClick={() => setRules([...rules, { path: "", caps: [] }])}
            >
              {t("+ Add a rule", "+ Tambah aturan")}
            </button>
          </div>

          <h2 class="section-title">{t("Collections", "Koleksi")}</h2>
          <p class="note">
            {t(
              "Collection rules let someone see or change which key names each environment must have. They never open a secret's values.",
              "Aturan koleksi membuat seseorang bisa melihat atau mengubah nama key yang harus dimiliki tiap environment. Aturan ini tidak pernah membuka nilai secret.",
            )}
          </p>
          <CollectionRuleRows
            rules={collections}
            errors={check.errors.collections}
            onChange={(i, next) => setCollections(collections.map((r, j) => (j === i ? next : r)))}
            onRemove={(i) => setCollections(collections.filter((_, j) => j !== i))}
          />
          <div>
            <button
              type="button"
              class="btn ghost sm"
              onClick={() => setCollections([...collections, { collection: "", caps: [] }])}
            >
              {t("+ Add a collection rule", "+ Tambah aturan koleksi")}
            </button>
          </div>
          {tried && check.errors.rulesEmpty && (
            <span class="field-error" role="alert">
              {t("Add at least one rule.", "Tambah minimal satu aturan.")}
            </span>
          )}
          {tried && check.errors.duplicate && (
            <span class="field-error" role="alert">
              {t(
                "Two rules use the same path. Merge them.",
                "Dua aturan memakai path yang sama. Gabungkan.",
              )}
            </span>
          )}
          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}
          <div class="form-foot">
            <Link class="btn ghost" href={PATHS.permissions}>
              {t("Cancel", "Batal")}
            </Link>
            <button type="submit" class="btn" disabled={busy}>
              {t("Save permission set", "Simpan set izin")}
            </button>
          </div>
        </form>

        <aside class="card side-note col-side" aria-labelledby="allows-title">
          <h2 id="allows-title">{t("What this allows", "Yang diizinkan")}</h2>
          {allows.length === 0 ? (
            <p class="note">{t("Nothing is allowed yet.", "Belum ada yang diizinkan.")}</p>
          ) : (
            <ul class="plain-list">
              {allows.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          )}
          <p class="note">{t("Everything else is blocked.", "Semua yang lain diblokir.")}</p>
        </aside>
      </div>
    </div>
  );
}

/**
 * New role: people and the permission sets they get. The API keeps permissions per person, so each pair is
 * one assignment and the role name is not stored (the board's name field is left out on purpose).
 */
export function RoleNewPage() {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const people = useLoad(() => api.identities(), "role-people");
  const policies = useLoad(() => api.policies(), "role-policies");
  const [chosenPeople, setChosenPeople] = useState<string[]>([]);
  const [chosenSets, setChosenSets] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  if (me === null) return null;
  if (me.role !== "admin")
    return (
      <div class="page">
        <PageTitle crumbs={pageCrumbs("roleNew")} />
        <Notice tone="info">
          {t("Only admins can change permissions.", "Hanya admin yang bisa mengubah izin.")}
        </Notice>
      </div>
    );

  const candidates = (people.data ?? [])
    .filter((i: Identity) => i.status === "active")
    .filter((i) => i.name.toLowerCase().includes(query.trim().toLowerCase()));
  const sets = policies.data ?? [];
  const chosenRules: PolicyRule[] = sets
    .filter((p) => chosenSets.includes(p.id))
    .flatMap((p) => p.rules);
  const canSave = !busy && chosenPeople.length > 0 && chosenSets.length > 0;

  async function onSubmit(event: Event) {
    event.preventDefault();
    if (!canSave) return;
    setBusy(true);
    setError(null);
    let failures = 0;
    for (const personId of chosenPeople) {
      for (const policyId of chosenSets) {
        try {
          await api.assignPolicy(policyId, personId);
        } catch {
          failures++;
        }
      }
    }
    setBusy(false);
    if (failures === 0) navigate(PATHS.permissions);
    else
      setError(
        t(
          `${failures} assignment(s) didn't save. Check and try again.`,
          `${failures} penugasan belum tersimpan. Periksa lalu coba lagi.`,
        ),
      );
  }

  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("roleNew")} />
      <p class="sub page-sub">
        {t(
          "A role puts people together and gives them permission sets, so you don't set things up one person at a time.",
          "Peran mengumpulkan orang dan memberi mereka set izin, jadi kamu tidak perlu mengatur satu per satu.",
        )}
      </p>
      <div class="cols">
        <form class="card form-stack col-main" onSubmit={onSubmit} aria-labelledby="role-title">
          <h2 id="role-title" class="visually-hidden">
            {t("New role", "Peran baru")}
          </h2>
          <fieldset class="field fieldset">
            <legend>{t("Who's in this role", "Siapa saja di peran ini")}</legend>
            <div class="field">
              <label for="role-search">{t("Find a person or bot", "Cari orang atau bot")}</label>
              <input
                id="role-search"
                type="text"
                value={query}
                onInput={(e) => setQuery(e.currentTarget.value)}
                autocomplete="off"
              />
            </div>
            {people.loading && <p class="note">{t("Loading...", "Memuat...")}</p>}
            <ul class="picker">
              {candidates.map((i) => (
                <li key={i.id}>
                  <label class="pick">
                    <input
                      type="checkbox"
                      checked={chosenPeople.includes(i.id)}
                      onChange={() =>
                        setChosenPeople((c) =>
                          c.includes(i.id) ? c.filter((x) => x !== i.id) : [...c, i.id],
                        )
                      }
                    />
                    <span class="pick-name">{i.name}</span>
                    {i.kind === "app" && <Pill>{t("App", "Aplikasi")}</Pill>}
                  </label>
                </li>
              ))}
            </ul>
            <p class="note">
              {t(
                "People are matched by the email they sign in with.",
                "Orang dicocokkan lewat email yang mereka pakai untuk masuk.",
              )}
            </p>
          </fieldset>

          <fieldset class="field fieldset">
            <legend>{t("Permission sets", "Set izin")}</legend>
            {policies.data && sets.length === 0 && (
              <p class="note">
                {t("Make a permission set first.", "Buat set izin dulu.")}{" "}
                <Link href={PATHS.permNew}>
                  {t("+ Create a new permission set", "+ Buat set izin baru")}
                </Link>
              </p>
            )}
            <ul class="picker">
              {sets.map((p) => (
                <li key={p.id}>
                  <label class="pick">
                    <input
                      type="checkbox"
                      checked={chosenSets.includes(p.id)}
                      onChange={() =>
                        setChosenSets((c) =>
                          c.includes(p.id) ? c.filter((x) => x !== p.id) : [...c, p.id],
                        )
                      }
                    />
                    <span class="pick-name">{p.name}</span>
                  </label>
                </li>
              ))}
            </ul>
          </fieldset>

          <Notice tone="info">
            {t(
              "The role name isn't saved yet. Each person gets each permission set directly.",
              "Nama peran belum disimpan. Tiap orang mendapat tiap set izin secara langsung.",
            )}
          </Notice>
          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}
          <div class="form-foot">
            <Link class="btn ghost" href={PATHS.permissions}>
              {t("Cancel", "Batal")}
            </Link>
            <button type="submit" class="btn" disabled={!canSave}>
              {busy ? t("Saving...", "Menyimpan...") : t("Save role", "Simpan peran")}
            </button>
          </div>
        </form>

        <aside class="card side-note col-side" aria-labelledby="role-means">
          <h2 id="role-means">{t("What this role means", "Arti peran ini")}</h2>
          {chosenRules.length === 0 ? (
            <p class="note">
              {t(
                "Pick a permission set to see what it allows.",
                "Pilih set izin untuk melihat apa yang diizinkan.",
              )}
            </p>
          ) : (
            <ul class="plain-list">
              {describeRules(chosenRules).map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          )}
          <Notice tone="info">
            {t(
              "Permissions only let people reach a secret. To open the values they also need to be in its group.",
              "Izin hanya membuat orang bisa menjangkau secret. Untuk membuka nilainya mereka juga harus ada di grupnya.",
            )}{" "}
            <Link href={PATHS.groups}>{t("Go to Groups", "Buka Grup")}</Link>
          </Notice>
        </aside>
      </div>
    </div>
  );
}
