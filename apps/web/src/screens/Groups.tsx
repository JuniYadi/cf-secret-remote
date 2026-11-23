import { useEffect, useState } from "preact/hooks";
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
import { api, type GroupMember, type Identity, type KeyringRow } from "../lib/api.ts";
import {
  addPersonToGroup,
  adminsWithVault,
  createGroup,
  groupSecrets,
  normalizePrefix,
  openMyGroupKey,
  type PersonKey,
  planRemoval,
  VaultLockedError,
  validatePrefix,
} from "../lib/groups.ts";
import { useLang, useSession } from "../lib/hooks.ts";
import { t } from "../lib/i18n.ts";
import {
  clearRelock,
  currentJob,
  type RelockJob,
  startRelock,
  subscribeRelock,
} from "../lib/relock.ts";
import { groupAddPath, groupPath, groupRelockPath, PATHS, pageCrumbs } from "../routes.ts";
import "../styles/admin.css";

/** Shows the two-admin warning on the Groups pages (DESIGN.md "Aturan minimal dua admin"). */
function TwoAdminWarning({ identities }: { identities: Identity[] | null }) {
  useLang();
  if (identities === null) return null;
  if (adminsWithVault(identities) >= 2) return null;
  return (
    <Notice
      tone="warn"
      title={t("Only one admin has a key.", "Hanya satu admin yang punya kunci.")}
    >
      {t(
        "If they're locked out, nobody can manage the vault. ",
        "Jika ia terkunci, tidak ada yang bisa mengelola vault. ",
      )}
      <Link href={PATHS.settings}>{t("Add another admin", "Tambah admin lagi")}</Link>
    </Notice>
  );
}

/** Groups: every group the person can see, with its key version. */
export function GroupsPage() {
  useLang();
  const { me } = useSession();
  const isAdmin = me?.role === "admin";
  const groups = useLoad(() => api.keyrings(), "groups");
  const people = useLoad(
    () => (isAdmin ? api.identities() : Promise.resolve(null)),
    `people:${isAdmin}`,
  );
  const crumbs = pageCrumbs("groups");

  return (
    <div class="page">
      <PageTitle crumbs={crumbs} />
      <div class="page-head">
        <p class="sub page-sub">
          {t(
            "A group decides who can actually open its secrets. Permissions only decide who can reach them, so people need both.",
            "Grup menentukan siapa yang benar-benar bisa membuka secret-nya. Izin hanya menentukan siapa yang bisa menjangkaunya, jadi orang butuh keduanya.",
          )}
        </p>
        {isAdmin && (
          <div class="actions">
            <Link class="btn ghost" href={PATHS.invite}>
              {t("Invite a teammate", "Undang anggota")}
            </Link>
            <Link class="btn" href={PATHS.groupNew}>
              {t("+ New group", "+ Grup baru")}
            </Link>
          </div>
        )}
      </div>

      <TwoAdminWarning identities={people.data} />
      <LoadStatus state={groups} />

      {groups.data && groups.data.length === 0 && (
        <div class="card empty">
          <h2>{t("No groups yet", "Belum ada grup")}</h2>
          <p class="note">
            {t(
              "Make a group for the secrets people share, like myapp/ or backend/.",
              "Buat grup untuk secret yang dibagikan, misalnya myapp/ atau backend/.",
            )}
          </p>
          {isAdmin && (
            <Link class="btn" href={PATHS.groupNew}>
              {t("+ New group", "+ Grup baru")}
            </Link>
          )}
        </div>
      )}

      {groups.data && groups.data.length > 0 && <GroupTable rows={groups.data} />}
    </div>
  );
}

function GroupTable({ rows }: { rows: KeyringRow[] }) {
  useLang();
  return (
    <div class="card tw">
      <table>
        <thead>
          <tr>
            <th scope="col">{t("Group", "Grup")}</th>
            <th scope="col">{t("Key version", "Versi kunci")}</th>
            <th scope="col">
              <span class="visually-hidden">{t("Open", "Buka")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.prefix}>
              <td>
                <Link class="strong-link" href={groupPath(row.prefix)}>
                  {row.prefix}
                </Link>
              </td>
              <td>
                <Pill>{`k${row.version}`}</Pill>
              </td>
              <td class="right">
                <Link class="btn ghost sm" href={groupPath(row.prefix)}>
                  {t("Open", "Buka")}
                  <span class="visually-hidden"> {row.prefix}</span>
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** New group: the browser makes the key and wraps it to each chosen person (ADR 3, ADR 14). */
export function GroupNewPage() {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const existing = useLoad(() => api.keyrings(), "groups-new");
  const people = useLoad(() => api.identities(), "people-new");
  const [prefix, setPrefix] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (me === null) return null;
  if (me.role !== "admin")
    return (
      <div class="page">
        <PageTitle crumbs={pageCrumbs("groupNew")} />
        <Notice tone="info">
          {t("Only admins can make groups.", "Hanya admin yang bisa membuat grup.")}
        </Notice>
      </div>
    );

  const names = (existing.data ?? []).map((r) => r.prefix);
  const prefixError = prefix === "" ? null : validatePrefix(prefix, names);
  const candidates: PersonKey[] = (people.data ?? [])
    .filter((i) => i.status === "active" && i.id !== me.id && i.publicKey !== null)
    .filter((i) => i.name.toLowerCase().includes(query.trim().toLowerCase()))
    .map((i) => ({ identityId: i.id, name: i.name, publicKey: i.publicKey ?? "" }));
  const canSubmit = !busy && validatePrefix(prefix, names) === null && me.publicKey !== null;

  async function onSubmit(event: Event) {
    event.preventDefault();
    if (!canSubmit || me === null || me.publicKey === null) return;
    setBusy(true);
    setError(null);
    try {
      const picked = candidates.filter((p) => chosen.includes(p.identityId));
      const everyone: PersonKey[] = [
        { identityId: me.id, name: me.name, publicKey: me.publicKey },
        ...picked,
      ];
      await createGroup(normalizePrefix(prefix), everyone);
      navigate(groupPath(normalizePrefix(prefix)));
    } catch (err) {
      setBusy(false);
      setError(failureText(err));
    }
  }

  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("groupNew")} />
      <p class="sub page-sub">
        {t(
          "A group is a set of people and bots who can open the same secrets.",
          "Grup adalah sekumpulan orang dan bot yang bisa membuka secret yang sama.",
        )}
      </p>
      <div class="cols">
        <form
          class="card form-stack col-main"
          onSubmit={onSubmit}
          aria-labelledby="group-new-title"
        >
          <h2 id="group-new-title" class="visually-hidden">
            {t("New group", "Grup baru")}
          </h2>
          <div class="field">
            <label for="group-prefix">
              {t("Which secrets does it protect?", "Secret mana yang dilindunginya?")}
            </label>
            <input
              id="group-prefix"
              type="text"
              value={prefix}
              onInput={(e) => setPrefix(e.currentTarget.value)}
              aria-invalid={prefixError ? "true" : undefined}
              aria-describedby="group-prefix-help"
              placeholder="myapp"
              autocomplete="off"
              required
            />
            <span id="group-prefix-help" class="note">
              {t(
                "Everything whose name starts with this, like data/dev and data/prod.",
                "Semua yang namanya diawali ini, seperti data/dev dan data/prod.",
              )}
            </span>
            {prefixError && (
              <span class="field-error" role="alert">
                {prefixError === "exists"
                  ? t("A group with this name already exists.", "Grup dengan nama ini sudah ada.")
                  : prefixError === "reserved"
                    ? t(
                        "This name is reserved for a web page.",
                        "Nama ini dicadangkan untuk halaman web.",
                      )
                    : t(
                        "Use letters, numbers, dots, dashes and underscores. No slash in the middle.",
                        "Pakai huruf, angka, titik, tanda hubung, dan garis bawah. Tanpa / di tengah.",
                      )}
              </span>
            )}
          </div>

          <fieldset class="field fieldset">
            <legend>{t("Who's in it", "Siapa saja di dalamnya")}</legend>
            <div class="chips">
              <span class="chip">
                {me.name} ({t("you", "kamu")})
              </span>
            </div>
            <div class="field">
              <label for="group-people-search">{t("Add people", "Tambah orang")}</label>
              <input
                id="group-people-search"
                type="text"
                value={query}
                onInput={(e) => setQuery(e.currentTarget.value)}
                placeholder={t("Find a person or bot", "Cari orang atau bot")}
                autocomplete="off"
              />
            </div>
            <PeoplePicker
              people={candidates}
              chosen={chosen}
              onToggle={(id) =>
                setChosen((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]))
              }
              emptyText={t(
                "Nobody else is ready yet. People need a vault password first.",
                "Belum ada orang lain yang siap. Mereka harus membuat vault password dulu.",
              )}
            />
            <span class="note">
              {t("You can add more people any time.", "Kamu bisa menambah orang kapan saja.")}
            </span>
          </fieldset>

          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}
          <div class="form-foot">
            <Link class="btn ghost" href={PATHS.groups}>
              {t("Cancel", "Batal")}
            </Link>
            <button type="submit" class="btn" disabled={!canSubmit}>
              {busy ? t("Making the key...", "Membuat kunci...") : t("Create group", "Buat grup")}
            </button>
          </div>
        </form>

        <aside class="card side-note col-side" aria-labelledby="what-is-group">
          <h2 id="what-is-group">{t("What's a group?", "Apa itu grup?")}</h2>
          <p>
            {t(
              "Being in a group is what lets someone actually open the values:",
              "Berada di grup itulah yang memungkinkan seseorang membuka nilainya:",
            )}
          </p>
          <ol class="plain-steps">
            <li>
              {t(
                "Your browser makes a new key for the group.",
                "Browsermu membuat kunci baru untuk grup.",
              )}
            </li>
            <li>
              {t(
                "The key is shared only with the people you add.",
                "Kunci itu hanya dibagikan ke orang yang kamu tambahkan.",
              )}
            </li>
            <li>
              {t(
                "Secrets in the group are locked with that key.",
                "Secret di grup ini dikunci dengan kunci itu.",
              )}
            </li>
          </ol>
          <Notice tone="info">
            {t(
              "Creating a group needs your vault unlocked. It happens in your browser, so the server never sees the key.",
              "Membuat grup butuh vault-mu terbuka. Terjadi di browsermu, jadi server tidak pernah melihat kuncinya.",
            )}
          </Notice>
        </aside>
      </div>
    </div>
  );
}

/** A list of people with a checkbox each. People without a key cannot be picked. */
function PeoplePicker({
  people,
  chosen,
  onToggle,
  emptyText,
}: {
  people: PersonKey[];
  chosen: string[];
  onToggle: (identityId: string) => void;
  emptyText: string;
}) {
  useLang();
  if (people.length === 0) return <p class="note">{emptyText}</p>;
  return (
    <ul class="picker" aria-label={t("People", "Orang")}>
      {people.map((p) => (
        <li key={p.identityId}>
          <label class="pick">
            <input
              type="checkbox"
              checked={chosen.includes(p.identityId)}
              onChange={() => onToggle(p.identityId)}
            />
            <span class="pick-name">{p.name}</span>
            <Pill tone="ok">{t("Ready", "Siap")}</Pill>
          </label>
        </li>
      ))}
    </ul>
  );
}

/** One group: members, who can open its values, and the staged removal (ADR 14). */
export function GroupDetailPage({ prefix }: { prefix: string }) {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const isAdmin = me?.role === "admin";
  const members = useLoad(() => api.keyringMembers(prefix), `members:${prefix}`);
  const people = useLoad(
    () => (isAdmin ? api.identities() : Promise.resolve(null)),
    `ppl:${prefix}`,
  );
  const secrets = useLoad(() => (isAdmin ? api.secrets() : Promise.resolve([])), `sec:${prefix}`);
  const [target, setTarget] = useState<GroupMember | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const crumbs = pageCrumbs("groupDetail", prefix);

  if (me === null) return null;
  const inGroup = groupSecrets(secrets.data ?? [], prefix);

  async function confirmRemove() {
    if (target === null || me === null || busy) return;
    setError(null);
    const plan = planRemoval(members.data ?? [], people.data ?? [], target.identityId, me.id);
    if (!plan.ok) {
      setError(
        plan.reason === "self"
          ? t(
              "You can't remove yourself from a group you're in.",
              "Kamu tidak bisa mengeluarkan dirimu sendiri.",
            )
          : plan.reason === "noKey"
            ? t(
                `${plan.name ?? "Someone"} hasn't set up a vault yet, so the new key can't reach them. Try again once they have.`,
                `${plan.name ?? "Seseorang"} belum menyiapkan vault, jadi kunci baru tidak bisa sampai. Coba lagi setelah itu.`,
              )
            : t(
                "That person is no longer in this group.",
                "Orang itu sudah tidak ada di grup ini.",
              ),
      );
      return;
    }
    setBusy(true);
    try {
      const { key, version } = await openMyGroupKey(prefix);
      startRelock(
        {
          prefix,
          currentVersion: version,
          removeIdentityId: target.identityId,
          remaining: plan.remaining,
          oldKey: key,
          secrets: inGroup,
        },
        target.name,
      );
      navigate(groupRelockPath(prefix));
    } catch (err) {
      setBusy(false);
      setError(failureText(err));
    }
  }

  const memberRows = members.data ?? [];
  return (
    <div class="page">
      <PageTitle crumbs={crumbs} />
      <div class="page-head">
        <p class="sub page-sub">
          {t(
            "People in this group hold its key. Removing someone re-locks every secret in it with a new key.",
            "Orang di grup ini memegang kuncinya. Mengeluarkan seseorang mengunci ulang semua secret di dalamnya dengan kunci baru.",
          )}
        </p>
        {isAdmin && (
          <div class="actions">
            <Link class="btn" href={groupAddPath(prefix)}>
              {t("+ Add member", "+ Tambah anggota")}
            </Link>
          </div>
        )}
      </div>

      <TwoAdminWarning identities={people.data} />
      <LoadStatus state={members} />

      {members.data && (
        <div class="cols">
          <div class="card tw col-main">
            <table>
              <thead>
                <tr>
                  <th scope="col">{t("Member", "Anggota")}</th>
                  <th scope="col">{t("Role", "Peran")}</th>
                  <th scope="col">{t("Can open values", "Bisa membuka nilai")}</th>
                  <th scope="col">
                    <span class="visually-hidden">{t("Actions", "Aksi")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {memberRows.map((m) => (
                  <tr key={m.identityId}>
                    <td>
                      <span class="strong">{m.name}</span>
                      {m.identityId === me.id && <span class="note"> ({t("you", "kamu")})</span>}
                    </td>
                    <td>{m.role === "admin" ? t("Admin", "Admin") : t("Member", "Anggota")}</td>
                    <td>
                      <Pill tone="ok">{t("Yes", "Ya")}</Pill>
                    </td>
                    <td class="right">
                      {isAdmin && m.identityId !== me.id && (
                        <button
                          type="button"
                          class="btn danger sm"
                          onClick={() => {
                            setTarget(m);
                            setError(null);
                          }}
                        >
                          {t("Remove", "Keluarkan")}
                          <span class="visually-hidden"> {m.name}</span>
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {isAdmin && target !== null && (
            <section class="card danger-card col-side" aria-labelledby="remove-title">
              <h2 id="remove-title" class="danger-title">
                {t(
                  `Remove ${target.name} from this group?`,
                  `Keluarkan ${target.name} dari grup ini?`,
                )}
              </h2>
              <p class="note-strong">
                {t(
                  "We'll re-lock everything in this group with a fresh key, right here in your browser.",
                  "Kami akan mengunci ulang semua isi grup ini dengan kunci baru, langsung di browsermu.",
                )}
              </p>
              <ul class="plain-list">
                <li>
                  {t(
                    `${inGroup.length} secrets are re-locked.`,
                    `${inGroup.length} secret dikunci ulang.`,
                  )}
                </li>
                <li>
                  {t(
                    `${target.name} can't open any new version.`,
                    `${target.name} tidak bisa membuka versi baru mana pun.`,
                  )}
                </li>
                <li>
                  <b>
                    {t(
                      "They still know what they already opened.",
                      "Ia tetap tahu apa yang sudah pernah dibukanya.",
                    )}
                  </b>{" "}
                  {t(
                    "Change those passwords and keys at their source, like the database or the API provider.",
                    "Ganti password dan key itu di sumbernya, seperti database atau penyedia API.",
                  )}
                </li>
              </ul>
              {error && (
                <p class="field-error" role="alert">
                  {error}
                </p>
              )}
              <div class="form-foot">
                <button type="button" class="btn ghost" onClick={() => setTarget(null)}>
                  {t("Cancel", "Batal")}
                </button>
                <button type="button" class="btn danger" disabled={busy} onClick={confirmRemove}>
                  {busy
                    ? t("Starting...", "Memulai...")
                    : t("Remove and re-lock", "Keluarkan dan kunci ulang")}
                </button>
              </div>
              <p class="note">
                {t(
                  "Needs your vault unlocked. The server never sees the values.",
                  "Butuh vault-mu terbuka. Server tidak pernah melihat nilainya.",
                )}
              </p>
            </section>
          )}
        </div>
      )}

      <TechDetails>
        {t("Group name", "Nama grup")}: {prefix}
        <br />
        {t("Members", "Anggota")}: {memberRows.length}
      </TechDetails>
    </div>
  );
}

/** Add member (ADR 14): the browser unwraps the group key and wraps it to each chosen person. */
export function GroupAddPage({ prefix }: { prefix: string }) {
  useLang();
  const [, navigate] = useLocation();
  const { me } = useSession();
  const members = useLoad(() => api.keyringMembers(prefix), `members-add:${prefix}`);
  const people = useLoad(() => api.identities(), `people-add:${prefix}`);
  const [query, setQuery] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  if (me === null) return null;
  const already = new Set((members.data ?? []).map((m) => m.identityId));
  const pool = (people.data ?? []).filter(
    (i) => i.status === "active" && !already.has(i.id) && i.id !== me.id,
  );
  const shown = pool.filter((i) => i.name.toLowerCase().includes(query.trim().toLowerCase()));
  const picked = pool.filter((i) => chosen.includes(i.id));

  async function onSubmit(event: Event) {
    event.preventDefault();
    if (busy || picked.length === 0) return;
    setBusy(true);
    setError(null);
    const missed: { id: string; name: string }[] = [];
    for (const who of picked) {
      if (who.publicKey === null) {
        missed.push({ id: who.id, name: who.name });
        continue;
      }
      try {
        await addPersonToGroup(prefix, {
          identityId: who.id,
          name: who.name,
          publicKey: who.publicKey,
        });
      } catch (err) {
        if (err instanceof VaultLockedError) {
          setError(failureText(err));
          setBusy(false);
          return;
        }
        missed.push({ id: who.id, name: who.name });
      }
    }
    setBusy(false);
    if (missed.length === 0) {
      navigate(groupPath(prefix));
      return;
    }
    // Keep the ones that failed ticked, so a retry only touches them.
    setFailed(missed.map((m) => m.name));
    setChosen(missed.map((m) => m.id));
    setError(
      t(
        "Some people weren't added. Check their status and try again.",
        "Ada orang yang belum ditambahkan. Periksa statusnya lalu coba lagi.",
      ),
    );
  }

  return (
    <div class="page">
      <PageTitle crumbs={pageCrumbs("groupAdd", prefix)} />
      <p class="sub page-sub">
        {t(
          "Choose who should be able to open this group's secrets. They need a vault password first.",
          "Pilih siapa yang bisa membuka secret grup ini. Mereka harus punya vault password dulu.",
        )}
      </p>
      <div class="cols">
        <form class="card form-stack col-main" onSubmit={onSubmit} aria-labelledby="add-title">
          <h2 id="add-title" class="visually-hidden">
            {t("Add member", "Tambah anggota")}
          </h2>
          <div class="field">
            <span class="label-text">{t("Group", "Grup")}</span>
            <span class="strong">{prefix}</span>
          </div>
          <div class="field">
            <label for="add-search">{t("Find a person or bot", "Cari orang atau bot")}</label>
            <input
              id="add-search"
              type="text"
              value={query}
              onInput={(e) => setQuery(e.currentTarget.value)}
              autocomplete="off"
            />
          </div>
          {people.loading && <p class="note">{t("Loading...", "Memuat...")}</p>}
          {people.error !== null && <Notice tone="danger">{failureText(people.error)}</Notice>}
          {people.data && shown.length === 0 && (
            <p class="note">{t("No one else to add.", "Tidak ada lagi yang bisa ditambahkan.")}</p>
          )}
          <ul class="picker" aria-label={t("People", "Orang")}>
            {shown.map((who) => {
              const ready = who.publicKey !== null;
              return (
                <li key={who.id}>
                  <label class={`pick ${ready ? "" : "is-disabled"}`.trim()}>
                    <input
                      type="checkbox"
                      disabled={!ready}
                      checked={chosen.includes(who.id)}
                      onChange={() =>
                        setChosen((c) =>
                          c.includes(who.id) ? c.filter((x) => x !== who.id) : [...c, who.id],
                        )
                      }
                    />
                    <span class="pick-name">
                      {who.name}
                      <span class="note">
                        {who.kind === "app" ? ` · ${t("App or bot", "Aplikasi atau bot")}` : ""}
                      </span>
                    </span>
                    {ready ? (
                      <Pill tone="ok">{t("Ready", "Siap")}</Pill>
                    ) : (
                      <Pill tone="warn">{t("Hasn't set up yet", "Belum menyiapkan")}</Pill>
                    )}
                  </label>
                </li>
              );
            })}
          </ul>
          {failed.length > 0 && (
            <p class="note" role="status">
              {t("Not added:", "Belum ditambahkan:")} {failed.join(", ")}
            </p>
          )}
          {error && (
            <p class="field-error" role="alert">
              {error}
            </p>
          )}
          <div class="form-foot">
            <Link class="btn ghost" href={groupPath(prefix)}>
              {t("Cancel", "Batal")}
            </Link>
            <button type="submit" class="btn" disabled={busy || picked.length === 0}>
              {busy
                ? t("Sharing the key...", "Membagikan kunci...")
                : t(
                    `Add ${picked.length} ${picked.length === 1 ? "member" : "members"}`,
                    `Tambah ${picked.length} anggota`,
                  )}
            </button>
          </div>
        </form>
        <aside class="card side-note col-side" aria-labelledby="what-happens">
          <h2 id="what-happens">{t("What happens", "Yang terjadi")}</h2>
          <ol class="plain-steps">
            <li>
              {t(
                "Your browser shares the group key with them. Only their own key can open it.",
                "Browsermu membagikan kunci grup kepada mereka. Hanya kunci milik mereka yang bisa membukanya.",
              )}
            </li>
            <li>
              {t(
                "The server only stores the locked copy.",
                "Server hanya menyimpan salinan yang terkunci.",
              )}
            </li>
            <li>
              {t(
                "They can open the values the next time they unlock their vault.",
                "Mereka bisa membuka nilainya saat membuka vault berikutnya.",
              )}
            </li>
          </ol>
          <Notice tone="warn">
            {t(
              "Add people you trust. Anyone in the group can open every secret in it.",
              "Tambahkan orang yang kamu percaya. Siapa pun di grup bisa membuka semua secret di dalamnya.",
            )}
          </Notice>
        </aside>
      </div>
    </div>
  );
}

/** Subscribes to the re-locking job for this group. Re-renders on every progress step. */
function useRelockJob(prefix: string): RelockJob | null {
  const [, bump] = useState(0);
  useEffect(() => subscribeRelock(() => bump((n) => n + 1)), []);
  return currentJob(prefix);
}

/** The "Re-locking" screen: progress, and the names of values the removed person could open (ADR 14). */
export function GroupRelockPage({ prefix }: { prefix: string }) {
  useLang();
  const [, navigate] = useLocation();
  const job = useRelockJob(prefix);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const crumbs = pageCrumbs("groupRelock", prefix);

  async function cancelStaged() {
    setCancelling(true);
    setCancelError(null);
    try {
      await api.rotateAbort(prefix);
      clearRelock();
      navigate(groupPath(prefix));
    } catch (err) {
      setCancelling(false);
      setCancelError(failureText(err));
    }
  }

  if (job === null)
    return (
      <div class="page">
        <PageTitle crumbs={crumbs} />
        <Notice tone="info">
          {t(
            "This re-locking isn't running in this tab any more. Reloading the page stops it, and the values stay under the old key.",
            "Pengunciulangan ini tidak berjalan lagi di tab ini. Memuat ulang halaman menghentikannya, dan nilainya tetap memakai kunci lama.",
          )}
        </Notice>
        {cancelError && (
          <p class="field-error" role="alert">
            {cancelError}
          </p>
        )}
        <div class="form-foot">
          <Link class="btn ghost" href={groupPath(prefix)}>
            {t("Back to group", "Kembali ke grup")}
          </Link>
          <button type="button" class="btn" disabled={cancelling} onClick={cancelStaged}>
            {t("Cancel the staged re-lock", "Batalkan pengunciulangan")}
          </button>
        </div>
      </div>
    );

  const { progress } = job;
  const percent = progress.total === 0 ? 100 : Math.round((progress.done / progress.total) * 100);
  const stateText = (s: "waiting" | "now" | "done") =>
    s === "done"
      ? t("Done", "Selesai")
      : s === "now"
        ? t("Working…", "Mengerjakan…")
        : t("Waiting", "Menunggu");
  const stateTone = (s: "waiting" | "now" | "done") =>
    s === "done" ? "ok" : s === "now" ? "warn" : "";

  return (
    <div class="page">
      <PageTitle crumbs={crumbs} />
      <div class="cols">
        <section class="card col-main" aria-labelledby="progress-title">
          <div class="row-between">
            <h2 id="progress-title">
              {t(
                `${progress.done} of ${progress.total} secrets re-locked`,
                `${progress.done} dari ${progress.total} secret sudah dikunci ulang`,
              )}
            </h2>
            {job.status === "running" && <Pill tone="warn">{t("In progress", "Berjalan")}</Pill>}
            {job.status === "done" && <Pill tone="ok">{t("Finished", "Selesai")}</Pill>}
          </div>
          <progress
            class="relock-bar"
            max={100}
            value={percent}
            aria-label={t("Re-locking progress", "Kemajuan pengunciulangan")}
          />
          <ul class="plain-list">
            {progress.items.map((item) => (
              <li key={item.path} class="row-between">
                <span class="mono">{item.path}</span>
                <Pill tone={stateTone(item.state)}>{stateText(item.state)}</Pill>
              </li>
            ))}
            {progress.items.length === 0 && (
              <li class="note">
                {t("No secrets in this group yet.", "Belum ada secret di grup ini.")}
              </li>
            )}
          </ul>
          {job.status === "running" && (
            <Notice tone="warn" title={t("Keep this tab open.", "Biarkan tab ini terbuka.")}>
              {t(
                "The locking happens in your browser. If you close it, the rest is not finished. Start the removal again to finish.",
                "Pengunciannya terjadi di browsermu. Jika kamu menutupnya, sisanya belum selesai. Mulai pengeluaran lagi untuk menyelesaikannya.",
              )}
            </Notice>
          )}
          {job.status === "failed" && job.error && (
            <Notice tone="danger">{failureText(job.error)}</Notice>
          )}
          {job.status === "done" && (
            <Notice tone="info">
              {t(
                "Everything in the group is locked with the new key.",
                "Semua isi grup sudah dikunci dengan kunci baru.",
              )}
            </Notice>
          )}
          <div class="form-foot">
            {job.status !== "running" && (
              <Link class="btn" href={groupPath(prefix)} onClick={() => clearRelock()}>
                {t("Back to group", "Kembali ke grup")}
              </Link>
            )}
          </div>
        </section>

        <section class="card col-side" aria-labelledby="source-title">
          <h2 id="source-title">
            {t("Then change these at the source", "Lalu ganti ini di sumbernya")}
          </h2>
          <p class="note-strong">
            {t(
              `${job.removedName} opened these values before being removed. A new lock can't make them forget.`,
              `${job.removedName} membuka nilai ini sebelum dikeluarkan. Kunci baru tidak bisa membuatnya lupa.`,
            )}
          </p>
          {job.openable.length === 0 && (
            <p class="note">
              {t("Nothing in this group to change.", "Tidak ada yang perlu diganti di grup ini.")}
            </p>
          )}
          <ul class="plain-list">
            {job.openable.map((s) => (
              <li key={s.path}>
                <span class="mono">{s.path}</span>
                {s.names.length > 0 && <span class="note"> {s.names.join(", ")}</span>}
              </li>
            ))}
          </ul>
          <p class="note">
            {t(
              "For example, create a new database password, then save it as a new version here.",
              "Misalnya, buat password database baru, lalu simpan sebagai versi baru di sini.",
            )}
          </p>
        </section>
      </div>
    </div>
  );
}
