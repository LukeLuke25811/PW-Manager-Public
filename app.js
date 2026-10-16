// PW-Manager for iPhone. Opens the encrypted vault, either a copy chosen from
// the Files app (read-only) or the shared vault in Dropbox (read and write,
// kept in step with the PC). The decrypted entries live only in memory while
// unlocked; only the encrypted file is stored or sent anywhere.

import {
  decryptWithSession, encryptVault, normaliseEntries, PasswordChanged, readHeader, unlockVault,
  WrongPassword,
} from "./vault.js";
import { mergePayloads, samePayload } from "./sync.js";
import * as dropbox from "./cloud.js";
import { generatePassword } from "./generator.js";

const MODE_KEY = "pwm.mode";      // "dropbox" or "file"
const CACHE_KEY = "pwm.vault";    // {name, modified, text, rev, dirty}: the encrypted file
const HIDDEN_LOCK_MS = 2 * 60 * 1000; // lock after 2 min in the background
const DEFAULT_AUTOLOCK_MIN = 5;
const DEFAULT_CLIPBOARD_SEC = 30;
const HISTORY_LIMIT = 10;

const $ = (id) => document.getElementById(id);

let mode = null;        // "dropbox", "file" or null (not chosen yet)
let cache = null;       // the encrypted file as last seen, see CACHE_KEY
let session = null;     // derived key while unlocked
let payload = null;     // decrypted vault while unlocked
let rev = null;         // Dropbox revision `payload` is based on
let dirty = false;      // local changes not yet in Dropbox
let syncing = null;     // running sync, if any
let filter = "all";     // "all", "fav" or a category name
let currentId = null;   // entry shown in the detail view
let editingId = null;   // entry in the edit form ("" = new)
let lastActivity = Date.now();
let hiddenAt = null;
let clipboardTimer = null;

// ---------- local storage ----------

function load(key) {
  try { return JSON.parse(localStorage.getItem(key) || "null"); } catch { return null; }
}

function store(key, value) {
  try {
    if (value == null) localStorage.removeItem(key); else localStorage.setItem(key, JSON.stringify(value));
  } catch { /* private mode or full: just don't remember */ }
}

function setMode(m) {
  mode = m;
  store(MODE_KEY, m);
}

function setCache(c) {
  cache = c;
  store(CACHE_KEY, c);
}

// ---------- views ----------

const VIEWS = ["unlock-view", "connect-view", "list-view", "detail-view", "edit-view"];

function show(view) {
  for (const v of VIEWS) $(v).hidden = v !== view;
  window.scrollTo(0, 0);
}

function formatDate(ms) {
  if (!ms) return "";
  return new Date(ms).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" });
}

function showError(el, message) {
  el.textContent = message;
  el.hidden = !message;
}

function editable() {
  return mode === "dropbox";
}

function showUnlock(message = "") {
  const ready = mode === "dropbox" ? dropbox.isConnected() : Boolean(cache);
  $("unlock-form").hidden = !ready;
  $("source-card").hidden = ready;
  $("dropbox-choice").hidden = !dropbox.isConfigured();
  showError($("unlock-error"), message);
  showError($("source-error"), "");
  if (mode === "dropbox") {
    $("file-info").textContent = "Tresor in Dropbox";
  } else if (cache) {
    const date = cache.modified ? ` · Stand ${formatDate(cache.modified)}` : "";
    $("file-info").textContent = `${cache.name}${date} · nur lesen`;
  }
  show("unlock-view");
  if (ready) $("master").focus();
}

// ---------- choosing the source ----------

$("file-input").addEventListener("change", async (ev) => {
  const f = ev.target.files && ev.target.files[0];
  ev.target.value = "";
  if (!f) return;
  try {
    const text = await f.text();
    readHeader(text); // validate before accepting it
    setMode("file");
    setCache({ name: f.name, modified: f.lastModified || 0, text });
    showUnlock();
  } catch (e) {
    showError($("source-error"), e.message || "Die Datei konnte nicht gelesen werden.");
  }
});

$("change-source").addEventListener("click", () => {
  if (mode === "dropbox" && !confirm("Die Verbindung zu Dropbox auf diesem Gerät trennen?")) return;
  if (mode === "dropbox") dropbox.disconnect();
  setMode(null);
  setCache(null);
  showUnlock();
});

$("dropbox-start").addEventListener("click", async () => {
  showError($("connect-error"), "");
  $("upload-card").hidden = true;
  $("connect-code").value = "";
  $("connect-link").href = await dropbox.authorizeUrl();
  show("connect-view");
});

$("connect-back").addEventListener("click", () => showUnlock());

$("connect-btn").addEventListener("click", async () => {
  const code = $("connect-code").value;
  if (!code.trim()) return;
  const btn = $("connect-btn");
  btn.disabled = true;
  showError($("connect-error"), "");
  try {
    await dropbox.connect(code);
    const remote = await dropbox.download();
    if (remote) {
      setMode("dropbox");
      setCache({ name: "vault.pwmv", modified: 0, text: remote.text, rev: remote.rev });
      showUnlock();
    } else {
      $("upload-card").hidden = false;
    }
  } catch (e) {
    showError($("connect-error"), e.message);
  } finally {
    btn.disabled = false;
  }
});

$("upload-input").addEventListener("change", async (ev) => {
  const f = ev.target.files && ev.target.files[0];
  ev.target.value = "";
  if (!f) return;
  try {
    const text = await f.text();
    readHeader(text);
    const newRev = await dropbox.upload(text, null);
    setMode("dropbox");
    setCache({ name: "vault.pwmv", modified: 0, text, rev: newRev });
    showUnlock();
  } catch (e) {
    showError($("upload-error"), e instanceof dropbox.Conflict
      ? "In Dropbox liegt inzwischen schon ein Tresor. Tippe auf Zurück und verbinde neu."
      : e.message);
  }
});

// ---------- unlock / lock ----------

$("unlock-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("master").value;
  if (!pw) return;
  const btn = $("unlock-btn");
  btn.disabled = true;
  btn.textContent = "Entsperre …";
  showError($("unlock-error"), "");
  try {
    if (mode === "dropbox") await unlockDropbox(pw); else await unlockFile(pw);
    $("master").value = "";
    $("master").blur();
    filter = "all";
    $("search").value = "";
    lastActivity = Date.now();
    renderAll();
    show("list-view");
    if (mode === "dropbox") sync();
  } catch (e) {
    session = null;
    payload = null;
    const msg = e instanceof WrongPassword ? "Falsches Master-Passwort." : e.message;
    showError($("unlock-error"), msg || "Der Tresor konnte nicht geöffnet werden.");
    $("master").select();
  } finally {
    btn.disabled = false;
    btn.textContent = "Entsperren";
  }
});

async function unlockFile(pw) {
  ({ payload, session } = await unlockVault(cache.text, pw));
}

async function unlockDropbox(pw) {
  // Prefer the latest file from Dropbox; fall back to the copy on this device offline.
  let remote = null;
  try {
    remote = await dropbox.download();
  } catch (e) {
    if (!(e instanceof dropbox.Offline) || !cache) throw e;
  }
  if (remote) {
    ({ payload, session } = await unlockVault(remote.text, pw));
    rev = remote.rev;
    dirty = false;
    if (cache?.dirty) {
      // Changes made here while offline: combine them with the latest file.
      try {
        const local = await decryptWithSession(cache.text, session);
        const merged = mergePayloads(local, payload);
        dirty = !samePayload(merged, payload);
        payload = merged;
      } catch { /* the old copy used another password: drop it */ }
    }
    if (!dirty) setCache({ ...cache, text: remote.text, rev, dirty: false });
  } else if (cache) {
    ({ payload, session } = await unlockVault(cache.text, pw));
    rev = cache.rev || null;
    dirty = Boolean(cache.dirty);
    setBanner("Offline: du siehst den zuletzt geladenen Stand.");
  } else {
    throw new Error("In Dropbox wurde kein Tresor gefunden.");
  }
}

function lock(message = "") {
  if (!session && !payload) return;
  session = null;
  payload = null;
  rev = null;
  currentId = null;
  editingId = null;
  $("entries").replaceChildren();
  $("filters").replaceChildren();
  clearDetail();
  clearEdit();
  if (history.state && history.state.view) history.replaceState(null, "");
  showUnlock(message);
}

$("lock-btn").addEventListener("click", () => lock());

function autolockMs() {
  const m = Number(payload?.settings?.autolock_minutes ?? DEFAULT_AUTOLOCK_MIN);
  return m > 0 ? m * 60 * 1000 : Infinity;
}

function isUnlocked() {
  return Boolean(session);
}

for (const type of ["pointerdown", "keydown", "input", "scroll"]) {
  document.addEventListener(type, () => { lastActivity = Date.now(); }, { passive: true, capture: true });
}

setInterval(() => {
  if (isUnlocked() && Date.now() - lastActivity > autolockMs()) lock();
}, 10 * 1000);

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    hiddenAt = Date.now();
    return;
  }
  // Timers don't run while the app is in the background, so check on return.
  const away = hiddenAt ? Date.now() - hiddenAt : 0;
  hiddenAt = null;
  if (isUnlocked() && (away > Math.min(HIDDEN_LOCK_MS, autolockMs())
                       || Date.now() - lastActivity > autolockMs())) {
    lock();
  } else if (isUnlocked()) {
    sync();
  }
});

window.addEventListener("online", () => sync());

// ---------- syncing with Dropbox ----------

function setBanner(text, isError = false) {
  const b = $("sync-banner");
  b.textContent = text;
  b.hidden = !text;
  b.classList.toggle("error", isError);
}

/** Bring this device and Dropbox to the same state. Safe to call any time. */
function sync() {
  if (mode !== "dropbox" || !session) return Promise.resolve();
  if (!syncing) {
    syncing = doSync().finally(() => { syncing = null; });
  }
  return syncing;
}

async function doSync() {
  const mySession = session;
  try {
    for (let attempt = 0; attempt < 5; attempt++) {
      if (!dirty && rev && (await dropbox.revision()) === rev) break; // nothing new anywhere
      if (session !== mySession) return; // locked meanwhile
      const remote = await dropbox.download();
      if (session !== mySession) return;
      if (remote && remote.rev !== rev) {
        const remotePayload = await decryptWithSession(remote.text, session);
        const merged = mergePayloads(payload, remotePayload);
        const changed = !samePayload(merged, payload);
        dirty = !samePayload(merged, remotePayload);
        payload = merged;
        rev = remote.rev;
        if (!dirty) setCache({ ...cache, text: remote.text, rev, dirty: false });
        if (changed) renderAll();
      }
      if (!dirty) break;
      const text = await encryptVault(payload, session);
      try {
        rev = await dropbox.upload(text, remote ? rev : null);
        dirty = false;
        setCache({ ...cache, text, rev, dirty: false });
        break;
      } catch (e) {
        if (!(e instanceof dropbox.Conflict)) throw e;
        // Someone else saved in between: loop to merge their version.
      }
    }
    setBanner("");
  } catch (e) {
    if (session !== mySession) return;
    if (e instanceof PasswordChanged) {
      lock("Das Master-Passwort wurde geändert. Bitte mit dem neuen Passwort entsperren.");
    } else if (e instanceof dropbox.Offline) {
      setBanner(dirty ? "Offline: Änderungen werden übertragen, sobald du wieder online bist."
        : "Offline: du siehst den zuletzt geladenen Stand.");
    } else if (e instanceof dropbox.NotConnected) {
      setBanner("Die Verbindung zu Dropbox ist abgelaufen. Sperren und „Andere Quelle wählen“, "
        + "um neu zu verbinden.", true);
    } else {
      setBanner(`Abgleich fehlgeschlagen: ${e.message}`, true);
    }
  }
}

/** Keep a local change: encrypted copy on the device first, then Dropbox. */
async function commit() {
  dirty = true;
  renderAll();
  const text = await encryptVault(payload, session);
  setCache({ ...cache, text, rev, dirty: true });
  sync();
}

// ---------- list ----------

function entries() {
  return normaliseEntries(payload || {});
}

function rawEntry(id) {
  return (payload?.entries || []).find((e) => e && e.id === id) || null;
}

function matches(e, q) {
  if (!q) return true;
  return [e.title, e.username, e.url, e.notes, e.category].some((s) => s.toLowerCase().includes(q));
}

function renderAll() {
  renderFilters();
  renderList();
  if (!$("detail-view").hidden && currentId) {
    const e = entries().find((x) => x.id === currentId);
    if (e) fillDetail(e); else closeDetail();
  }
}

function renderFilters() {
  const list = entries();
  const cats = [...new Set(list.map((e) => e.category).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, "de"));
  if (filter !== "all" && filter !== "fav" && !cats.includes(filter)) filter = "all";
  const chips = [["all", "Alle"], ["fav", "★ Favoriten"], ...cats.map((c) => [c, c])];
  $("filters").replaceChildren(...chips.map(([value, label]) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "chip";
    b.textContent = label;
    b.setAttribute("aria-pressed", String(value === filter));
    b.addEventListener("click", () => {
      filter = value;
      renderFilters();
      renderList();
    });
    return b;
  }));
}

function renderList() {
  const all = entries();
  const q = $("search").value.trim().toLowerCase();
  const shown = all
    .filter((e) => filter === "all" || (filter === "fav" ? e.favorite : e.category === filter))
    .filter((e) => matches(e, q))
    .sort((a, b) => (b.favorite - a.favorite) || a.title.localeCompare(b.title, "de"));

  $("entries").replaceChildren(...shown.map((e) => {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    b.className = "entry";
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = (e.title.trim()[0] || "?").toUpperCase();
    const text = document.createElement("span");
    text.className = "entry-text";
    const t = document.createElement("span");
    t.className = "entry-title";
    t.textContent = (e.favorite ? "★ " : "") + (e.title || "(ohne Namen)");
    const u = document.createElement("span");
    u.className = "entry-sub";
    u.textContent = e.username || hostOf(e.url);
    text.append(t, u);
    b.append(avatar, text);
    b.addEventListener("click", () => openDetail(e.id));
    li.append(b);
    return li;
  }));

  const empty = $("empty");
  empty.hidden = shown.length > 0;
  empty.textContent = all.length ? "Keine Treffer." : "Der Tresor ist leer.";
  $("add-btn").hidden = !editable();
  $("source-info").textContent = mode === "dropbox" ? "Tresor in Dropbox"
    : cache && cache.modified ? `Stand der Tresordatei: ${formatDate(cache.modified)} · nur lesen`
      : "Nur lesen";
}

$("search").addEventListener("input", renderList);

// ---------- detail ----------

function hostOf(url) {
  return url.split("://").pop().split("/")[0].replace(/^www\./, "");
}

function safeHref(url) {
  const u = url.trim();
  if (!u) return null;
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:/i.test(u) ? u : "https://" + u);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : null;
  } catch {
    return null;
  }
}

function maskPassword(pw) {
  return pw ? "•".repeat(Math.min(Math.max(pw.length, 8), 16)) : "";
}

function current() {
  return entries().find((e) => e.id === currentId) || null;
}

function fillDetail(e) {
  $("d-title").textContent = e.title || "(ohne Namen)";
  $("d-username").textContent = e.username;
  const pw = $("d-password");
  pw.textContent = pw.dataset.revealed ? e.password : maskPassword(e.password);
  const href = safeHref(e.url);
  const link = $("d-url");
  link.textContent = e.url;
  if (href) link.href = href; else link.removeAttribute("href");
  $("d-category").textContent = e.category;
  $("d-notes").textContent = e.notes;
  $("f-username").hidden = !e.username;
  $("f-password").hidden = !e.password;
  $("f-url").hidden = !e.url;
  $("f-category").hidden = !e.category;
  $("f-notes").hidden = !e.notes;
  $("edit-btn").hidden = !editable();
}

function openDetail(id) {
  currentId = id;
  $("d-password").dataset.revealed = "";
  $("reveal").textContent = "Zeigen";
  fillDetail(current());
  history.pushState({ view: "detail" }, "");
  show("detail-view");
}

function clearDetail() {
  for (const id of ["d-title", "d-username", "d-password", "d-url", "d-category", "d-notes"]) {
    $(id).textContent = "";
  }
  $("d-url").removeAttribute("href");
}

function closeDetail() {
  currentId = null;
  clearDetail();
  if (isUnlocked()) show("list-view");
}

$("back-btn").addEventListener("click", () => {
  if (history.state && history.state.view) history.back(); else closeDetail();
});

window.addEventListener("popstate", () => {
  if (!$("edit-view").hidden) {
    closeEdit();
  } else {
    closeDetail();
  }
});

$("reveal").addEventListener("click", () => {
  const e = current();
  if (!e) return;
  const el = $("d-password");
  const revealed = !el.dataset.revealed;
  el.dataset.revealed = revealed ? "1" : "";
  el.textContent = revealed ? e.password : maskPassword(e.password);
  $("reveal").textContent = revealed ? "Verbergen" : "Zeigen";
});

// ---------- add / edit / delete ----------

function openEdit(id) {
  editingId = id;
  const e = id ? entries().find((x) => x.id === id) : null;
  $("e-heading").textContent = e ? "Bearbeiten" : "Neuer Eintrag";
  $("e-title").value = e?.title || "";
  $("e-username").value = e?.username || "";
  $("e-password").value = e?.password || "";
  $("e-url").value = e?.url || "";
  $("e-category").value = e?.category || (filter !== "all" && filter !== "fav" ? filter : "Login");
  $("e-notes").value = e?.notes || "";
  $("e-favorite").checked = e?.favorite || false;
  $("delete-btn").hidden = !e;
  showError($("edit-error"), "");
  const cats = [...new Set([...(payload.categories || []), ...entries().map((x) => x.category)])]
    .filter(Boolean);
  $("category-list").replaceChildren(...cats.map((c) => {
    const o = document.createElement("option");
    o.value = c;
    return o;
  }));
  history.pushState({ view: "edit" }, "");
  show("edit-view");
  if (!e) $("e-title").focus();
}

function clearEdit() {
  for (const id of ["e-title", "e-username", "e-password", "e-url", "e-category", "e-notes"]) {
    $(id).value = "";
  }
}

function closeEdit() {
  const backTo = editingId ? "detail-view" : "list-view";
  editingId = null;
  clearEdit();
  if (!isUnlocked()) return;
  if (backTo === "detail-view" && current()) {
    fillDetail(current());
    show("detail-view");
  } else {
    show("list-view");
  }
}

function leaveEdit() {
  if (history.state && history.state.view === "edit") history.back(); else closeEdit();
}

$("add-btn").addEventListener("click", () => openEdit(""));
$("edit-btn").addEventListener("click", () => openEdit(currentId));
$("edit-cancel").addEventListener("click", leaveEdit);

$("e-generate").addEventListener("click", () => {
  const field = $("e-password");
  if (field.value && !confirm("Das bisherige Passwort ersetzen?")) return;
  field.value = generatePassword(payload.settings || {});
});

function nowSeconds() {
  return Date.now() / 1000;
}

$("edit-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const values = {
    title: $("e-title").value.trim(),
    username: $("e-username").value.trim(),
    password: $("e-password").value,
    url: $("e-url").value.trim(),
    category: $("e-category").value.trim() || "Login",
    notes: $("e-notes").value,
    favorite: $("e-favorite").checked,
  };
  if (!values.title) {
    showError($("edit-error"), "Bitte einen Namen eingeben.");
    return;
  }
  const now = nowSeconds();
  let id = editingId;
  if (id) {
    const e = rawEntry(id);
    if (!e) {
      showError($("edit-error"), "Dieser Eintrag wurde inzwischen auf einem anderen Gerät gelöscht.");
      return;
    }
    if (values.password !== (e.password || "") && e.password) {
      e.history = [{ password: e.password, until: now }, ...(Array.isArray(e.history) ? e.history : [])]
        .slice(0, HISTORY_LIMIT);
      e.password_changed = now;
    }
    Object.assign(e, values, { modified: now });
  } else {
    id = crypto.randomUUID().replace(/-/g, "");
    payload.entries = [...(payload.entries || []), {
      ...values, id, created: now, modified: now, password_changed: now, history: [],
    }];
  }
  if (!(payload.categories || []).includes(values.category)) {
    payload.categories = [...(payload.categories || []), values.category];
  }
  editingId = null;
  clearEdit();
  currentId = id;
  $("d-password").dataset.revealed = "";
  $("reveal").textContent = "Zeigen";
  history.replaceState({ view: "detail" }, "");
  show("detail-view");
  await commit();
  toast("Gesichert");
});

$("delete-btn").addEventListener("click", async () => {
  const id = editingId;
  const e = rawEntry(id);
  if (!e || !confirm(`„${e.title || "Eintrag"}“ wirklich löschen?`)) return;
  payload.entries = payload.entries.filter((x) => x.id !== id);
  payload.deleted = { ...(payload.deleted || {}), [id]: nowSeconds() };
  editingId = null;
  currentId = null;
  clearEdit();
  clearDetail();
  history.replaceState(null, "");
  show("list-view");
  await commit();
  toast("Gelöscht");
});

// ---------- clipboard ----------

async function writeClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for browsers without the async clipboard API.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

for (const btn of document.querySelectorAll("[data-copy]")) {
  btn.addEventListener("click", async () => {
    const e = current();
    if (!e) return;
    const field = btn.dataset.copy;
    if (!(await writeClipboard(e[field]))) {
      toast("Kopieren hat nicht geklappt.");
      return;
    }
    if (field !== "password") {
      toast("Benutzername kopiert");
      return;
    }
    const secs = Number(payload?.settings?.clipboard_clear_seconds ?? DEFAULT_CLIPBOARD_SEC);
    clearTimeout(clipboardTimer);
    if (secs > 0) {
      // iOS only allows this while the app is open, so it is best effort.
      clipboardTimer = setTimeout(() => {
        if (!document.hidden) navigator.clipboard?.writeText("").catch(() => {});
      }, secs * 1000);
      toast(`Passwort kopiert, wird nach ${secs} s geleert`);
    } else {
      toast("Passwort kopiert");
    }
  });
}

let toastTimer = null;
function toast(message) {
  const t = $("toast");
  t.textContent = message;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 2500);
}

// ---------- start ----------

mode = load(MODE_KEY);
cache = load(CACHE_KEY);
if (cache && typeof cache.text !== "string") cache = null;
if (!mode && cache) mode = "file"; // stored by the first, read-only version
if (mode === "dropbox" && !dropbox.isConnected()) mode = null;
showUnlock();

if ("serviceWorker" in navigator && window.isSecureContext) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}
