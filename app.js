// PW-Manager for iPhone: opens the encrypted vault file and shows the entries
// read-only. Nothing leaves the device; the decrypted entries live only in
// memory while unlocked.

import { decryptVault, normaliseEntries, readHeader, WrongPassword } from "./vault.js";

const STORE_KEY = "pwm.vault";
const HIDDEN_LOCK_MS = 2 * 60 * 1000; // lock after 2 min in the background
const DEFAULT_AUTOLOCK_MIN = 5;
const DEFAULT_CLIPBOARD_SEC = 30;

const $ = (id) => document.getElementById(id);

let file = null;        // {name, modified, text} of the encrypted vault
let entries = [];       // decrypted entries while unlocked
let settings = {};
let filter = "all";     // "all", "fav" or a category name
let current = null;     // entry shown in the detail view
let lastActivity = Date.now();
let hiddenAt = null;
let clipboardTimer = null;

// ---------- storage of the encrypted file ----------

function loadStored() {
  try {
    const s = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
    if (s && typeof s.text === "string") return s;
  } catch { /* storage unavailable */ }
  return null;
}

function store(f) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(f));
  } catch { /* private mode or full: just don't remember */ }
}

function forget() {
  try { localStorage.removeItem(STORE_KEY); } catch { /* ignore */ }
}

// ---------- views ----------

function show(view) {
  for (const v of ["unlock-view", "list-view", "detail-view"]) $(v).hidden = v !== view;
  window.scrollTo(0, 0);
}

function formatDate(ms) {
  if (!ms) return "";
  return new Date(ms).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" });
}

function showUnlock() {
  const hasFile = Boolean(file);
  $("unlock-form").hidden = !hasFile;
  $("choose-card").hidden = hasFile;
  $("unlock-error").hidden = true;
  if (hasFile) {
    const date = file.modified ? ` · Stand ${formatDate(file.modified)}` : "";
    $("file-info").textContent = `${file.name}${date}`;
  }
  show("unlock-view");
  if (hasFile) $("master").focus();
}

function showError(el, message) {
  el.textContent = message;
  el.hidden = false;
}

// ---------- choosing a file ----------

$("file-input").addEventListener("change", async (ev) => {
  const f = ev.target.files && ev.target.files[0];
  ev.target.value = "";
  if (!f) return;
  $("choose-error").hidden = true;
  try {
    const text = await f.text();
    readHeader(text); // validate before accepting it
    file = { name: f.name, modified: f.lastModified || 0, text };
    if ($("remember").checked) store(file); else forget();
    showUnlock();
  } catch (e) {
    showError($("choose-error"), e.message || "Die Datei konnte nicht gelesen werden.");
  }
});

$("change-file").addEventListener("click", () => {
  file = null;
  showUnlock();
});

// ---------- unlock / lock ----------

$("unlock-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("master").value;
  if (!pw || !file) return;
  const btn = $("unlock-btn");
  btn.disabled = true;
  btn.textContent = "Entsperre …";
  $("unlock-error").hidden = true;
  try {
    const payload = await decryptVault(file.text, pw);
    entries = normaliseEntries(payload);
    settings = payload.settings && typeof payload.settings === "object" ? payload.settings : {};
    $("master").value = "";
    $("master").blur();
    filter = "all";
    $("search").value = "";
    lastActivity = Date.now();
    renderFilters();
    renderList();
    show("list-view");
  } catch (e) {
    const msg = e instanceof WrongPassword ? "Falsches Master-Passwort." : e.message;
    showError($("unlock-error"), msg || "Der Tresor konnte nicht geöffnet werden.");
    $("master").select();
  } finally {
    btn.disabled = false;
    btn.textContent = "Entsperren";
  }
});

function lock() {
  if (!entries.length && $("unlock-view").hidden === false) return;
  entries = [];
  settings = {};
  current = null;
  $("entries").replaceChildren();
  $("filters").replaceChildren();
  clearDetail();
  if (history.state && history.state.detail) history.replaceState(null, "");
  showUnlock();
}

$("lock-btn").addEventListener("click", lock);

function autolockMs() {
  const m = Number(settings.autolock_minutes ?? DEFAULT_AUTOLOCK_MIN);
  return m > 0 ? m * 60 * 1000 : Infinity;
}

function isUnlocked() {
  return $("unlock-view").hidden;
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
  }
});

// ---------- list ----------

function matches(e, q) {
  if (!q) return true;
  return [e.title, e.username, e.url, e.notes, e.category].some((s) => s.toLowerCase().includes(q));
}

function renderFilters() {
  const cats = [...new Set(entries.map((e) => e.category).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, "de"));
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
  const q = $("search").value.trim().toLowerCase();
  const shown = entries
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
    b.addEventListener("click", () => openDetail(e));
    li.append(b);
    return li;
  }));

  const empty = $("empty");
  empty.hidden = shown.length > 0;
  empty.textContent = entries.length ? "Keine Treffer." : "Der Tresor ist leer.";
  $("stale").textContent = file && file.modified
    ? `Stand der Tresordatei: ${formatDate(file.modified)}` : "";
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

function openDetail(e) {
  current = e;
  $("d-title").textContent = e.title || "(ohne Namen)";
  $("d-username").textContent = e.username;
  $("d-password").textContent = maskPassword(e.password);
  $("d-password").dataset.revealed = "";
  $("reveal").textContent = "Zeigen";
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
  history.pushState({ detail: true }, "");
  show("detail-view");
}

function clearDetail() {
  for (const id of ["d-title", "d-username", "d-password", "d-url", "d-category", "d-notes"]) {
    $(id).textContent = "";
  }
  $("d-url").removeAttribute("href");
}

function closeDetail() {
  current = null;
  clearDetail();
  if (isUnlocked()) show("list-view");
}

$("back-btn").addEventListener("click", () => {
  if (history.state && history.state.detail) history.back(); else closeDetail();
});
window.addEventListener("popstate", closeDetail);

$("reveal").addEventListener("click", () => {
  if (!current) return;
  const el = $("d-password");
  const revealed = !el.dataset.revealed;
  el.dataset.revealed = revealed ? "1" : "";
  el.textContent = revealed ? current.password : maskPassword(current.password);
  $("reveal").textContent = revealed ? "Verbergen" : "Zeigen";
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
    if (!current) return;
    const field = btn.dataset.copy;
    if (!(await writeClipboard(current[field]))) {
      toast("Kopieren hat nicht geklappt.");
      return;
    }
    if (field !== "password") {
      toast("Benutzername kopiert");
      return;
    }
    const secs = Number(settings.clipboard_clear_seconds ?? DEFAULT_CLIPBOARD_SEC);
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

file = loadStored();
showUnlock();

if ("serviceWorker" in navigator && window.isSecureContext) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}
