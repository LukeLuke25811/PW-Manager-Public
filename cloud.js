// Dropbox storage for the vault file, so the PC and the phone share one file.
//
// The app only has access to its own app folder (Dropbox/Apps/<app name>/).
// Sign-in uses OAuth with PKCE and no redirect: Dropbox shows a code that is
// pasted into the app, which works inside an iPhone home-screen app. The
// refresh token is kept in this browser's storage; the vault itself stays
// encrypted with the master password, which never leaves the device.

import { DROPBOX_APP_KEY } from "./config.js";

const AUTH_URL = "https://www.dropbox.com/oauth2/authorize";
const TOKEN_URL = "https://api.dropboxapi.com/oauth2/token";
const API = "https://api.dropboxapi.com/2";
const CONTENT = "https://content.dropboxapi.com/2";
const TOKEN_KEY = "pwm.dropbox";
const PKCE_KEY = "pwm.dropbox.pkce";
export const VAULT_PATH = "/vault.pwmv";

export class Conflict extends Error {}
export class Offline extends Error {}
export class NotConnected extends Error {}

let accessToken = null;
let accessExpires = 0;

function load(key) {
  try { return JSON.parse(localStorage.getItem(key) || "null"); } catch { return null; }
}

function save(key, value) {
  try {
    if (value == null) localStorage.removeItem(key); else localStorage.setItem(key, JSON.stringify(value));
  } catch { /* storage unavailable */ }
}

function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function isConfigured() {
  return Boolean(DROPBOX_APP_KEY);
}

export function isConnected() {
  return Boolean(load(TOKEN_KEY)?.refresh_token);
}

export function disconnect() {
  save(TOKEN_KEY, null);
  save(PKCE_KEY, null);
  accessToken = null;
}

/** Start sign-in: returns the Dropbox page to open. */
export async function authorizeUrl() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
  const challenge = b64url(new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  save(PKCE_KEY, { verifier });
  const q = new URLSearchParams({
    client_id: DROPBOX_APP_KEY,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    token_access_type: "offline",
  });
  return `${AUTH_URL}?${q}`;
}

async function tokenRequest(params) {
  let r;
  try {
    r = await fetch(TOKEN_URL, { method: "POST", body: new URLSearchParams(params) });
  } catch {
    throw new Offline("Keine Verbindung zu Dropbox.");
  }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new NotConnected(body.error_description || "Dropbox hat die Anmeldung abgelehnt.");
  accessToken = body.access_token;
  accessExpires = Date.now() + (Number(body.expires_in) || 3600) * 1000 - 60_000;
  return body;
}

/** Finish sign-in with the code Dropbox showed. */
export async function connect(code) {
  const pkce = load(PKCE_KEY);
  if (!pkce) throw new NotConnected("Bitte zuerst „Bei Dropbox anmelden“ antippen.");
  const body = await tokenRequest({
    grant_type: "authorization_code",
    code: code.trim(),
    client_id: DROPBOX_APP_KEY,
    code_verifier: pkce.verifier,
  });
  if (!body.refresh_token) throw new NotConnected("Dropbox hat keinen dauerhaften Zugang erteilt.");
  save(TOKEN_KEY, { refresh_token: body.refresh_token });
  save(PKCE_KEY, null);
}

async function token() {
  if (accessToken && Date.now() < accessExpires) return accessToken;
  const stored = load(TOKEN_KEY);
  if (!stored?.refresh_token) throw new NotConnected("Nicht mit Dropbox verbunden.");
  try {
    await tokenRequest({
      grant_type: "refresh_token",
      refresh_token: stored.refresh_token,
      client_id: DROPBOX_APP_KEY,
    });
  } catch (e) {
    if (e instanceof NotConnected) disconnect(); // access was revoked
    throw e;
  }
  return accessToken;
}

async function call(url, { arg, body, json } = {}) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const headers = { Authorization: `Bearer ${await token()}` };
    if (arg) headers["Dropbox-API-Arg"] = JSON.stringify(arg);
    if (json) headers["Content-Type"] = "application/json";
    if (body != null && !json) headers["Content-Type"] = "application/octet-stream";
    let r;
    try {
      r = await fetch(url, { method: "POST", headers, body: json ? JSON.stringify(json) : body });
    } catch {
      throw new Offline("Keine Verbindung zu Dropbox.");
    }
    if (r.status === 401 && attempt === 0) {
      accessToken = null;
      continue;
    }
    return r;
  }
  throw new NotConnected("Dropbox-Anmeldung abgelaufen.");
}

async function errorSummary(r) {
  const body = await r.json().catch(() => ({}));
  return String(body.error_summary || `HTTP ${r.status}`);
}

async function missingOrThrow(r) {
  const summary = await errorSummary(r);
  if (r.status === 409 && summary.includes("not_found")) return null;
  throw new Error(`Dropbox: ${summary}`);
}

/** Current revision of the vault file, or null if there is none. */
export async function revision() {
  const r = await call(`${API}/files/get_metadata`, { json: { path: VAULT_PATH } });
  if (!r.ok) return missingOrThrow(r);
  return (await r.json()).rev;
}

/** Download the vault file: {text, rev}, or null if there is none yet. */
export async function download() {
  const r = await call(`${CONTENT}/files/download`, { arg: { path: VAULT_PATH } });
  if (!r.ok) return missingOrThrow(r);
  const text = await r.text();
  let rev = null;
  try { rev = JSON.parse(r.headers.get("Dropbox-API-Result") || "null")?.rev; } catch { /* hidden */ }
  return { text, rev: rev || await revision() };
}

/**
 * Upload the vault file. `rev` is the revision the change is based on (null
 * for a new file); if the file changed meanwhile this throws Conflict.
 */
export async function upload(text, rev) {
  const r = await call(`${CONTENT}/files/upload`, {
    arg: {
      path: VAULT_PATH,
      mode: rev ? { ".tag": "update", update: rev } : { ".tag": "add" },
      autorename: false,
      mute: true,
    },
    body: new TextEncoder().encode(text),
  });
  if (r.status === 409) {
    const summary = await errorSummary(r);
    if (summary.includes("conflict")) throw new Conflict("Die Datei wurde inzwischen geändert.");
    throw new Error(`Dropbox: ${summary}`);
  }
  if (!r.ok) throw new Error(`Dropbox: ${await errorSummary(r)}`);
  return (await r.json()).rev;
}
