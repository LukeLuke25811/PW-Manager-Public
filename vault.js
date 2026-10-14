// Reads a PW-Manager vault file (.pwmv) in the browser.
//
// Mirrors pwmanager/crypto.py: Argon2id derives a 256-bit key from the master
// password, AES-256-GCM decrypts the payload, and the header (format, version,
// KDF parameters) is bound to the ciphertext as associated data.
//
// Argon2id comes from hash-wasm (vendor/argon2.umd.min.js, global `hashwasm`);
// AES-GCM from the browser's built-in Web Crypto.

export const FORMAT_NAME = "pwmanager-vault";
export const FORMAT_VERSION = 1;

// Same guard rails as crypto.py: refuse absurd or weakened parameters.
const LIMITS = {
  iterations: [1, 50],
  memory_kib: [8 * 1024, 4 * 1024 * 1024],
  lanes: [1, 64],
};

export class VaultError extends Error {}
export class WrongPassword extends VaultError {}

function b64d(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4) {
    throw new VaultError("Die Tresordatei ist beschädigt.");
  }
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64e(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// json.dumps(obj, sort_keys=True, separators=(",", ":")) for the header,
// which only holds ASCII strings, integers and nested objects.
function canonicalJson(value) {
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

export function readHeader(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new VaultError("Diese Datei ist kein Tresor (oder sie ist beschädigt).");
  }
  if (!doc || typeof doc !== "object" || doc.format !== FORMAT_NAME) {
    throw new VaultError("Diese Datei ist kein PW-Manager-Tresor.");
  }
  if (doc.version !== FORMAT_VERSION) {
    throw new VaultError(`Nicht unterstützte Tresor-Version: ${doc.version}`);
  }
  if (doc.cipher !== "aes-256-gcm") {
    throw new VaultError(`Nicht unterstützte Verschlüsselung: ${doc.cipher}`);
  }
  const kdf = doc.kdf || {};
  if (kdf.name !== "argon2id") {
    throw new VaultError(`Nicht unterstützte Schlüsselableitung: ${kdf.name}`);
  }
  const params = { salt: b64d(kdf.salt) };
  for (const [name, [min, max]] of Object.entries(LIMITS)) {
    const v = kdf[name];
    if (!Number.isInteger(v) || v < min || v > max) {
      throw new VaultError("Die Einstellungen der Schlüsselableitung sind ungültig.");
    }
    params[name] = v;
  }
  if (params.salt.length < 16) {
    throw new VaultError("Die Einstellungen der Schlüsselableitung sind ungültig.");
  }
  return { doc, params };
}

function header(params) {
  return {
    format: FORMAT_NAME,
    version: FORMAT_VERSION,
    cipher: "aes-256-gcm",
    kdf: {
      name: "argon2id",
      salt: b64e(params.salt),
      iterations: params.iterations,
      memory_kib: params.memory_kib,
      lanes: params.lanes,
    },
  };
}

async function deriveKey(password, params) {
  const argon2id = globalThis.hashwasm?.argon2id;
  if (!argon2id) throw new VaultError("Argon2 konnte nicht geladen werden.");
  return argon2id({
    password: new TextEncoder().encode(password),
    salt: params.salt,
    iterations: params.iterations,
    memorySize: params.memory_kib,
    parallelism: params.lanes,
    hashLength: 32,
    outputType: "binary",
  });
}

/** Decrypt the text of a .pwmv file. Returns the payload {entries, settings, categories}. */
export async function decryptVault(text, password) {
  const { doc, params } = readHeader(text);
  const nonce = b64d(doc.nonce);
  const ciphertext = b64d(doc.data);
  const rawKey = await deriveKey(password, params);
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  rawKey.fill(0);
  const aad = new TextEncoder().encode(canonicalJson(header(params)));
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, ciphertext);
  } catch {
    throw new WrongPassword("Falsches Master-Passwort.");
  }
  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain));
  } catch {
    throw new VaultError("Der Tresorinhalt ist beschädigt.");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new VaultError("Der Tresorinhalt ist beschädigt.");
  }
  return payload;
}

const STRING_FIELDS = ["id", "title", "username", "password", "url", "notes", "category"];

/** Normalise entries defensively, like Entry.from_dict in vault.py. */
export function normaliseEntries(payload) {
  const list = Array.isArray(payload.entries) ? payload.entries : [];
  return list.filter((e) => e && typeof e === "object").map((e) => {
    const out = {};
    for (const f of STRING_FIELDS) out[f] = e[f] == null ? "" : String(e[f]);
    out.favorite = Boolean(e.favorite);
    out.modified = Number(e.modified) || 0;
    return out;
  });
}
