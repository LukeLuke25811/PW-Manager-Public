// Merge two versions of a vault payload. Same rules as pwmanager/sync.py;
// keep them in step (web/tests/sync.test.mjs checks both give the same result).
//
// The newer version of each entry (by `modified`) wins; on a tie, local wins.
// Deletions are kept as tombstones in payload.deleted ({id: time}).
// Settings travel as a whole; the more recently changed set wins.

const TOMBSTONE_DAYS = 400;

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

export function mergePayloads(local, remote, now = Date.now() / 1000) {
  const deleted = {};
  for (const src of [remote, local]) {
    for (const [id, t] of Object.entries(src.deleted || {})) {
      deleted[id] = Math.max(deleted[id] ?? num(t), num(t));
    }
  }
  const cutoff = now - TOMBSTONE_DAYS * 86400;
  for (const id of Object.keys(deleted)) if (deleted[id] < cutoff) delete deleted[id];

  const byId = new Map();
  for (const src of [local, remote]) {
    for (const e of Array.isArray(src.entries) ? src.entries : []) {
      if (!e || typeof e !== "object" || !e.id) continue;
      const id = String(e.id);
      const have = byId.get(id);
      if (!have || num(e.modified) > num(have.modified)) byId.set(id, e);
    }
  }
  const entries = [...byId.entries()]
    .filter(([id, e]) => (deleted[id] ?? -1) < num(e.modified))
    .map(([, e]) => e);

  const categories = [...(local.categories || [])];
  for (const c of remote.categories || []) if (!categories.includes(c)) categories.push(c);

  const newer = num(remote.settings_modified) > num(local.settings_modified) ? remote : local;

  return {
    ...remote,
    ...local,
    entries,
    deleted,
    categories,
    settings: { ...(newer.settings || {}) },
    settings_modified: num(newer.settings_modified),
  };
}

/** Order-insensitive comparison of two payloads. */
export function samePayload(a, b) {
  const canon = (p) => JSON.stringify(sortKeys({
    ...p,
    entries: [...(p.entries || [])].sort((x, y) => String(x.id).localeCompare(String(y.id))),
    categories: [...(p.categories || [])].sort(),
  }));
  return canon(a) === canon(b);
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  }
  return v;
}
