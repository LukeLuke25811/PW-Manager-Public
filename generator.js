// Password generator with the same character sets as pwmanager/generator.py.

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~";
const AMBIGUOUS = new Set("Il1O0o|`'\"");

function randomIndex(n) {
  // Rejection sampling avoids modulo bias.
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limit);
  return buf[0] % n;
}

/** Uses the vault's generator settings (gen_length, gen_upper, ...). */
export function generatePassword(settings = {}) {
  const length = Math.max(4, Math.min(128, Number(settings.gen_length) || 20));
  const pools = [];
  for (const [key, chars] of [["gen_upper", UPPER], ["gen_lower", LOWER],
                              ["gen_digits", DIGITS], ["gen_symbols", SYMBOLS]]) {
    if (settings[key] === false) continue;
    pools.push(settings.gen_exclude_ambiguous ? [...chars].filter((c) => !AMBIGUOUS.has(c)).join("") : chars);
  }
  if (!pools.length) pools.push(LOWER);
  const alphabet = pools.join("");
  for (;;) {
    const pw = Array.from({ length }, () => alphabet[randomIndex(alphabet.length)]);
    if (length < pools.length || pools.every((p) => pw.some((c) => p.includes(c)))) return pw.join("");
  }
}
