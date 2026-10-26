import { createHash } from "node:crypto";

const PASSWORD_WORDS = ["Harbor", "River", "Maple", "Copper", "Willow", "Summit", "Cedar", "Marble", "Falcon", "Juniper", "Saddle", "Beacon", "Meadow", "Granite", "Voyage", "Anchor"];
const PASSWORD_TAILS = ["lane", "rock", "pine", "ford", "gate", "hill", "bay", "wood", "port", "vale"];
const SYMBOLS = ["#", "@", "!", "%", "&"];

function tokenHash(seed, kind) {
  return createHash("sha256").update(`${seed}:${kind}`).digest("hex");
}

function passwordFromHash(hex) {
  const word = PASSWORD_WORDS[Number.parseInt(hex.slice(0, 2), 16) % PASSWORD_WORDS.length];
  const tail = PASSWORD_TAILS[Number.parseInt(hex.slice(2, 4), 16) % PASSWORD_TAILS.length];
  const digits = String(Number.parseInt(hex.slice(4, 8), 16) % 9000 + 1000);
  const symbol = SYMBOLS[Number.parseInt(hex.slice(8, 10), 16) % SYMBOLS.length];
  return `${word}${symbol}${digits}${tail}`;
}

/**
 * Create deterministic honeytokens for a persona.
 *
 * @param {object} persona
 * @param {object} [options]
 * @param {boolean} [options.enabled]
 * @returns {{ tokens: Array<object>, lookup: (text: string) => Array<object>, plantedIn: (kind: string) => Array<string> }}
 */
export function createHoneytokens(persona, options = {}) {
  const enabled = options.enabled !== false;
  if (!enabled || !persona) {
    return { tokens: [], lookup: () => [], plantedIn: () => [] };
  }
  const seed = persona.seed || "change-me-default-seed";
  const slugLetters = persona.company.slug.replace(/[^a-z]/g, "").slice(0, 3) || "abc";
  const defs = [
    { kind: "ssh_password", account: "deploy" },
    { kind: "ftp_password", account: "backup" },
    { kind: "wp_password", account: "webmaster" },
    { kind: "db_password", account: null },
    { kind: "api_key", account: null },
  ];
  const tokens = defs.map((def) => {
    const hex = tokenHash(seed, def.kind);
    const value = def.kind === "api_key" ? `${slugLetters}_live_${hex.slice(0, 32)}` : passwordFromHash(hex);
    const token = { id: `ht-${hex.slice(0, 8)}`, kind: def.kind, value, plantedIn: [] };
    if (def.account) token.account = def.account;
    return token;
  });
  const planted = {
    ssh_password: ["/home/deploy/notes.txt", "/backup/notes.txt"],
    ftp_password: ["/home/deploy/.bash_history", "/backup/config.bak"],
    wp_password: ["/home/deploy/notes.txt", "/backup/notes.txt"],
    db_password: ["/var/www/html/wp-config.php", "/var/www/html/.env", "/.env", "/wp-config.php.bak", "/backup/config.bak"],
    api_key: ["/var/www/html/.env", "/.env", "/backup/config.bak"],
  };
  for (const token of tokens) token.plantedIn = [...(planted[token.kind] || [])];
  function lookup(text) {
    if (!text) return [];
    const candidates = [String(text)];
    try {
      const decoded = decodeURIComponent(String(text));
      if (decoded !== String(text)) candidates.push(decoded);
    } catch {
      /* Ignore undecodable input. */
    }
    return tokens.filter((token) => candidates.some((candidate) => candidate.includes(token.value)));
  }
  function plantedIn(kind) {
    return [...(planted[kind] || [])];
  }
  return { tokens, lookup, plantedIn };
}
