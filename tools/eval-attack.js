import { readFileSync } from "node:fs";

export const DEFAULT_API_BASE = "http://127.0.0.1:3001";
export const EVENT_RULE_TECHNIQUES = [
  { techniqueId: "T1110.001", tactic: "Credential Access" },
  { techniqueId: "T1078", tactic: "Initial Access" },
];

export function buildAllowedMap(rules) {
  const map = new Map();
  for (const rule of rules) {
    if (rule && rule.techniqueId && rule.tactic && !map.has(rule.techniqueId)) {
      map.set(rule.techniqueId, rule.tactic);
    }
  }
  for (const entry of EVENT_RULE_TECHNIQUES) {
    if (!map.has(entry.techniqueId)) map.set(entry.techniqueId, entry.tactic);
  }
  return map;
}

export function loadAllowedMap() {
  const text = readFileSync(new URL("../packages/mitre/src/rules.json", import.meta.url), "utf8");
  const rules = JSON.parse(text);
  return buildAllowedMap(rules);
}

export function roundPercent(value) {
  return Math.round(value * 100) / 100;
}

export function computeAttack(attackers, profiles, allowedMap) {
  const counts = new Map();
  const docs = [...attackers, ...profiles];
  for (const doc of docs) {
    const ids = Array.isArray(doc.mitreTechniqueIds) ? [...new Set(doc.mitreTechniqueIds)] : [];
    for (const id of ids) {
      counts.set(id, (counts.get(id) || 0) + 1);
    }
  }
  const observedIds = [...counts.keys()].sort();
  const observed = observedIds.map((id) => ({
    techniqueId: id,
    tactic: allowedMap.has(id) ? allowedMap.get(id) : "unknown",
    count: counts.get(id),
  }));
  const observedAllowedIds = observedIds.filter((id) => allowedMap.has(id));
  const unknown = observedIds.filter((id) => !allowedMap.has(id)).map((id) => ({
    techniqueId: id,
    count: counts.get(id),
  }));
  const neverObserved = [...allowedMap.keys()].filter((id) => !counts.has(id)).sort().map((id) => ({
    techniqueId: id,
    tactic: allowedMap.get(id),
  }));
  const allowedTotal = allowedMap.size;
  const coverageFraction = allowedTotal === 0 ? null : observedAllowedIds.length / allowedTotal;
  return {
    totalUnique: observedIds.length,
    observed,
    allowedTotal,
    observedAllowed: observedAllowedIds.length,
    coverageFraction,
    coveragePercent: coverageFraction === null ? null : roundPercent(coverageFraction * 100),
    neverObserved,
    unknown,
  };
}

export function formatAttackText(summary) {
  const computed = summary.computed;
  const lines = [
    "evaluation: attack",
    `api base: ${summary.apiBase}`,
    `attackers fetched: ${summary.attackersFetched}`,
    `profiles fetched: ${summary.profilesFetched}`,
    `total unique techniques observed: ${computed.totalUnique}`,
    "observed techniques:",
  ];
  if (computed.observed.length === 0) lines.push("none");
  for (const entry of computed.observed) {
    lines.push(`${entry.techniqueId} ${entry.tactic} ${entry.count}`);
  }
  lines.push(`allowed techniques total: ${computed.allowedTotal}`);
  lines.push(`observed allowed techniques: ${computed.observedAllowed}`);
  lines.push(`coverage fraction: ${computed.coverageFraction === null ? "TBD" : `${computed.observedAllowed}/${computed.allowedTotal}`}`);
  lines.push(`coverage percent: ${computed.coveragePercent === null ? "TBD" : `${computed.coveragePercent}%`}`);
  lines.push("allowed techniques never observed:");
  if (computed.neverObserved.length === 0) lines.push("none");
  for (const entry of computed.neverObserved) {
    lines.push(`${entry.techniqueId} ${entry.tactic}`);
  }
  lines.push("unknown techniques:");
  if (computed.unknown.length === 0) lines.push("none");
  for (const entry of computed.unknown) {
    lines.push(`${entry.techniqueId} ${entry.count}`);
  }
  return lines.join("\n");
}

export function attackToJson(summary) {
  const computed = summary.computed;
  return {
    evaluation: "attack",
    apiBase: summary.apiBase,
    attackersFetched: summary.attackersFetched,
    profilesFetched: summary.profilesFetched,
    totalUnique: computed.totalUnique,
    observed: computed.observed,
    allowedTotal: computed.allowedTotal,
    observedAllowed: computed.observedAllowed,
    coverageFraction: computed.coverageFraction === null ? "TBD" : computed.coverageFraction,
    coveragePercent: computed.coveragePercent === null ? "TBD" : computed.coveragePercent,
    neverObserved: computed.neverObserved,
    unknown: computed.unknown,
  };
}

export async function fetchList(apiBase, path, fetchFn) {
  const response = await fetchFn(`${apiBase}${path}`);
  if (!response.ok) throw new Error(`API request failed: ${path}`);
  const body = await response.json();
  if (Array.isArray(body)) return body;
  if (body && Array.isArray(body.data)) return body.data;
  return [];
}

export async function summarizeAttack(apiBase, fetchFn = fetch) {
  const attackers = await fetchList(apiBase, "/api/attackers?limit=50", fetchFn);
  const profiles = await fetchList(apiBase, "/api/profiles?limit=200", fetchFn);
  const allowedMap = loadAllowedMap();
  return {
    apiBase,
    attackersFetched: attackers.length,
    profilesFetched: profiles.length,
    computed: computeAttack(attackers, profiles, allowedMap),
  };
}

export function parseAttackArgs(argv) {
  const options = { apiBase: DEFAULT_API_BASE };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--api-base") {
      options.apiBase = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!options.apiBase) throw new Error("api base required");
  return options;
}

export async function runAttackCli(argv, options = {}) {
  let cliOptions;
  try {
    cliOptions = parseAttackArgs(argv);
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  let summary;
  try {
    summary = await summarizeAttack(cliOptions.apiBase, options.fetchFn || fetch);
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  console.log(formatAttackText(summary));
  console.log("JSON:");
  console.log(JSON.stringify(attackToJson(summary), null, 2));
  return 0;
}

async function main(argv) {
  process.exitCode = await runAttackCli(argv);
}

if (process.argv[1] && process.argv[1].endsWith("eval-attack.js")) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
