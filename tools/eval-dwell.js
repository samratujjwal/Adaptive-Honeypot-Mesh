export const DEFAULT_API_BASE = "http://127.0.0.1:3001";

export function roundSeconds(value) {
  return Math.round(value * 1000) / 1000;
}

export function median(values) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[middle];
  return (sorted[middle - 1] + sorted[middle]) / 2;
}

export function mean(values) {
  if (values.length === 0) return null;
  let sum = 0;
  for (const value of values) sum += value;
  return sum / values.length;
}

export function maxValue(values) {
  if (values.length === 0) return null;
  let best = values[0];
  for (const value of values) {
    if (value > best) best = value;
  }
  return best;
}

export function llmResponseCount(session) {
  if (typeof session.llmResponses === "number") return session.llmResponses;
  const counts = session.eventTypeCounts;
  if (counts && typeof counts.llm_response === "number") return counts.llm_response;
  return 0;
}

export function computeDwell(sessions) {
  const durations = [];
  const llmDurations = [];
  const staticDurations = [];
  let incomplete = 0;
  for (const session of sessions) {
    const first = Date.parse(session.firstSeen);
    const last = Date.parse(session.lastSeen);
    if (Number.isNaN(first) || Number.isNaN(last) || last < first) {
      incomplete += 1;
      continue;
    }
    const seconds = (last - first) / 1000;
    durations.push(seconds);
    if (llmResponseCount(session) > 0) llmDurations.push(seconds);
    else staticDurations.push(seconds);
  }
  const medianAll = median(durations);
  const meanAll = mean(durations);
  const maxAll = maxValue(durations);
  const llmMedian = median(llmDurations);
  const staticMedian = median(staticDurations);
  return {
    totalSessions: sessions.length,
    completeSessions: durations.length,
    incompleteSessions: incomplete,
    medianSeconds: medianAll === null ? null : roundSeconds(medianAll),
    meanSeconds: meanAll === null ? null : roundSeconds(meanAll),
    maxSeconds: maxAll === null ? null : roundSeconds(maxAll),
    llmSessions: llmDurations.length,
    staticSessions: staticDurations.length,
    llmMedianSeconds: llmMedian === null ? null : roundSeconds(llmMedian),
    staticMedianSeconds: staticMedian === null ? null : roundSeconds(staticMedian),
    medianDifferenceSeconds: llmMedian === null || staticMedian === null ? null : roundSeconds(llmMedian - staticMedian),
  };
}

export function showValue(value) {
  return value === null ? "TBD" : String(value);
}

export function formatDwellText(summary) {
  const computed = summary.computed;
  return [
    "evaluation: dwell",
    `api base: ${summary.apiBase}`,
    `sessions fetched: ${summary.sessionsFetched}`,
    `profiles fetched: ${summary.profilesFetched}`,
    `total sessions measured: ${computed.totalSessions}`,
    `complete sessions: ${computed.completeSessions}`,
    `incomplete sessions: ${computed.incompleteSessions}`,
    `median session duration seconds: ${showValue(computed.medianSeconds)}`,
    `mean session duration seconds: ${showValue(computed.meanSeconds)}`,
    `max session duration seconds: ${showValue(computed.maxSeconds)}`,
    `sessions with LLM response: ${computed.llmSessions}`,
    `sessions without LLM response: ${computed.staticSessions}`,
    `median LLM session duration seconds: ${showValue(computed.llmMedianSeconds)}`,
    `median static session duration seconds: ${showValue(computed.staticMedianSeconds)}`,
    `median difference LLM minus static seconds: ${showValue(computed.medianDifferenceSeconds)}`,
  ].join("\n");
}

export function dwellToJson(summary) {
  const computed = summary.computed;
  const withTbd = (value) => (value === null ? "TBD" : value);
  return {
    evaluation: "dwell",
    apiBase: summary.apiBase,
    sessionsFetched: summary.sessionsFetched,
    profilesFetched: summary.profilesFetched,
    totalSessions: computed.totalSessions,
    completeSessions: computed.completeSessions,
    incompleteSessions: computed.incompleteSessions,
    medianSeconds: withTbd(computed.medianSeconds),
    meanSeconds: withTbd(computed.meanSeconds),
    maxSeconds: withTbd(computed.maxSeconds),
    llmSessions: computed.llmSessions,
    staticSessions: computed.staticSessions,
    llmMedianSeconds: withTbd(computed.llmMedianSeconds),
    staticMedianSeconds: withTbd(computed.staticMedianSeconds),
    medianDifferenceSeconds: withTbd(computed.medianDifferenceSeconds),
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

export async function summarizeDwell(apiBase, fetchFn = fetch) {
  const sessions = await fetchList(apiBase, "/api/sessions?limit=200", fetchFn);
  const profiles = await fetchList(apiBase, "/api/profiles?limit=200", fetchFn);
  return {
    apiBase,
    sessionsFetched: sessions.length,
    profilesFetched: profiles.length,
    computed: computeDwell(sessions),
  };
}

export function parseDwellArgs(argv) {
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

export async function runDwellCli(argv, options = {}) {
  let cliOptions;
  try {
    cliOptions = parseDwellArgs(argv);
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  let summary;
  try {
    summary = await summarizeDwell(cliOptions.apiBase, options.fetchFn || fetch);
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  console.log(formatDwellText(summary));
  console.log("JSON:");
  console.log(JSON.stringify(dwellToJson(summary), null, 2));
  return 0;
}

async function main(argv) {
  process.exitCode = await runDwellCli(argv);
}

if (process.argv[1] && process.argv[1].endsWith("eval-dwell.js")) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
