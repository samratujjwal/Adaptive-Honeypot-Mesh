import net from "node:net";

export const DEFAULT_API_BASE = "http://127.0.0.1:3001";
export const ALLOWED_HOST = "127.0.0.1";
export const ALLOWED_PORTS = [2222, 8080, 2121, 3001];
export const SAMPLE_COUNT = 20;

export function validateLatencyTarget(host, port) {
  if (host !== ALLOWED_HOST) {
    throw new Error(`latency target not allowed: ${host}`);
  }
  if (!ALLOWED_PORTS.includes(port)) {
    throw new Error(`latency port not allowed: ${port}`);
  }
}

export function parseApiBase(apiBase) {
  let url;
  try {
    url = new URL(apiBase);
  } catch {
    throw new Error(`invalid api base: ${apiBase}`);
  }
  const host = url.hostname;
  const port = url.port === "" ? 3001 : Number.parseInt(url.port, 10);
  validateLatencyTarget(host, port);
  return { host, port, base: `http://${host}:${port}` };
}

export function roundMs(value) {
  return Math.round(value * 100) / 100;
}

export function computeLatencyStats(samples) {
  const good = samples.filter((value) => typeof value === "number");
  const failed = samples.length - good.length;
  if (good.length === 0) {
    return { attempted: samples.length, succeeded: 0, failed, medianMs: null, meanMs: null, minMs: null, maxMs: null };
  }
  const sorted = [...good].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const medianRaw = sorted.length % 2 === 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
  let sum = 0;
  for (const value of good) sum += value;
  let min = good[0];
  let max = good[0];
  for (const value of good) {
    if (value < min) min = value;
    if (value > max) max = value;
  }
  return {
    attempted: samples.length,
    succeeded: good.length,
    failed,
    medianMs: roundMs(medianRaw),
    meanMs: roundMs(sum / good.length),
    minMs: min,
    maxMs: max,
  };
}

async function fetchTimed(fetchFn, url, timeoutMs = 5000) {
  const start = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    await fetchFn(url, { signal: controller.signal });
    return Date.now() - start;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function measureApiHealth(apiBase, fetchFn = fetch, count = SAMPLE_COUNT) {
  const samples = [];
  for (let i = 0; i < count; i += 1) {
    samples.push(await fetchTimed(fetchFn, `${apiBase}/api/health`));
  }
  return computeLatencyStats(samples);
}

export async function measureHttp(httpBase, fetchFn = fetch, count = SAMPLE_COUNT) {
  const samples = [];
  for (let i = 0; i < count; i += 1) {
    samples.push(await fetchTimed(fetchFn, `${httpBase}/wp-login.php`));
  }
  return computeLatencyStats(samples);
}

export async function measureSshBannerOnce(host, port, timeoutMs = 5000) {
  const start = Date.now();
  return new Promise((resolve) => {
    const socket = net.connect(port, host);
    let buffer = "";
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        socket.destroy();
        resolve(null);
      }
    }, timeoutMs);
    const finish = (value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (buffer.includes("\n")) finish(Date.now() - start);
    });
    socket.on("error", () => finish(null));
    socket.on("close", () => finish(null));
  });
}

export async function measureSshBanner(host, port, count = SAMPLE_COUNT) {
  const samples = [];
  for (let i = 0; i < count; i += 1) {
    samples.push(await measureSshBannerOnce(host, port));
  }
  return computeLatencyStats(samples);
}

export function showLatency(value) {
  return value === null ? "TBD" : String(value);
}

export function formatLatencyText(summary) {
  const lines = [
    "evaluation: latency",
    `api base: ${summary.apiBase}`,
  ];
  const groups = [
    ["api health", summary.apiHealth],
    ["http wp-login", summary.httpLogin],
    ["ssh banner", summary.sshBanner],
  ];
  for (const [label, stats] of groups) {
    lines.push(`${label} attempts: ${stats.attempted} succeeded: ${stats.succeeded} failed: ${stats.failed}`);
    lines.push(`${label} median ms: ${showLatency(stats.medianMs)}`);
    lines.push(`${label} mean ms: ${showLatency(stats.meanMs)}`);
    lines.push(`${label} min ms: ${showLatency(stats.minMs)}`);
    lines.push(`${label} max ms: ${showLatency(stats.maxMs)}`);
  }
  return lines.join("\n");
}

export function latencyToJson(summary) {
  const withTbd = (stats) => ({
    attempted: stats.attempted,
    succeeded: stats.succeeded,
    failed: stats.failed,
    medianMs: stats.medianMs === null ? "TBD" : stats.medianMs,
    meanMs: stats.meanMs === null ? "TBD" : stats.meanMs,
    minMs: stats.minMs === null ? "TBD" : stats.minMs,
    maxMs: stats.maxMs === null ? "TBD" : stats.maxMs,
  });
  return {
    evaluation: "latency",
    apiBase: summary.apiBase,
    apiHealth: withTbd(summary.apiHealth),
    httpLogin: withTbd(summary.httpLogin),
    sshBanner: withTbd(summary.sshBanner),
  };
}

export async function measureLatency(apiBase, options = {}) {
  const parsed = parseApiBase(apiBase);
  const fetchFn = options.fetchFn || fetch;
  const httpPort = options.httpPort || 8080;
  const sshPort = options.sshPort || 2222;
  const apiHealth = await measureApiHealth(parsed.base, fetchFn);
  const httpLogin = await measureHttp(`http://${parsed.host}:${httpPort}`, fetchFn);
  const sshBanner = await measureSshBanner(parsed.host, sshPort);
  return { apiBase: parsed.base, apiHealth, httpLogin, sshBanner };
}

export function parseLatencyArgs(argv) {
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

export async function runLatencyCli(argv, options = {}) {
  let cliOptions;
  try {
    cliOptions = parseLatencyArgs(argv);
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  let summary;
  try {
    summary = await measureLatency(cliOptions.apiBase, options);
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  console.log(formatLatencyText(summary));
  console.log("JSON:");
  console.log(JSON.stringify(latencyToJson(summary), null, 2));
  return 0;
}

async function main(argv) {
  process.exitCode = await runLatencyCli(argv);
}

if (process.argv[1] && process.argv[1].endsWith("eval-latency.js")) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
