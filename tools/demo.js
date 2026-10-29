import net from "node:net";
import { config } from "../packages/shared/src/config.js";
import { logger } from "../packages/shared/src/logger.js";
import { startAll } from "./start-all.js";
import { start as startProcessorModule } from "../services/processor/src/index.js";
import { createEsClient } from "../packages/search/src/es-client.js";
import { createServer } from "../services/api/src/server.js";
import { runScenario, formatSummary } from "./attack-simulator.js";

export const ALLOWED_HOST = "127.0.0.1";
export const ALLOWED_PORTS = [2222, 8080, 2121, 3001, 9200];
export const SERVICE_PORTS = [2222, 8080, 2121, 3001];
export const ES_URL = "http://127.0.0.1:9200";
export const DASHBOARD_URL = "http://127.0.0.1:3001/dashboard";
export const ATTACKER_URL = "http://127.0.0.1:3001/dashboard/attacker/?ip=127.0.0.1";
export const GRAFANA_URL = "http://127.0.0.1:3000";
export const ES_TIMEOUT_MS = 60000;
export const SERVICE_TIMEOUT_MS = 30000;
export const POLL_MS = 250;
export const SIMULATOR_COUNT = 1;
export const SIMULATOR_DELAY_MS = 1000;
export const COMPOSE_COMMAND = "docker compose up -d kafka elasticsearch grafana";
export const DEMO_STEPS = [
  "validate targets",
  "check elasticsearch",
  "start services",
  "wait services",
  "simulator basic-ssh",
  "simulator mixed",
  "print urls",
  "stop services",
];

export function validateDemoTarget(host, port) {
  if (host !== ALLOWED_HOST) throw new Error(`demo host not allowed: ${host}`);
  if (!ALLOWED_PORTS.includes(port)) throw new Error(`demo port not allowed: ${port}`);
}

export function validateAllTargets(host) {
  for (const port of ALLOWED_PORTS) validateDemoTarget(host, port);
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function tcpConnectOnce(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

export async function waitForTcpPort(host, port, timeoutMs, deps = {}) {
  const tryConnect = deps.tryConnect || tcpConnectOnce;
  const sleepFn = deps.sleepFn || sleep;
  const pollMs = deps.pollMs || POLL_MS;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    if (await tryConnect(host, port)) return true;
    if (Date.now() + pollMs > deadline) break;
    await sleepFn(pollMs);
  }
  return false;
}

export async function waitForHttp(url, timeoutMs, deps = {}) {
  const fetchFn = deps.fetchFn || fetch;
  const sleepFn = deps.sleepFn || sleep;
  const pollMs = deps.pollMs || POLL_MS;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    try {
      await fetchFn(url);
      return true;
    } catch {
      if (Date.now() + pollMs > deadline) break;
      await sleepFn(pollMs);
    }
  }
  return false;
}

export async function startProcessorReal() {
  const started = await startProcessorModule();
  await started.consumer.start();
  return { close: started.close };
}

export async function startHoneypotsReal() {
  const started = await startAll();
  return { close: started.close };
}

export async function startApiReal() {
  const es = createEsClient({ config, logger });
  const server = createServer({ es, logger, config });
  await new Promise((resolve) => server.listen(config.API_PORT, config.API_HOST, resolve));
  server.startLive();
  return { close: () => new Promise((resolve) => server.closeApi(resolve)) };
}

export async function runSimulatorReal(scenario) {
  const result = await runScenario({ scenario, count: SIMULATOR_COUNT, delay: SIMULATOR_DELAY_MS, host: ALLOWED_HOST });
  return formatSummary(result);
}

export function defaultStarters() {
  return { processor: startProcessorReal, honeypots: startHoneypotsReal, api: startApiReal };
}

export function parseDemoArgs(argv) {
  const options = {};
  for (const arg of argv) {
    if (arg === "--help") options.help = true;
    else throw new Error(`unknown demo argument: ${arg}`);
  }
  return options;
}

export function demoUsage() {
  return [
    "usage, two steps, no angle brackets:",
    "Step 1: set GF_ADMIN_USER and GF_ADMIN_PASSWORD on the host, then docker compose up -d kafka elasticsearch grafana, wait 60 to 90 seconds, check docker compose ps and ES on 127.0.0.1:9200",
    "Step 2: npm run demo",
    "demo starts processor, honeypots, and API in-process, runs simulator basic-ssh and mixed, prints URLs, and stops its own in-process services on exit. Loopback only.",
  ].join("\n");
}

export async function runDemo(input = {}) {
  const host = input.host || ALLOWED_HOST;
  const starters = input.starters || defaultStarters();
  const simulator = input.simulator || runSimulatorReal;
  const log = input.logFn || ((line) => console.log(line));
  const sleepFn = input.sleepFn || sleep;
  const fetchFn = input.fetchFn || fetch;
  const tryConnect = input.tryConnect || tcpConnectOnce;
  const esTimeoutMs = input.esTimeoutMs || ES_TIMEOUT_MS;
  const serviceTimeoutMs = input.serviceTimeoutMs || SERVICE_TIMEOUT_MS;
  const pollMs = input.pollMs || POLL_MS;
  const handles = [];
  let cancelled = false;
  const onSignal = () => { cancelled = true; };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  let failed = null;
  const stepFailed = (step, reason) => {
    failed = { step, reason };
    return false;
  };
  try {
    try {
      validateAllTargets(host);
    } catch (error) {
      stepFailed("validate targets", error.message);
    }
    if (!failed && !cancelled) {
      log("demo: checking elasticsearch on 127.0.0.1:9200");
      const ready = await waitForHttp(ES_URL, esTimeoutMs, { fetchFn, sleepFn, pollMs });
      if (ready) log("demo: elasticsearch responding");
      else stepFailed("check elasticsearch", `elasticsearch did not respond on 127.0.0.1:9200; run this first: ${COMPOSE_COMMAND} (set GF_ADMIN_USER and GF_ADMIN_PASSWORD on the host first), wait 60 to 90 seconds, check docker compose ps, then run npm run demo again`);
    }
    if (!failed && !cancelled) {
      log("demo: starting processor, honeypots, api");
      try {
        handles.push(await starters.processor());
        handles.push(await starters.honeypots());
        handles.push(await starters.api());
      } catch (error) {
        stepFailed("start services", error.message);
      }
    }
    if (!failed && !cancelled) {
      log("demo: waiting for honeypots and api");
      for (const port of SERVICE_PORTS) {
        if (cancelled) break;
        const ready = await waitForTcpPort(host, port, serviceTimeoutMs, { tryConnect, sleepFn, pollMs });
        if (!ready) {
          stepFailed("wait services", `port ${port} did not listen in time`);
          break;
        }
      }
      if (!failed) log("demo: all services listening");
    }
    if (!failed && !cancelled) {
      log("demo: running simulator basic-ssh");
      try {
        log((await simulator("basic-ssh")).trimEnd());
      } catch (error) {
        stepFailed("simulator basic-ssh", error.message);
      }
    }
    if (!failed && !cancelled) {
      log("demo: running simulator mixed");
      try {
        log((await simulator("mixed")).trimEnd());
      } catch (error) {
        stepFailed("simulator mixed", error.message);
      }
    }
    if (!failed && !cancelled) {
      log(`demo: dashboard ${DASHBOARD_URL}`);
      log(`demo: attacker ${ATTACKER_URL}`);
      log(`demo: grafana ${GRAFANA_URL}`);
      log("demo: note: Grafana panels No data is a separate issue, Grafana panels showing data is not claimed");
      log("demo: note: kafka, elasticsearch, and grafana were started manually with docker compose and are left running, only in-process services are stopped on exit");
    }
    if (cancelled && !failed) stepFailed("cancelled", "demo interrupted");
  } finally {
    if (handles.length > 0) {
      log("demo: stopping services");
      for (const handle of [...handles].reverse()) {
        try {
          await handle.close();
        } catch (error) {
          if (!failed) stepFailed("stop services", error.message);
        }
      }
    }
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
  }
  if (failed) {
    log(`demo: FAILED at step ${failed.step}: ${failed.reason}`);
    return 1;
  }
  log("demo: complete");
  return 0;
}

export async function runDemoCli(argv, deps = {}) {
  const log = deps.logFn || ((line) => console.log(line));
  let options;
  try {
    options = parseDemoArgs(argv);
  } catch (error) {
    console.error(error.message);
    return 1;
  }
  if (options.help) {
    log(demoUsage());
    return 0;
  }
  return runDemo(deps);
}

async function main() {
  process.exitCode = await runDemoCli(process.argv.slice(2));
}

if (process.argv[1] && process.argv[1].endsWith("demo.js")) {
  main();
}
