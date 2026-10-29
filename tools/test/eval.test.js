import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import { readFileSync } from "node:fs";
import { computeDwell, formatDwellText, dwellToJson, summarizeDwell, runDwellCli } from "../eval-dwell.js";
import { computeLatencyStats, validateLatencyTarget, measureApiHealth, measureLatency, runLatencyCli } from "../eval-latency.js";
import { loadAllowedMap, computeAttack, summarizeAttack, runAttackCli } from "../eval-attack.js";

function captureOutput() {
  const lines = [];
  const errors = [];
  const originalLog = console.log;
  const originalError = console.error;
  console.log = (...args) => {
    lines.push(args.join(" "));
  };
  console.error = (...args) => {
    errors.push(args.join(" "));
  };
  return {
    lines,
    errors,
    restore() {
      console.log = originalLog;
      console.error = originalError;
    },
  };
}

function fakeFetch(routes) {
  const calls = [];
  const fn = async (url) => {
    calls.push(url);
    for (const [path, body] of Object.entries(routes)) {
      if (url.endsWith(path)) {
        return { ok: true, json: async () => body };
      }
    }
    return { ok: false, json: async () => ({}) };
  };
  fn.calls = calls;
  return fn;
}

function session(firstSeen, lastSeen, llmResponses) {
  const doc = { sessionId: `s-${firstSeen}-${lastSeen}`, firstSeen, lastSeen };
  if (llmResponses !== undefined) doc.llmResponses = llmResponses;
  return doc;
}

async function startFakeHttp() {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain", Connection: "close" });
    res.end("ok");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: server.address().port,
    async close() {
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

async function startFakeBanner() {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    socket.write("SSH-2.0-FAKE\r\n");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: server.address().port,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

test("dwell tool computes median and mean from firstSeen and lastSeen only, with incomplete sessions excluded", () => {
  const sessions = [
    session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:10.000Z", 2),
    session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:20.000Z", 0),
    session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:40.000Z", 0),
    session("2026-01-01T00:00:00.000Z", undefined, 0),
    session("2026-01-01T00:00:00.000Z", "not-a-date", 0),
    session(undefined, "2026-01-01T00:00:30.000Z", 0),
  ];
  const result = computeDwell(sessions);
  assert.equal(result.totalSessions, 6);
  assert.equal(result.completeSessions, 3);
  assert.equal(result.incompleteSessions, 3);
  assert.equal(result.medianSeconds, 20);
  assert.equal(result.meanSeconds, 23.333);
  assert.equal(result.maxSeconds, 40);
  assert.equal(result.llmSessions, 1);
  assert.equal(result.staticSessions, 2);
  assert.equal(result.llmMedianSeconds, 10);
  assert.equal(result.staticMedianSeconds, 30);
  assert.equal(result.medianDifferenceSeconds, -20);
});

test("dwell tool reports LLM and static medians separately, with TBD when a group is empty", () => {
  const mixed = computeDwell([
    session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:10.000Z", 1),
    session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:30.000Z", 1),
    session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:20.000Z", 0),
  ]);
  assert.equal(mixed.llmMedianSeconds, 20);
  assert.equal(mixed.staticMedianSeconds, 20);
  assert.equal(mixed.medianDifferenceSeconds, 0);
  const staticOnly = computeDwell([
    session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:20.000Z", 0),
    session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:40.000Z", 0),
  ]);
  assert.equal(staticOnly.llmMedianSeconds, null);
  assert.equal(staticOnly.staticMedianSeconds, 30);
  assert.equal(staticOnly.medianDifferenceSeconds, null);
  const text = formatDwellText({ apiBase: "http://127.0.0.1:3001", sessionsFetched: 2, profilesFetched: 0, computed: staticOnly });
  assert.ok(text.includes("median LLM session duration seconds: TBD"));
  assert.ok(text.includes("median difference LLM minus static seconds: TBD"));
  const json = dwellToJson({ apiBase: "http://127.0.0.1:3001", sessionsFetched: 2, profilesFetched: 0, computed: staticOnly });
  assert.equal(json.llmMedianSeconds, "TBD");
  assert.equal(json.medianDifferenceSeconds, "TBD");
});

test("latency tool returns median, mean, min, and max for 20 samples, with no external timing library", () => {
  const samples = [];
  for (let i = 1; i <= 20; i += 1) samples.push(i);
  const stats = computeLatencyStats(samples);
  assert.equal(stats.attempted, 20);
  assert.equal(stats.succeeded, 20);
  assert.equal(stats.failed, 0);
  assert.equal(stats.medianMs, 10.5);
  assert.equal(stats.meanMs, 10.5);
  assert.equal(stats.minMs, 1);
  assert.equal(stats.maxMs, 20);
  const partial = computeLatencyStats([5, null, 15, null, 10]);
  assert.equal(partial.succeeded, 3);
  assert.equal(partial.failed, 2);
  assert.equal(partial.medianMs, 10);
  const source = readFileSync(new URL("../eval-latency.js", import.meta.url), "utf8");
  assert.ok(source.includes("Date.now"));
  assert.ok(!source.includes("perf_hooks"));
  assert.ok(!source.includes("performance.now"));
});

test("latency tool rejects a non-loopback host before any connection, with exit code 1", async () => {
  let calls = 0;
  const countingFetch = async () => {
    calls += 1;
    return { ok: true, json: async () => ({}) };
  };
  const output = captureOutput();
  try {
    const code = await runLatencyCli(["--api-base", "http://8.8.8.8:3001"], { fetchFn: countingFetch });
    assert.equal(code, 1);
    assert.equal(calls, 0);
    const localCode = await runLatencyCli(["--api-base", "http://localhost:3001"], { fetchFn: countingFetch });
    assert.equal(localCode, 1);
    assert.equal(calls, 0);
  } finally {
    output.restore();
  }
  assert.throws(() => validateLatencyTarget("8.8.8.8", 3001));
});

test("ATT&CK tool computes coverage as observed unique divided by allowed total, with no invented technique", () => {
  const allowed = loadAllowedMap();
  assert.equal(allowed.size, 15);
  assert.deepEqual([...allowed.keys()].sort(), ["T1003", "T1016", "T1027", "T1033", "T1046", "T1057", "T1078", "T1082", "T1083", "T1087", "T1105", "T1110.001", "T1190", "T1547", "T1552.001"]);
  const result = computeAttack(
    [{ mitreTechniqueIds: ["T1033", "T1078"] }],
    [{ mitreTechniqueIds: ["T1105", "T1033"] }],
    allowed,
  );
  assert.equal(result.totalUnique, 3);
  assert.equal(result.allowedTotal, 15);
  assert.equal(result.observedAllowed, 3);
  assert.equal(result.coverageFraction, 0.2);
  assert.equal(result.coveragePercent, 20);
  assert.equal(result.neverObserved.length, 12);
  assert.ok(!result.neverObserved.some((entry) => entry.techniqueId === "T1033"));
  assert.ok(!result.neverObserved.some((entry) => entry.techniqueId === "T1078"));
  assert.ok(!result.neverObserved.some((entry) => entry.techniqueId === "T1105"));
  assert.deepEqual(result.unknown, []);
  assert.deepEqual(result.observed.map((entry) => entry.techniqueId), ["T1033", "T1078", "T1105"]);
});

test("ATT&CK tool counts unknown techniques separately, never maps them to an allowed technique", () => {
  const allowed = loadAllowedMap();
  const result = computeAttack(
    [{ mitreTechniqueIds: ["T9999"] }],
    [{ mitreTechniqueIds: ["T1033", "T9999"] }],
    allowed,
  );
  assert.equal(result.totalUnique, 2);
  assert.equal(result.observedAllowed, 1);
  assert.equal(result.coverageFraction, 1 / 15);
  assert.deepEqual(result.unknown, [{ techniqueId: "T9999", count: 2 }]);
  assert.ok(!result.observed.some((entry) => entry.techniqueId === "T9999" && entry.tactic !== "unknown"));
  assert.ok(!result.neverObserved.some((entry) => entry.techniqueId === "T9999"));
});

test("eval tools never print password, token, rawQuery, rawBody, or rawTarget", async () => {
  const sessions = [
    {
      sessionId: "s1",
      firstSeen: "2026-01-01T00:00:00.000Z",
      lastSeen: "2026-01-01T00:00:10.000Z",
      llmResponses: 1,
      password: "hunter2-secret",
      token: "tok-secret-xyz",
      rawQuery: "q-secret",
      rawBody: "b-secret",
      rawTarget: "t-secret",
    },
  ];
  const profiles = [
    {
      sessionId: "s1",
      mitreTechniqueIds: ["T1033"],
      password: "hunter2-secret",
      token: "tok-secret-xyz",
      rawQuery: "q-secret",
      rawBody: "b-secret",
      rawTarget: "t-secret",
    },
  ];
  const dwellFetch = fakeFetch({
    "/api/sessions?limit=200": { data: sessions },
    "/api/profiles?limit=200": { data: profiles },
  });
  const attackFetch = fakeFetch({
    "/api/attackers?limit=50": { data: [{ mitreTechniqueIds: ["T1033"], password: "hunter2-secret", token: "tok-secret-xyz", rawQuery: "q-secret", rawBody: "b-secret", rawTarget: "t-secret" }] },
    "/api/profiles?limit=200": { data: profiles },
  });
  const output = captureOutput();
  try {
    const dwellCode = await runDwellCli(["--api-base", "http://127.0.0.1:3001"], { fetchFn: dwellFetch });
    assert.equal(dwellCode, 0);
    const attackCode = await runAttackCli(["--api-base", "http://127.0.0.1:3001"], { fetchFn: attackFetch });
    assert.equal(attackCode, 0);
  } finally {
    output.restore();
  }
  const joined = output.lines.join("\n");
  for (const secret of ["hunter2-secret", "tok-secret-xyz", "q-secret", "b-secret", "t-secret"]) {
    assert.ok(!joined.includes(secret), `output leaked ${secret}`);
  }
  for (const key of ["password", "token", "rawQuery", "rawBody", "rawTarget"]) {
    assert.ok(!joined.includes(key), `output contains ${key}`);
  }
});

test("README evaluation results table contains TBD in every result cell, with no measured number", () => {
  const text = readFileSync(new URL("../../docs/evaluation.md", import.meta.url), "utf8");
  const lines = text.split("\n");
  const tableStart = lines.findIndex((line) => line.startsWith("| Metric | Result |"));
  assert.ok(tableStart >= 0);
  const rows = [];
  for (let i = tableStart + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line.startsWith("|")) break;
    if (line.includes("---")) continue;
    rows.push(line);
  }
  assert.ok(rows.length >= 10);
  for (const row of rows) {
    const cells = row.split("|").map((cell) => cell.trim()).filter((cell) => cell !== "");
    assert.equal(cells.length, 2);
    assert.equal(cells[1], "TBD");
    assert.ok(!/^\d/.test(cells[1]));
  }
  const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
  assert.ok(readme.includes("## Evaluation: dwell time, latency, and ATT&CK coverage (Day 19)"));
  assert.ok(readme.includes("TBD"));
});

test("eval tools use only existing API read routes, with no new route", async () => {
  const dwellFetch = fakeFetch({
    "/api/sessions?limit=200": { data: [] },
    "/api/profiles?limit=200": { data: [] },
  });
  const attackFetch = fakeFetch({
    "/api/attackers?limit=50": { data: [] },
    "/api/profiles?limit=200": { data: [] },
  });
  const output = captureOutput();
  try {
    await runDwellCli(["--api-base", "http://127.0.0.1:3001"], { fetchFn: dwellFetch });
    await runAttackCli(["--api-base", "http://127.0.0.1:3001"], { fetchFn: attackFetch });
  } finally {
    output.restore();
  }
  const allowedApiPaths = ["/api/sessions", "/api/profiles", "/api/attackers", "/api/health"];
  for (const url of [...dwellFetch.calls, ...attackFetch.calls]) {
    const path = new URL(url).pathname;
    assert.ok(allowedApiPaths.includes(path), `unexpected API route ${path}`);
  }
  const apiFetch = fakeFetch({});
  await measureApiHealth("http://127.0.0.1:3001", apiFetch);
  assert.ok(apiFetch.calls.length === 20);
  for (const url of apiFetch.calls) {
    assert.ok(url.endsWith("/api/health"), `unexpected API route ${url}`);
  }
  assert.ok(dwellFetch.calls.some((url) => url.endsWith("/api/sessions?limit=200")));
  assert.ok(dwellFetch.calls.some((url) => url.endsWith("/api/profiles?limit=200")));
  assert.ok(attackFetch.calls.some((url) => url.endsWith("/api/attackers?limit=50")));
  assert.ok(attackFetch.calls.some((url) => url.endsWith("/api/profiles?limit=200")));
});

test("dwell, latency, and ATT&CK tools all run with fake API data in staging, with no real ES, Docker, or Kafka", async () => {
  const dwellFetch = fakeFetch({
    "/api/sessions?limit=200": { data: [session("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:10.000Z", 1)] },
    "/api/profiles?limit=200": { data: [{ sessionId: "s1", mitreTechniqueIds: ["T1033"] }] },
  });
  const attackFetch = fakeFetch({
    "/api/attackers?limit=50": { data: [{ mitreTechniqueIds: ["T1033", "T1078"] }] },
    "/api/profiles?limit=200": { data: [{ sessionId: "s1", mitreTechniqueIds: ["T1033"] }] },
  });
  const httpServer = await startFakeHttp();
  const bannerServer = await startFakeBanner();
  const latencyFetch = async (url, options) => {
    if (url.endsWith("/wp-login.php")) return fetch(url, options);
    return { ok: true, json: async () => ({}) };
  };
  const output = captureOutput();
  try {
    const dwellSummary = await summarizeDwell("http://127.0.0.1:3001", dwellFetch);
    assert.equal(dwellSummary.computed.totalSessions, 1);
    const attackSummary = await summarizeAttack("http://127.0.0.1:3001", attackFetch);
    assert.equal(attackSummary.computed.totalUnique, 2);
    const latencySummary = await measureLatency("http://127.0.0.1:3001", { fetchFn: latencyFetch, httpPort: httpServer.port, sshPort: bannerServer.port });
    assert.equal(latencySummary.apiHealth.attempted, 20);
    assert.equal(latencySummary.httpLogin.attempted, 20);
    assert.equal(latencySummary.httpLogin.succeeded, 20);
    assert.equal(latencySummary.sshBanner.attempted, 20);
    assert.equal(latencySummary.sshBanner.succeeded, 20);
  } finally {
    output.restore();
    await httpServer.close();
    await bannerServer.close();
  }
});

test("latency tool rejects a disallowed port before any connection", async () => {
  let calls = 0;
  const countingFetch = async () => {
    calls += 1;
    return { ok: true, json: async () => ({}) };
  };
  const output = captureOutput();
  try {
    const code = await runLatencyCli(["--api-base", "http://127.0.0.1:9999"], { fetchFn: countingFetch });
    assert.equal(code, 1);
    assert.equal(calls, 0);
  } finally {
    output.restore();
  }
  assert.throws(() => validateLatencyTarget("127.0.0.1", 9999));
});

test("dwell tool counts sessions without lastSeen as incomplete and reports TBD for all durations when none are complete", () => {
  const result = computeDwell([
    session("2026-01-01T00:00:00.000Z", undefined, 0),
    session("2026-01-01T00:00:00.000Z", undefined, 1),
  ]);
  assert.equal(result.totalSessions, 2);
  assert.equal(result.completeSessions, 0);
  assert.equal(result.incompleteSessions, 2);
  assert.equal(result.medianSeconds, null);
  assert.equal(result.meanSeconds, null);
  assert.equal(result.maxSeconds, null);
  assert.equal(result.llmSessions, 0);
  assert.equal(result.staticSessions, 0);
  const text = formatDwellText({ apiBase: "http://127.0.0.1:3001", sessionsFetched: 2, profilesFetched: 0, computed: result });
  assert.ok(text.includes("median session duration seconds: TBD"));
  assert.ok(text.includes("mean session duration seconds: TBD"));
  assert.ok(text.includes("max session duration seconds: TBD"));
});

test("ATT&CK tool lists each technique tactic from mitre rules", () => {
  const allowed = loadAllowedMap();
  const result = computeAttack(
    [{ mitreTechniqueIds: ["T1033", "T1105", "T1078", "T1110.001"] }],
    [],
    allowed,
  );
  const byId = new Map(result.observed.map((entry) => [entry.techniqueId, entry.tactic]));
  assert.equal(byId.get("T1033"), "Discovery");
  assert.equal(byId.get("T1105"), "Command and Control");
  assert.equal(byId.get("T1078"), "Initial Access");
  assert.equal(byId.get("T1110.001"), "Credential Access");
});
