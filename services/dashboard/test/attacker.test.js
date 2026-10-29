import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "../../api/src/server.js";
import { isValidIp, ipError, filterProfilesBySourceIp, filterSessionsBySourceIp } from "../public/attacker/attacker.js";
import { stripForbidden } from "../public/app.js";

const silent = { info: () => {}, warn: () => {}, error: () => {} };
const attackerHtml = readFileSync(new URL("../public/attacker/index.html", import.meta.url), "utf8");
const attackerJs = readFileSync(new URL("../public/attacker/attacker.js", import.meta.url), "utf8");
const compose = readFileSync(new URL("../../../docker-compose.yml", import.meta.url), "utf8");
const datasourceYaml = readFileSync(new URL("../../../provisioning/grafana/datasources/elasticsearch.yaml", import.meta.url), "utf8");
const dashboardJson = JSON.parse(readFileSync(new URL("../../../provisioning/grafana/dashboards/mesh-overview.json", import.meta.url), "utf8"));

const attackerDoc = {
  attackerId: "127.0.0.1", sourceIp: "127.0.0.1", firstSeen: "2026-10-28T10:00:00Z", lastSeen: "2026-10-28T10:01:00Z",
  sessionCount: 2, serviceCount: 2, services: ["ftp", "ssh"], sessionIds: ["s1", "s2"],
  mitreTechniqueIds: ["T1033", "T1105", "T1033"], tools: ["wget"], commandNames: ["whoami"],
  classification: { actorType: "unknown", skillLevel: "intermediate", intent: "exploitation", confidence: 0.7, llmIntentMismatch: false },
  strategy: { name: "contain", reason: "exploitation+intermediate", crossService: true },
};

function fakeEs(overrides = {}) {
  return {
    info: async () => ({}),
    search: async (params) => {
      if (overrides.search) return overrides.search(params);
      const index = params.index || "";
      if (index.includes("sessions")) return { hits: { total: { value: 1 }, hits: [{ _id: "s1", _source: { sessionId: "s1", service: "ssh", sourceIp: "127.0.0.1", firstSeen: "2026-10-28T10:00:00Z", lastSeen: "2026-10-28T10:01:00Z", durationMs: 60000, closed: true, eventCount: 5 } }] } };
      if (index.includes("profiles")) return { hits: { total: { value: 1 }, hits: [] }, aggregations: { byTool: { buckets: [] } } };
      if (index.includes("attackers")) return { hits: { total: { value: 1 }, hits: [] } };
      if (index.includes("events")) return { hits: { total: { value: 0 }, hits: [] }, aggregations: { byService: { buckets: [] }, bySourceIp: { buckets: [] } } };
      return { hits: { total: { value: 0 }, hits: [] } };
    },
    get: async (params) => {
      if (params.id === "127.0.0.1") return { found: true, _id: "127.0.0.1", _source: attackerDoc };
      const error = new Error("not found");
      error.statusCode = 404;
      throw error;
    },
  };
}

async function startServer(es) {
  const server = createServer({ es, logger: silent, config: { ES_INDEX_PREFIX: "honeypot", API_POLL_MS: 60000 } });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server;
}

async function stopServer(server) {
  await new Promise((resolve) => server.closeApi(resolve));
}

async function fetchJson(server, path) {
  const port = server.address().port;
  const response = await fetch(`http://127.0.0.1:${port}${path}`);
  const text = await response.text();
  let body = null;
  try { body = JSON.parse(text); } catch {}
  return { status: response.status, body, text };
}

test("attacker page served 200 and contains attacker, sessions, profiles, and strategy sections", async () => {
  const server = await startServer(fakeEs());
  try {
    const port = server.address().port;
    const response = await fetch(`http://127.0.0.1:${port}/dashboard/attacker/`);
    const text = await response.text();
    assert.equal(response.status, 200);
    for (const id of ["attacker-details", "sessions-section", "profiles-section", "strategy-section"]) assert.ok(text.includes(`id="${id}"`), `missing ${id}`);
  } finally { await stopServer(server); }
});

test("attacker page with missing ip shows a plain error, never another attacker's data", () => {
  const error = ipError("");
  assert.ok(error.includes("Missing ip"));
  assert.ok(!error.includes("127.0.0.1") || error.includes("ip=127.0.0.1"));
  assert.equal(ipError(null).includes("Missing ip"), true);
});

test("attacker page with invalid ip shows a plain error, never crashes", () => {
  assert.equal(ipError("not-an-ip"), "Invalid ip parameter.");
  assert.equal(ipError("999.999.999.999"), "Invalid ip parameter.");
  assert.equal(isValidIp("127.0.0.1"), true);
  assert.equal(isValidIp("::1"), true);
});

test("attacker page profiles are filtered client-side by sourceIp, other IPs are dropped", () => {
  const profiles = [
    { sessionId: "s1", sourceIp: "127.0.0.1" },
    { sessionId: "s2", sourceIp: "10.0.0.9" },
    { sessionId: "s3", sourceIp: "127.0.0.1" },
  ];
  const kept = filterProfilesBySourceIp(profiles, "127.0.0.1");
  assert.equal(kept.length, 2);
  assert.ok(kept.every((profile) => profile.sourceIp === "127.0.0.1"));
});

test("attacker page sessions are filtered client-side by sourceIp, other IPs are dropped", () => {
  const sessions = [
    { sessionId: "s1", sourceIp: "127.0.0.1" },
    { sessionId: "s2", sourceIp: "10.0.0.9" },
  ];
  const kept = filterSessionsBySourceIp(sessions, "127.0.0.1");
  assert.equal(kept.length, 1);
  assert.equal(kept[0].sessionId, "s1");
});

test("attacker page strips forbidden keys before render, same list as Day 15", () => {
  const doc = { sessionId: "s1", password: "p", token: "t", rawQuery: "q", rawBody: "b", rawTarget: "/x", summary: "s", pwd: "p2", tokenValue: "tv", credential: "c", credentials: ["c2"] };
  const result = stripForbidden(doc);
  assert.equal(result.stripped, 10);
  assert.equal(result.clean.sessionId, "s1");
  assert.ok(attackerJs.includes("stripForbidden"));
});

test("attacker page renders attacker strings only with textContent, never innerHTML", () => {
  assert.ok(!attackerJs.includes("innerHTML"));
  assert.ok(!attackerJs.includes("document.write"));
  assert.ok(!attackerJs.includes("insertAdjacentHTML"));
  assert.ok(attackerJs.includes("textContent"));
});

test("STIX route returns a valid bundle with spec_version 2.1 and bundle id", async () => {
  const server = await startServer(fakeEs());
  try {
    const { status, body } = await fetchJson(server, "/api/attackers/127.0.0.1/stix");
    assert.equal(status, 200);
    assert.equal(body.type, "bundle");
    assert.equal(body.spec_version, "2.1");
    assert.match(body.id, /^bundle--[0-9a-f-]{36}$/);
    assert.ok(Array.isArray(body.objects));
    assert.ok(body.objects.length >= 1);
  } finally { await stopServer(server); }
});

test("STIX route contains exactly one identity for the requested ip, never a real-world actor claim", async () => {
  const server = await startServer(fakeEs());
  try {
    const { body } = await fetchJson(server, "/api/attackers/127.0.0.1/stix");
    const identities = body.objects.filter((object) => object.type === "identity");
    assert.equal(identities.length, 1);
    assert.equal(identities[0].name, "127.0.0.1");
    assert.equal(identities[0].identity_class, "system");
    assert.ok(identities[0].description.includes("honeypot"));
    assert.ok(!identities[0].description.includes("confirmed real-world actor"));
  } finally { await stopServer(server); }
});

test("STIX route contains one attack-pattern per unique technique, with mitre external_id, no invented technique", async () => {
  const server = await startServer(fakeEs());
  try {
    const { body } = await fetchJson(server, "/api/attackers/127.0.0.1/stix");
    const patterns = body.objects.filter((object) => object.type === "attack-pattern");
    assert.equal(patterns.length, 2);
    const names = patterns.map((pattern) => pattern.name).sort();
    assert.deepEqual(names, ["T1033", "T1105"]);
    for (const pattern of patterns) {
      assert.equal(pattern.external_references[0].source_name, "mitre-attack");
      assert.equal(pattern.external_references[0].external_id, pattern.name);
      assert.match(pattern.id, /^attack-pattern--[0-9a-f-]{36}$/);
    }
  } finally { await stopServer(server); }
});

test("STIX route for unknown attacker returns 404 code-only, for invalid ip returns 400 code-only", async () => {
  const server = await startServer(fakeEs());
  try {
    const unknown = await fetchJson(server, "/api/attackers/10.9.9.9/stix");
    assert.equal(unknown.status, 404);
    assert.equal(unknown.body.error.code, "NOT_FOUND");
    const invalid = await fetchJson(server, "/api/attackers/nope/stix");
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.error.code, "INVALID_IP");
  } finally { await stopServer(server); }
});

test("STIX route with no techniques returns a valid bundle with identity only, never empty objects", async () => {
  const noTech = { ...attackerDoc, mitreTechniqueIds: [] };
  const es = fakeEs();
  es.get = async (params) => {
    if (params.id === "127.0.0.1") return { found: true, _id: "127.0.0.1", _source: noTech };
    const error = new Error("not found");
    error.statusCode = 404;
    throw error;
  };
  const server = await startServer(es);
  try {
    const { status, body } = await fetchJson(server, "/api/attackers/127.0.0.1/stix");
    assert.equal(status, 200);
    assert.equal(body.type, "bundle");
    assert.equal(body.objects.length >= 1, true);
    assert.equal(body.objects.filter((object) => object.type === "identity").length, 1);
    assert.equal(body.objects.filter((object) => object.type === "attack-pattern").length, 0);
  } finally { await stopServer(server); }
});

test("STIX route with ES down returns 500 code-only, never an ES error body", async () => {
  const broken = { info: async () => { throw new Error("connection refused"); }, search: async () => { throw new Error("connection refused"); }, get: async () => { throw new Error("connection refused"); } };
  const server = await startServer(broken);
  try {
    const { status, body, text } = await fetchJson(server, "/api/attackers/127.0.0.1/stix");
    assert.equal(status, 500);
    assert.equal(body.error.code, "INTERNAL_ERROR");
    assert.ok(!text.includes("connection refused"));
  } finally { await stopServer(server); }
});

test("Grafana compose service binds loopback only on 3000, image is pinned, no latest tag", () => {
  assert.ok(compose.includes('"127.0.0.1:3000:3000"'));
  assert.ok(!compose.includes("0.0.0.0:3000"));
  const grafanaBlock = compose.slice(compose.indexOf("grafana:"));
  assert.match(grafanaBlock, /image: grafana\/grafana:[0-9]+\.[0-9]+\.[0-9]+/);
  assert.ok(!grafanaBlock.includes(":latest"));
  assert.ok(grafanaBlock.includes("GF_SECURITY_ADMIN_USER: ${GF_ADMIN_USER}"));
  assert.ok(grafanaBlock.includes("GF_SECURITY_ADMIN_PASSWORD: ${GF_ADMIN_PASSWORD}"));
  assert.ok(!/\n\s+GF_SECURITY_ADMIN_PASSWORD: [^$]/.test(grafanaBlock));
});

test("Grafana datasource provisioning is valid YAML, url is elasticsearch:9200, no auth, no credential", () => {
  assert.ok(datasourceYaml.includes("apiVersion: 1"));
  assert.ok(datasourceYaml.includes("name: Elasticsearch"));
  assert.ok(datasourceYaml.includes("url: http://elasticsearch:9200"));
  assert.ok(datasourceYaml.includes("isDefault: true"));
  assert.ok(datasourceYaml.includes("editable: false"));
  assert.ok(!datasourceYaml.includes("basicAuth"));
  assert.ok(!datasourceYaml.includes("password"));
  assert.ok(!datasourceYaml.includes("token"));
  for (const line of datasourceYaml.split("\n")) assert.ok(!line.startsWith("\t"), "tabs are not valid YAML indentation");
});

test("Grafana dashboard JSON is valid JSON, title MESH OVERVIEW, panels query only existing indices and the provisioned datasource", () => {
  assert.equal(dashboardJson.title, "MESH OVERVIEW");
  assert.equal(dashboardJson.panels.length, 4);
  const allowedIndices = ["honeypot-events-*", "honeypot-sessions", "honeypot-profiles", "honeypot-attackers"];
  for (const panel of dashboardJson.panels) {
    assert.equal(panel.datasource.uid, "elasticsearch");
    for (const target of panel.targets) {
      assert.equal(target.datasource.uid, "elasticsearch");
      const query = target.query || "";
      const indexPart = query.replace("_index:", "");
      assert.ok(allowedIndices.includes(indexPart), `panel ${panel.title} queries unknown index ${indexPart}`);
    }
  }
  const titles = dashboardJson.panels.map((panel) => panel.title);
  assert.ok(titles.includes("Events by service over time"));
  assert.ok(titles.includes("Sessions count"));
  assert.ok(titles.includes("Top techniques"));
  assert.ok(titles.includes("Top source IPs"));
});
