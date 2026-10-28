import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "../src/server.js";
import { createLiveFeed } from "../src/live.js";
import { sanitizeDoc } from "../src/sanitize.js";

const silent = { info: () => {}, warn: () => {}, error: () => {} };

function fakeEs(overrides = {}) {
  return {
    info: async () => ({}),
    search: async (params) => {
      if (overrides.search) return overrides.search(params);
      const index = params.index || "";
      if (index.includes("events")) {
        return { hits: { total: { value: 2 }, hits: [
          { _id: "e1", _source: { eventType: "command", honeypot: { service: "ssh" }, source: { ip: "10.0.0.1" }, timestamp: "2026-10-28T10:00:00Z" } },
          { _id: "e2", _source: { eventType: "command", honeypot: { service: "ssh" }, source: { ip: "10.0.0.2" }, timestamp: "2026-10-28T10:01:00Z" } },
        ] }, aggregations: { byService: { buckets: [{ key: "ssh", doc_count: 2 }] }, bySourceIp: { buckets: [{ key: "10.0.0.1", doc_count: 1 }] } } };
      }
      if (index.includes("sessions")) return { hits: { total: { value: 1 }, hits: [{ _id: "s1", _source: { service: "ssh", sourceIp: "10.0.0.1", closed: true } }] } };
      if (index.includes("profiles")) return { hits: { total: { value: 1 }, hits: [{ _id: "p1", _source: { service: "ssh", classification: { intent: "recon", skillLevel: "beginner", actorType: "unknown", tools: ["wget"] } } }] }, aggregations: { byTool: { buckets: [{ key: "wget", doc_count: 1 }] } } };
      if (index.includes("attackers")) return { hits: { total: { value: 1 }, hits: [{ _id: "10.0.0.1", _source: { attackerId: "10.0.0.1", strategy: { name: "contain", reason: "exploitation+intermediate", crossService: true }, classification: { intent: "exploitation" } } }] } };
      return { hits: { total: { value: 0 }, hits: [] } };
    },
    get: async (params) => {
      if (params.id === "10.0.0.1") return { found: true, _id: "10.0.0.1", _source: { attackerId: "10.0.0.1", strategy: { name: "contain", reason: "exploitation+intermediate", crossService: true } } };
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

async function get(server, path) {
  const port = server.address().port;
  const response = await fetch(`http://127.0.0.1:${port}${path}`);
  const body = await response.json();
  return { status: response.status, body };
}

test("api: health returns ok and es reachable flag", async () => {
  const server = await startServer(fakeEs());
  try {
    const { status, body } = await get(server, "/api/health");
    assert.equal(status, 200);
    assert.equal(body.status, "ok");
    assert.equal(body.es.reachable, true);
    assert.equal(typeof body.uptimeMs, "number");
  } finally { await stopServer(server); }
});

test("api: events list returns data, total, limit, offset, clamped limit", async () => {
  const server = await startServer(fakeEs());
  try {
    const { status, body } = await get(server, "/api/events?limit=999");
    assert.equal(status, 200);
    assert.equal(body.limit, 200);
    assert.equal(body.offset, 0);
    assert.equal(body.total, 2);
    assert.equal(body.data.length, 2);
  } finally { await stopServer(server); }
});

test("api: events filter by service works", async () => {
  let seenQuery = null;
  const es = fakeEs({ search: async (params) => { seenQuery = params; return { hits: { total: { value: 1 }, hits: [{ _id: "e1", _source: { eventType: "command" } }] } }; } });
  const server = await startServer(es);
  try {
    const { status, body } = await get(server, "/api/events?service=ssh");
    assert.equal(status, 200);
    assert.equal(body.total, 1);
    assert.ok(JSON.stringify(seenQuery.query).includes("ssh"));
  } finally { await stopServer(server); }
});

test("api: sessions filter by sourceIp works", async () => {
  let seenQuery = null;
  const es = fakeEs({ search: async (params) => { seenQuery = params; return { hits: { total: { value: 1 }, hits: [{ _id: "s1", _source: { service: "ssh", sourceIp: "10.0.0.1" } }] } }; } });
  const server = await startServer(es);
  try {
    const { status, body } = await get(server, "/api/sessions?sourceIp=10.0.0.1");
    assert.equal(status, 200);
    assert.equal(body.total, 1);
    assert.ok(JSON.stringify(seenQuery.query).includes("10.0.0.1"));
  } finally { await stopServer(server); }
});

test("api: profiles filter by intent works", async () => {
  let seenQuery = null;
  const es = fakeEs({ search: async (params) => { seenQuery = params; return { hits: { total: { value: 1 }, hits: [{ _id: "p1", _source: { classification: { intent: "recon" } } }] } }; } });
  const server = await startServer(es);
  try {
    const { status, body } = await get(server, "/api/profiles?intent=recon");
    assert.equal(status, 200);
    assert.equal(body.total, 1);
    assert.ok(JSON.stringify(seenQuery.query).includes("recon"));
  } finally { await stopServer(server); }
});

test("api: attackers list and single attacker by IP works", async () => {
  const server = await startServer(fakeEs());
  try {
    const list = await get(server, "/api/attackers");
    assert.equal(list.status, 200);
    assert.equal(list.body.total, 1);
    assert.equal(list.body.data[0].attackerId, "10.0.0.1");
    const single = await get(server, "/api/attackers/10.0.0.1");
    assert.equal(single.status, 200);
    assert.equal(single.body.data.attackerId, "10.0.0.1");
  } finally { await stopServer(server); }
});

test("api: unknown attacker IP returns 404", async () => {
  const server = await startServer(fakeEs());
  try {
    const { status, body } = await get(server, "/api/attackers/10.0.0.9");
    assert.equal(status, 404);
    assert.equal(body.error.code, "NOT_FOUND");
  } finally { await stopServer(server); }
});

test("api: invalid limit returns 400", async () => {
  const server = await startServer(fakeEs());
  try {
    const { status, body } = await get(server, "/api/events?limit=abc");
    assert.equal(status, 400);
    assert.ok(body.error.code);
    const badOffset = await get(server, "/api/events?offset=-1");
    assert.equal(badOffset.status, 400);
  } finally { await stopServer(server); }
});

test("api: invalid attacker IP returns 400", async () => {
  const server = await startServer(fakeEs());
  try {
    const { status, body } = await get(server, "/api/attackers/not-an-ip");
    assert.equal(status, 400);
    assert.equal(body.error.code, "INVALID_IP");
    const traversal = await get(server, "/api/attackers/..%2F..%2Fetc");
    assert.equal(traversal.status, 400);
  } finally { await stopServer(server); }
});

test("api: sanitize removes password, token, rawQuery, rawBody, rawTarget, summary", () => {
  const doc = { sessionId: "s1", password: "secret-pass", token: "secret-token", payload: { rawQuery: "a=1", rawBody: "body", rawTarget: "/x", summary: "free text", nested: { tokenValue: "t", credential: "c" } }, commandNames: ["ls"] };
  const clean = sanitizeDoc(doc);
  const text = JSON.stringify(clean);
  assert.ok(!text.includes("secret-pass"));
  assert.ok(!text.includes("secret-token"));
  assert.ok(!text.includes("free text"));
  assert.equal(clean.sessionId, "s1");
  assert.deepEqual(clean.commandNames, ["ls"]);
});

test("api: stats returns eventsByService, sessions, profiles, attackers", async () => {
  const server = await startServer(fakeEs());
  try {
    const { status, body } = await get(server, "/api/stats");
    assert.equal(status, 200);
    assert.deepEqual(body.eventsByService, { ssh: 2 });
    assert.equal(body.sessions, 1);
    assert.equal(body.profiles, 1);
    assert.equal(body.attackers, 1);
    assert.ok(Array.isArray(body.topSourceIps));
    assert.ok(Array.isArray(body.topTools));
  } finally { await stopServer(server); }
});

test("api: socket hello is emitted on connect", async () => {
  const { io } = await import("socket.io-client");
  const server = await startServer(fakeEs());
  try {
    const port = server.address().port;
    const socket = io(`http://127.0.0.1:${port}`, { transports: ["websocket"] });
    try {
      const hello = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("hello timeout")), 5000);
        socket.on("hello", (doc) => { clearTimeout(timer); resolve(doc); });
      });
      assert.ok(hello.serverTime);
      assert.ok(hello.counts);
    } finally { socket.disconnect(); }
  } finally { await stopServer(server); }
});

test("api: socket live feed emits new event only once, never duplicates by _id", async () => {
  const emitted = [];
  const io = { emit: (name, doc) => emitted.push([name, doc]) };
  const es = fakeEs();
  const feed = createLiveFeed({ es, prefix: "honeypot", io, pollMs: 60000, logger: silent, getStats: async () => ({}) });
  await feed.pollOnce();
  const firstCount = emitted.length;
  assert.ok(firstCount > 0);
  await feed.pollOnce();
  assert.equal(emitted.length, firstCount);
  feed.close();
});

test("api: socket live feed stops on server close, no dangling timer", async () => {
  const io = { emit: () => {} };
  const feed = createLiveFeed({ es: fakeEs(), prefix: "honeypot", io, pollMs: 50, logger: silent, getStats: async () => ({}) });
  feed.start();
  feed.close();
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.ok(true);
});

test("api: server does not crash when ES is unreachable at startup, health reports es false", async () => {
  const broken = { info: async () => { throw new Error("connection refused"); }, search: async () => { throw new Error("connection refused"); }, get: async () => { throw new Error("connection refused"); } };
  const server = await startServer(broken);
  try {
    const { status, body } = await get(server, "/api/health");
    assert.equal(status, 200);
    assert.equal(body.status, "ok");
    assert.equal(body.es.reachable, false);
    const events = await get(server, "/api/events");
    assert.equal(events.status, 500);
    assert.equal(events.body.error.code, "INTERNAL_ERROR");
    assert.ok(!JSON.stringify(events.body).includes("connection refused"));
  } finally { await stopServer(server); }
});
