import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "../../api/src/server.js";
import { stripForbidden, asText, addToFeed, ingestDoc, bucketTimeline, topCommands, heatmapCounts, tacticFor, geoNote, statsCards } from "../public/app.js";

const silent = { info: () => {}, warn: () => {}, error: () => {} };
const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
const appJs = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
const css = readFileSync(new URL("../public/style.css", import.meta.url), "utf8");

function fakeEs() {
  return {
    info: async () => ({}),
    search: async (params) => {
      const index = params.index || "";
      if (index.includes("events")) return { hits: { total: { value: 1 }, hits: [{ _id: "e1", _source: { eventType: "command", timestamp: "2026-10-29T00:00:00Z" } }] }, aggregations: { byService: { buckets: [] }, bySourceIp: { buckets: [] } } };
      if (index.includes("sessions")) return { hits: { total: { value: 1 }, hits: [] } };
      if (index.includes("profiles")) return { hits: { total: { value: 1 }, hits: [] }, aggregations: { byTool: { buckets: [] } } };
      if (index.includes("attackers")) return { hits: { total: { value: 1 }, hits: [] } };
      return { hits: { total: { value: 0 }, hits: [] } };
    },
    get: async () => { const e = new Error("not found"); e.statusCode = 404; throw e; },
  };
}

async function startServer() {
  const server = createServer({ es: fakeEs(), logger: silent, config: { ES_INDEX_PREFIX: "honeypot", API_POLL_MS: 60000 } });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server;
}

async function stopServer(server) {
  await new Promise((resolve) => server.closeApi(resolve));
}

async function get(server, path) {
  const port = server.address().port;
  const response = await fetch(`http://127.0.0.1:${port}${path}`);
  return { status: response.status, text: await response.text(), json: async () => JSON.parse(response.text()) };
}

test("dashboard html served 200 and contains all six section ids", async () => {
  const server = await startServer();
  try {
    const { status, text } = await get(server, "/dashboard");
    assert.equal(status, 200);
    for (const id of ["live-feed", "stats-cards", "timeline", "top-commands", "attack-heatmap", "world-map"]) assert.ok(text.includes(`id="${id}"`), `missing ${id}`);
  } finally { await stopServer(server); }
});

test("dashboard html contains no external CDN, font, or tile URL", async () => {
  const combined = html + appJs + css;
  const urls = combined.match(/https?:\/\/[^\s"'\)]+/g) || [];
  for (const url of urls) assert.ok(url.startsWith("http://127.0.0.1:3001"), `external url ${url}`);
  assert.ok(!combined.includes("cdn"));
  assert.ok(!combined.includes("fonts.googleapis"));
  assert.ok(!combined.includes("tile"));
});

test("api data routes unchanged after dashboard route is added, including /api/unknown still 404", async () => {
  const server = await startServer();
  try {
    const port = server.address().port;
    const health = await fetch(`http://127.0.0.1:${port}/api/health`);
    assert.equal(health.status, 200);
    const unknown = await fetch(`http://127.0.0.1:${port}/api/unknown`);
    assert.equal(unknown.status, 404);
    const body = await unknown.json();
    assert.equal(body.error.code, "NOT_FOUND");
    assert.ok(!JSON.stringify(body).includes("stack"));
  } finally { await stopServer(server); }
});

test("root route unchanged, still 404 as on Day 14", async () => {
  const server = await startServer();
  try {
    const port = server.address().port;
    const root = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(root.status, 404);
  } finally { await stopServer(server); }
});

test("strip forbidden keys recursively before render, including nested objects and arrays", () => {
  const doc = { sessionId: "s1", password: "p", nested: { token: "t", list: [{ rawQuery: "q", keep: 1 }] }, summary: "s" };
  const result = stripForbidden(doc);
  assert.equal(result.stripped, 4);
  assert.equal(result.clean.password, undefined);
  assert.equal(result.clean.summary, undefined);
  assert.equal(result.clean.nested.token, undefined);
  assert.equal(result.clean.nested.list[0].rawQuery, undefined);
  assert.equal(result.clean.nested.list[0].keep, 1);
  assert.equal(result.clean.sessionId, "s1");
  const ingested = ingestDoc([], { id: "e1", password: "secret-pass", nested: { token: "secret-token" } });
  assert.equal(ingested.stripped, 2);
  assert.equal(ingested.feed[0].password, undefined);
  assert.equal(ingested.feed[0].nested.token, undefined);
  assert.equal(ingested.changed, true);
});

test("attacker string with script tag is rendered as text, never as HTML, via the escaping helper", () => {
  const evil = "<script>alert(1)</script>";
  assert.equal(asText(evil), evil);
  assert.ok(!appJs.includes("innerHTML"));
  assert.ok(!appJs.includes("document.write"));
  assert.ok(!appJs.includes("insertAdjacentHTML"));
  assert.ok(appJs.includes("textContent"));
});

test("live feed dedup by id, second copy of the same id is dropped", () => {
  const first = addToFeed([], { id: "e1", eventType: "command" });
  assert.equal(first.length, 1);
  const second = addToFeed(first, { id: "e1", eventType: "command" });
  assert.equal(second.length, 1);
  assert.equal(second, first);
});

test("live feed cap at 100, 101st new document drops the oldest", () => {
  let feed = [];
  for (let i = 0; i < 101; i += 1) feed = addToFeed(feed, { id: String(i) });
  assert.equal(feed.length, 100);
  assert.equal(feed[0].id, "100");
  assert.equal(feed[99].id, "1");
});

test("timeline buckets by hour UTC, last 24 hours only, empty hour is zero", () => {
  const now = Date.parse("2026-10-29T01:30:00Z");
  const buckets = bucketTimeline([
    { timestamp: "2026-10-29T00:15:00Z" },
    { timestamp: "2026-10-29T00:45:00Z" },
    { timestamp: "2026-10-27T00:00:00Z" },
    { timestamp: "not-a-date" },
  ], now);
  assert.equal(buckets.length, 24);
  const hour00 = buckets.find((b) => b.label === "00:00");
  assert.equal(hour00.count, 2);
  const empty = buckets.filter((b) => b.count === 0);
  assert.ok(empty.length >= 20);
});

test("top commands from profiles only, top 10 descending, correct counts", () => {
  const profiles = [];
  for (let i = 0; i < 12; i += 1) profiles.push({ commandNames: ["cmd" + i, "ls"] });
  const top = topCommands(profiles);
  assert.equal(top.length, 10);
  assert.equal(top[0].command, "ls");
  assert.equal(top[0].count, 12);
  for (let i = 1; i < top.length; i += 1) assert.ok(top[i - 1].count >= top[i].count);
});

test("heatmap counts only allowed technique IDs, unknown ID dropped and counted", () => {
  const result = heatmapCounts([{ mitreTechniqueIds: ["T1033", "T9999", "T1105"] }], [{ mitreTechniqueIds: ["T1033", "FAKE"] }]);
  assert.equal(result.dropped, 2);
  assert.deepEqual(result.cells.map((c) => c.techniqueId).sort(), ["T1033", "T1105"]);
  assert.equal(result.cells.find((c) => c.techniqueId === "T1033").count, 2);
});

test("heatmap tactic comes from mitre rules, never invented", () => {
  assert.equal(tacticFor("T1033"), "Discovery");
  assert.equal(tacticFor("T1105"), "Command and Control");
  assert.equal(tacticFor("T1547"), "Persistence");
  assert.equal(tacticFor("T1190"), "Initial Access");
  assert.equal(tacticFor("T1078"), "Initial Access");
  assert.equal(tacticFor("T1110.001"), "Credential Access");
  assert.equal(tacticFor("T9999"), null);
});

test("world map with null geo shows loopback note and no fake coordinate", () => {
  const note = geoNote("127.0.0.1", null);
  assert.equal(note, "No geo data for loopback traffic");
  assert.ok(!note.includes("lat"));
  assert.ok(!note.includes("lon"));
  assert.ok(!/\d+\.\d+/.test(note));
});

test("stats cards render from hello counts with identical field names", () => {
  const counts = { eventsByService: { ssh: 3 }, events: 3, sessions: 2, profiles: 2, attackers: 1, topSourceIps: [{ ip: "127.0.0.1", count: 3 }], topTools: [{ tool: "wget", count: 1 }] };
  const cards = statsCards(counts);
  assert.deepEqual(cards.eventsByService, { ssh: 3 });
  assert.equal(cards.events, 3);
  assert.equal(cards.sessions, 2);
  assert.equal(cards.profiles, 2);
  assert.equal(cards.attackers, 1);
  assert.deepEqual(cards.topSourceIps, [{ ip: "127.0.0.1", count: 3 }]);
  assert.deepEqual(cards.topTools, [{ tool: "wget", count: 1 }]);
});

test("socket disconnect fallback polls events and dedups against socket docs", () => {
  let feed = addToFeed([], { id: "e1", eventType: "command" });
  const polled = [{ id: "e1", eventType: "command" }, { id: "e2", eventType: "command" }];
  for (const doc of polled) feed = addToFeed(feed, doc);
  assert.equal(feed.length, 2);
  assert.equal(feed[0].id, "e2");
  assert.equal(feed[1].id, "e1");
});

test("initial feed is newest first, first row is the maximum timestamp, not the oldest", async () => {
  const { initialLoad } = await import("../public/app.js");
  const events = [
    { id: "e1", eventType: "command", timestamp: "2026-10-27T10:00:00Z" },
    { id: "e2", eventType: "command", timestamp: "2026-10-29T11:00:00Z" },
    { id: "e3", eventType: "command", timestamp: "2026-10-28T10:00:00Z" },
  ];
  const loaded = initialLoad(events, Date.parse("2026-10-29T12:00:00Z"));
  assert.equal(loaded.feed[0].id, "e2");
  assert.equal(loaded.feed[0].timestamp, "2026-10-29T11:00:00Z");
  assert.equal(loaded.lastEvent, "2026-10-29T11:00:00Z");
});

test("initial timeline uses the newest 200 events filtered to last 24 hours, not the oldest 20", async () => {
  const { initialLoad } = await import("../public/app.js");
  const events = [];
  for (let i = 0; i < 30; i += 1) events.push({ id: "old" + i, eventType: "command", timestamp: "2026-10-27T10:00:00Z" });
  events.push({ id: "fresh", eventType: "http_request", timestamp: "2026-10-29T11:00:00Z" });
  const loaded = initialLoad(events, Date.parse("2026-10-29T12:00:00Z"));
  const total = loaded.buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  assert.equal(total, 1);
  assert.equal(loaded.feed[0].id, "fresh");
});

test("live document prepends to feed exactly once, newest first, dedup still works", async () => {
  const { applyLiveDocument } = await import("../public/app.js");
  const now = Date.parse("2026-10-29T12:00:00Z");
  let state = { feed: [{ id: "e1", eventType: "command", timestamp: "2026-10-29T10:00:00Z" }], timelineEvents: [], buckets: [], lastEvent: "2026-10-29T10:00:00Z", stats: null };
  state = applyLiveDocument(state, { id: "e2", eventType: "http_request", timestamp: "2026-10-29T11:00:00Z" }, now);
  assert.equal(state.feed[0].id, "e2");
  assert.equal(state.feed.length, 2);
  assert.equal(state.changed, true);
  const again = applyLiveDocument(state, { id: "e2", eventType: "http_request", timestamp: "2026-10-29T11:00:00Z" }, now);
  assert.equal(again.feed.length, 2);
  assert.equal(again.changed, false);
});

test("live document recomputes timeline, current hour bucket increments by one", async () => {
  const { applyLiveDocument, bucketTimeline } = await import("../public/app.js");
  const now = Date.parse("2026-10-29T12:30:00Z");
  const base = { feed: [], timelineEvents: [], buckets: bucketTimeline([], now), lastEvent: null, stats: null };
  const after = applyLiveDocument(base, { id: "e1", eventType: "http_request", timestamp: "2026-10-29T12:05:00Z" }, now);
  const total = after.buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  assert.equal(total, 1);
  const hour12 = after.buckets.find((bucket) => bucket.label === "12:00");
  assert.equal(hour12.count, 1);
});

test("live document updates top-bar last event to the new maximum timestamp", async () => {
  const { applyLiveDocument } = await import("../public/app.js");
  const now = Date.parse("2026-10-29T12:00:00Z");
  const base = { feed: [], timelineEvents: [], buckets: [], lastEvent: "2026-10-27T16:33:53Z", stats: null };
  const after = applyLiveDocument(base, { id: "e1", eventType: "http_request", timestamp: "2026-10-29T11:00:00Z" }, now);
  assert.equal(after.lastEvent, "2026-10-29T11:00:00Z");
  const older = applyLiveDocument(after, { id: "e2", eventType: "command", timestamp: "2026-10-28T10:00:00Z" }, now);
  assert.equal(older.lastEvent, "2026-10-29T11:00:00Z");
});

test("stats refresh does not clear or reset live feed rows", async () => {
  const { applyStats } = await import("../public/app.js");
  const feed = [{ id: "e1" }, { id: "e2" }];
  const state = { feed, timelineEvents: [], buckets: [], lastEvent: "2026-10-29T11:00:00Z", stats: null };
  const after = applyStats(state, { events: 999, sessions: 1, profiles: 1, attackers: 1 });
  assert.equal(after.feed, feed);
  assert.equal(after.feed.length, 2);
  assert.equal(after.stats.events, 999);
});

test("polling document and socket document with the same id are shown only once", async () => {
  const { applyLiveDocument } = await import("../public/app.js");
  const now = Date.parse("2026-10-29T12:00:00Z");
  let state = { feed: [], timelineEvents: [], buckets: [], lastEvent: null, stats: null };
  state = applyLiveDocument(state, { id: "e9", eventType: "command", timestamp: "2026-10-29T11:00:00Z" }, now);
  state = applyLiveDocument(state, { id: "e9", eventType: "command", timestamp: "2026-10-29T11:00:00Z" }, now);
  assert.equal(state.feed.length, 1);
});

test("timeline empty text appears only when last 24 hour count is actually zero", async () => {
  const { bucketTimeline, timelineIsEmpty } = await import("../public/app.js");
  const now = Date.parse("2026-10-29T12:00:00Z");
  assert.equal(timelineIsEmpty(bucketTimeline([], now)), true);
  assert.equal(timelineIsEmpty(bucketTimeline([{ timestamp: "2026-10-27T10:00:00Z" }], now)), true);
  assert.equal(timelineIsEmpty(bucketTimeline([{ timestamp: "2026-10-29T11:00:00Z" }], now)), false);
});
