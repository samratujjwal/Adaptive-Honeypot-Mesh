export const FORBIDDEN_KEYS = new Set(["password", "pwd", "token", "tokenValue", "credential", "credentials", "rawQuery", "rawBody", "rawTarget", "summary"]);

export const ALLOWED_TECHNIQUES = new Set(["T1033", "T1057", "T1082", "T1083", "T1087", "T1003", "T1552.001", "T1016", "T1046", "T1105", "T1027", "T1547", "T1190", "T1110.001", "T1078"]);

export const TECHNIQUE_TACTICS = {
  T1033: "Discovery",
  T1057: "Discovery",
  T1082: "Discovery",
  T1083: "Discovery",
  T1087: "Discovery",
  T1003: "Credential Access",
  "T1552.001": "Credential Access",
  T1016: "Discovery",
  T1046: "Discovery",
  T1105: "Command and Control",
  T1027: "Defense Evasion",
  T1547: "Persistence",
  T1190: "Initial Access",
  "T1110.001": "Credential Access",
  T1078: "Initial Access",
};

export function stripForbidden(value) {
  let stripped = 0;
  function walk(item) {
    if (Array.isArray(item)) return item.map(walk);
    if (!item || typeof item !== "object") return item;
    const out = {};
    for (const [key, child] of Object.entries(item)) {
      if (FORBIDDEN_KEYS.has(key)) {
        stripped += 1;
        continue;
      }
      out[key] = walk(child);
    }
    return out;
  }
  return { clean: walk(value), stripped };
}

export function asText(value) {
  if (value === null || value === undefined) return "";
  return String(value);
}

export function docId(doc) {
  if (!doc || typeof doc !== "object") return null;
  return doc.id || doc.sessionId || doc.attackerId || null;
}

export function addToFeed(feed, doc) {
  const id = docId(doc);
  if (id && feed.some((row) => docId(row) === id)) return feed;
  const next = [doc, ...feed];
  return next.slice(0, 100);
}

export function bucketTimeline(events, nowMs) {
  const buckets = [];
  for (let i = 23; i >= 0; i -= 1) {
    const start = Math.floor(nowMs / 3600000) * 3600000 - i * 3600000;
    buckets.push({ start, label: new Date(start).toISOString().slice(11, 13) + ":00", count: 0 });
  }
  const earliest = buckets[0].start;
  for (const event of events) {
    const stamp = Date.parse(event.timestamp || event.ingestedAt || "");
    if (Number.isNaN(stamp) || stamp < earliest || stamp > nowMs) continue;
    const index = Math.floor((stamp - earliest) / 3600000);
    if (index >= 0 && index < 24) buckets[index].count += 1;
  }
  return buckets;
}

export function topCommands(profiles) {
  const counts = new Map();
  for (const profile of profiles) {
    const names = Array.isArray(profile.commandNames) ? profile.commandNames : [];
    for (const name of names) counts.set(name, (counts.get(name) || 0) + 1);
  }
  return [...counts.entries()].map(([command, count]) => ({ command, count })).sort((a, b) => b.count - a.count || a.command.localeCompare(b.command)).slice(0, 10);
}

export function heatmapCounts(profiles, attackers) {
  const counts = new Map();
  let dropped = 0;
  function collect(ids) {
    for (const id of Array.isArray(ids) ? ids : []) {
      if (ALLOWED_TECHNIQUES.has(id)) counts.set(id, (counts.get(id) || 0) + 1);
      else dropped += 1;
    }
  }
  for (const profile of profiles) collect(profile.mitreTechniqueIds);
  for (const attacker of attackers) collect(attacker.mitreTechniqueIds);
  const cells = [...counts.entries()].map(([techniqueId, count]) => ({ techniqueId, tactic: TECHNIQUE_TACTICS[techniqueId], count })).sort((a, b) => b.count - a.count || a.techniqueId.localeCompare(b.techniqueId));
  return { cells, dropped };
}

export function tacticFor(techniqueId) {
  return TECHNIQUE_TACTICS[techniqueId] || null;
}

export function geoNote(ip, geo) {
  if (ip === "127.0.0.1" || ip === "::1") return "No geo data for loopback traffic";
  if (!geo) return "No geo data available";
  return asText(geo);
}

export function statsCards(counts) {
  if (!counts || typeof counts !== "object") return null;
  return {
    eventsByService: counts.eventsByService || {},
    events: counts.events,
    sessions: counts.sessions,
    profiles: counts.profiles,
    attackers: counts.attackers,
    topSourceIps: counts.topSourceIps || [],
    topTools: counts.topTools || [],
  };
}

export function sortNewestFirst(events) {
  return [...events].sort((a, b) => {
    const ta = Date.parse(a.timestamp || a.updatedAt || a.lastSeen || "");
    const tb = Date.parse(b.timestamp || b.updatedAt || b.lastSeen || "");
    if (Number.isNaN(ta) && Number.isNaN(tb)) return 0;
    if (Number.isNaN(ta)) return 1;
    if (Number.isNaN(tb)) return -1;
    return tb - ta;
  });
}

export function maxTimestamp(events) {
  let best = null;
  for (const event of events) {
    const stamp = event.timestamp || event.updatedAt || event.lastSeen || null;
    if (stamp && (!best || stamp > best)) best = stamp;
  }
  return best;
}

export function initialLoad(events, nowMs) {
  const sorted = sortNewestFirst(events).slice(0, 200);
  return {
    feed: sorted.slice(0, 20),
    timelineEvents: sorted,
    buckets: bucketTimeline(sorted, nowMs),
    lastEvent: maxTimestamp(sorted),
  };
}

export function timelineIsEmpty(buckets) {
  return buckets.every((bucket) => bucket.count === 0);
}

export function applyLiveDocument(state, doc, nowMs) {
  const stripped = stripForbidden(doc);
  const clean = stripped.clean;
  const next = addToFeed(state.feed, clean);
  const changed = next !== state.feed;
  let lastEvent = state.lastEvent;
  const stamp = clean.timestamp || clean.updatedAt || clean.lastSeen || null;
  if (stamp && (!lastEvent || stamp > lastEvent)) lastEvent = stamp;
  let timelineEvents = state.timelineEvents;
  let buckets = state.buckets;
  if (changed && clean.eventType) {
    timelineEvents = [...state.timelineEvents, clean];
    buckets = bucketTimeline(timelineEvents, nowMs);
  }
  return { feed: next, timelineEvents, buckets, lastEvent, changed };
}

export function applyStats(state, counts) {
  return { ...state, stats: counts };
}

export function isLoopback(ip) {
  return ip === "127.0.0.1" || ip === "::1";
}

const POLL_MS = 5000;
const STATS_MS = 30000;
const FEED_OFFLINE_MS = 10000;

let feed = [];
let lastStats = null;
let lastEventTime = null;
let esReachable = "unknown";
let pollTimer = null;
let statsTimer = null;
let offlineTimer = null;
let socketConnected = false;

function apiBase() {
  if (typeof window === "undefined" || !window.location) return "";
  const host = window.location.hostname;
  if (host === "127.0.0.1" || host === "localhost" || host === "") return "";
  return "http://127.0.0.1:3001";
}

function setText(id, text) {
  const node = document.getElementById(id);
  if (node) node.textContent = text;
}

function show(id, visible) {
  const node = document.getElementById(id);
  if (node) node.hidden = !visible;
}

function renderStatus() {
  setText("status-line", "ES reachable: " + esReachable + " | Kafka: unknown | Last event: " + (lastEventTime || "none"));
}

function renderStats() {
  const cards = statsCards(lastStats);
  if (!cards) return;
  show("stats-empty", false);
  const body = document.getElementById("stats-body");
  body.replaceChildren();
  const rows = [
    ["Events", cards.events],
    ["Sessions", cards.sessions],
    ["Profiles", cards.profiles],
    ["Attackers", cards.attackers],
  ];
  for (const [label, value] of rows) {
    const row = document.createElement("div");
    const name = document.createElement("span");
    name.textContent = label + ": ";
    const num = document.createElement("span");
    num.textContent = asText(value);
    num.className = "mono";
    row.append(name, num);
    body.appendChild(row);
  }
  const services = document.getElementById("events-by-service");
  services.replaceChildren();
  for (const [service, count] of Object.entries(cards.eventsByService)) {
    const row = document.createElement("div");
    const name = document.createElement("span");
    name.textContent = service + ": ";
    const num = document.createElement("span");
    num.textContent = asText(count);
    num.className = "mono";
    row.append(name, num);
    services.appendChild(row);
  }
  const ips = document.getElementById("top-ips");
  ips.replaceChildren();
  for (const entry of cards.topSourceIps) {
    const row = document.createElement("div");
    row.textContent = asText(entry.ip) + ": " + asText(entry.count);
    row.className = "mono";
    ips.appendChild(row);
  }
  const tools = document.getElementById("top-tools");
  tools.replaceChildren();
  for (const entry of cards.topTools) {
    const row = document.createElement("div");
    row.textContent = asText(entry.tool) + ": " + asText(entry.count);
    row.className = "mono";
    tools.appendChild(row);
  }
  setText("footer-totals", "Totals: events " + asText(cards.events) + " | sessions " + asText(cards.sessions) + " | profiles " + asText(cards.profiles) + " | attackers " + asText(cards.attackers));
}

function feedDetail(doc, kind) {
  if (kind === "attacker") return (doc.strategy ? doc.strategy.name : "") + " " + (doc.sourceIp || doc.attackerId || "");
  if (kind === "profile") return (doc.classification ? doc.classification.intent + "/" + doc.classification.skillLevel : "") + " " + (doc.service || "");
  return (doc.eventType || "") + " " + (doc.honeypot && doc.honeypot.service ? doc.honeypot.service : (doc.service || ""));
}

function renderFeed() {
  const tbody = document.getElementById("feed-rows");
  tbody.replaceChildren();
  show("feed-empty", feed.length === 0);
  for (const doc of feed) {
    const kind = doc.attackerId ? "attacker" : (doc.classification ? "profile" : "event");
    const row = document.createElement("tr");
    const time = document.createElement("td");
    time.textContent = asText(doc.timestamp || doc.updatedAt || doc.lastSeen || "");
    time.title = asText(doc.timestamp || doc.updatedAt || doc.lastSeen || "");
    const kindCell = document.createElement("td");
    kindCell.textContent = kind;
    const idCell = document.createElement("td");
    const idText = asText(docId(doc) || "");
    idCell.textContent = idText.length > 16 ? idText.slice(0, 16) + "..." : idText;
    idCell.title = idText;
    idCell.className = "trunc";
    const detail = document.createElement("td");
    detail.textContent = feedDetail(doc, kind);
    if (kind === "attacker" && doc.strategy) {
      const tag = document.createElement("span");
      tag.textContent = doc.strategy.name;
      tag.className = "tag tag-" + doc.strategy.name;
      detail.appendChild(document.createTextNode(" "));
      detail.appendChild(tag);
    }
    row.append(time, kindCell, idCell, detail);
    tbody.appendChild(row);
  }
}

export function ingestDoc(currentFeed, doc) {
  const stripped = stripForbidden(doc);
  const next = addToFeed(currentFeed, stripped.clean);
  return { feed: next, changed: next !== currentFeed, stripped: stripped.stripped };
}

let liveState = { feed: [], timelineEvents: [], buckets: [], lastEvent: null, stats: null };

function pushDoc(doc) {
  const result = applyLiveDocument(liveState, doc, Date.now());
  liveState = result;
  feed = result.feed;
  if (result.changed) {
    lastEventTime = result.lastEvent;
    renderFeed();
    renderTimelineBuckets(result.buckets);
    renderStatus();
  } else if (result.lastEvent !== lastEventTime) {
    lastEventTime = result.lastEvent;
    renderStatus();
  }
}

function renderTimelineBuckets(buckets) {
  const wrap = document.getElementById("timeline-bars");
  wrap.replaceChildren();
  show("timeline-empty", timelineIsEmpty(buckets));
  const max = Math.max(1, ...buckets.map((b) => b.count));
  for (const bucket of buckets) {
    const col = document.createElement("div");
    col.className = "hour-col";
    const count = document.createElement("span");
    count.textContent = String(bucket.count);
    count.className = "hour-count";
    const bar = document.createElement("div");
    bar.className = "hour-bar";
    bar.style.height = Math.round((bucket.count / max) * 80) + "px";
    const label = document.createElement("span");
    label.textContent = bucket.label;
    label.className = "hour-label";
    col.append(count, bar, label);
    wrap.appendChild(col);
  }
}

function renderCommands(profiles) {
  const top = topCommands(profiles);
  const list = document.getElementById("commands-list");
  list.replaceChildren();
  show("commands-empty", top.length === 0);
  for (const entry of top) {
    const item = document.createElement("li");
    item.textContent = entry.command + ": " + entry.count;
    item.className = "mono";
    list.appendChild(item);
  }
}

function renderHeatmap(profiles, attackers) {
  const result = heatmapCounts(profiles, attackers);
  const grid = document.getElementById("heatmap-grid");
  grid.replaceChildren();
  show("heatmap-empty", result.cells.length === 0);
  const max = Math.max(1, ...result.cells.map((c) => c.count));
  for (const cell of result.cells) {
    const level = cell.count >= max ? 4 : cell.count >= Math.ceil(max * 0.6) ? 3 : cell.count >= Math.ceil(max * 0.3) ? 2 : 1;
    const node = document.createElement("div");
    node.className = "heat-cell heat-" + level;
    const id = document.createElement("div");
    id.textContent = cell.techniqueId;
    const tactic = document.createElement("div");
    tactic.textContent = cell.tactic;
    const count = document.createElement("div");
    count.textContent = String(cell.count);
    node.append(id, tactic, count);
    grid.appendChild(node);
  }
  setText("heatmap-dropped", result.dropped > 0 ? "Dropped unknown technique IDs: " + result.dropped : "");
}

function renderMap() {
  const cards = statsCards(lastStats);
  const list = document.getElementById("map-list");
  list.replaceChildren();
  if (!cards || cards.topSourceIps.length === 0) {
    show("map-empty", true);
    return;
  }
  show("map-empty", false);
  for (const entry of cards.topSourceIps) {
    const item = document.createElement("li");
    item.className = "mono";
    item.textContent = asText(entry.ip) + ": " + asText(entry.count) + " | " + geoNote(entry.ip, entry.geo || null);
    list.appendChild(item);
  }
}

async function fetchJson(path) {
  const response = await fetch(apiBase() + path);
  if (!response.ok) throw new Error("fetch failed: " + response.status);
  return response.json();
}

async function refreshStats() {
  try {
    lastStats = await fetchJson("/api/stats");
    liveState = applyStats(liveState, lastStats);
    renderStats();
    renderMap();
  } catch {
    esReachable = "no";
    renderStatus();
  }
}

async function pollEvents() {
  try {
    const result = await fetchJson("/api/events?limit=20");
    for (const doc of [...result.data].reverse()) pushDoc(doc);
    setText("last-poll", "Last poll: " + new Date().toISOString());
  } catch {
    esReachable = "no";
    renderStatus();
  }
}

function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(() => { void pollEvents(); }, POLL_MS);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function markOffline() {
  show("offline-banner", true);
  startPolling();
}

function markOnline() {
  show("offline-banner", false);
  stopPolling();
  if (offlineTimer) {
    clearTimeout(offlineTimer);
    offlineTimer = null;
  }
}

async function boot() {
  const clock = document.getElementById("clock-utc");
  setInterval(() => { clock.textContent = new Date().toISOString(); }, 1000);
  clock.textContent = new Date().toISOString();
  try {
    const health = await fetchJson("/api/health");
    esReachable = health.es && health.es.reachable ? "yes" : "no";
  } catch {
    esReachable = "no";
  }
  renderStatus();
  try {
    lastStats = await fetchJson("/api/stats");
    liveState = applyStats(liveState, lastStats);
    renderStats();
  } catch {
    esReachable = "no";
  }
  let events = [];
  let profiles = [];
  let attackers = [];
  try {
    const result = await fetchJson("/api/events?limit=200");
    events = result.data || [];
    const loaded = initialLoad(events, Date.now());
    liveState = { feed: loaded.feed, timelineEvents: loaded.timelineEvents, buckets: loaded.buckets, lastEvent: loaded.lastEvent, stats: liveState.stats };
    feed = loaded.feed;
    lastEventTime = loaded.lastEvent;
    renderFeed();
    renderTimelineBuckets(loaded.buckets);
  } catch {}
  try {
    const result = await fetchJson("/api/profiles?limit=200");
    profiles = result.data || [];
  } catch {}
  try {
    const result = await fetchJson("/api/attackers?limit=50");
    attackers = result.data || [];
  } catch {}
  renderCommands(profiles);
  renderHeatmap(profiles, attackers);
  renderMap();
  renderStatus();
  statsTimer = setInterval(() => { void refreshStats(); }, STATS_MS);
  if (typeof window !== "undefined" && window.io) {
    const socket = window.io(apiBase() || undefined);
    socket.on("hello", (hello) => {
      if (hello && hello.counts) {
        lastStats = hello.counts;
        renderStats();
        renderMap();
      }
    });
    socket.on("event", (doc) => pushDoc(doc));
    socket.on("profile", (doc) => pushDoc(doc));
    socket.on("attacker", (doc) => pushDoc(doc));
    socket.on("connect", () => {
      socketConnected = true;
      markOnline();
    });
    socket.on("disconnect", () => {
      socketConnected = false;
      if (offlineTimer) clearTimeout(offlineTimer);
      offlineTimer = setTimeout(() => {
        if (!socketConnected) markOffline();
      }, FEED_OFFLINE_MS);
    });
    socket.on("connect_error", () => {
      if (offlineTimer) clearTimeout(offlineTimer);
      offlineTimer = setTimeout(() => {
        if (!socketConnected) markOffline();
      }, FEED_OFFLINE_MS);
    });
  } else {
    markOffline();
  }
  setText("last-poll", "Last poll: " + new Date().toISOString());
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => { void boot(); });
  else void boot();
}
