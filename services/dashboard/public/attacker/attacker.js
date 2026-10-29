import { stripForbidden, asText, tacticFor, ALLOWED_TECHNIQUES } from "../app.js";

export function isValidIp(ip) {
  if (typeof ip !== "string" || ip === "") return false;
  const v4 = ip.split(".");
  if (v4.length === 4 && v4.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) return true;
  if (ip.includes(":") && /^[0-9a-fA-F:]+$/.test(ip) && ip.split(":").length >= 3) return true;
  return false;
}

export function ipError(ip) {
  if (ip === null || ip === undefined || ip === "") return "Missing ip parameter. Open this page with an ip query, for example /dashboard/attacker?ip=127.0.0.1";
  if (!isValidIp(ip)) return "Invalid ip parameter.";
  return null;
}

export function filterProfilesBySourceIp(profiles, ip) {
  return (Array.isArray(profiles) ? profiles : []).filter((profile) => profile.sourceIp === ip);
}

export function filterSessionsBySourceIp(sessions, ip) {
  return (Array.isArray(sessions) ? sessions : []).filter((session) => session.sourceIp === ip);
}

export function attackerTechniques(attacker) {
  const ids = Array.isArray(attacker.mitreTechniqueIds) ? attacker.mitreTechniqueIds : [];
  return [...new Set(ids)].filter((id) => ALLOWED_TECHNIQUES.has(id));
}

function setText(id, text) {
  const node = document.getElementById(id);
  if (node) node.textContent = text;
}

function show(id, visible) {
  const node = document.getElementById(id);
  if (node) node.hidden = !visible;
}

function renderAttacker(attacker) {
  const clean = stripForbidden(attacker).clean;
  setText("attacker-id", asText(clean.attackerId));
  setText("attacker-ip", asText(clean.sourceIp));
  setText("attacker-first", asText(clean.firstSeen));
  setText("attacker-last", asText(clean.lastSeen));
  setText("attacker-sessions", asText(clean.sessionCount));
  setText("attacker-services", asText((clean.services || []).join(", ")));
  setText("attacker-service-count", asText(clean.serviceCount));
  setText("attacker-session-ids", asText((clean.sessionIds || []).length));
  const classification = clean.classification || {};
  setText("attacker-actor", asText(classification.actorType));
  setText("attacker-skill", asText(classification.skillLevel));
  setText("attacker-intent", asText(classification.intent));
  setText("attacker-confidence", asText(classification.confidence));
  setText("attacker-mismatch", asText(classification.llmIntentMismatch));
  const strategy = clean.strategy || {};
  setText("strategy-name", asText(strategy.name));
  setText("strategy-reason", asText(strategy.reason));
  setText("strategy-cross", asText(strategy.crossService));
  const tag = document.getElementById("strategy-tag");
  if (tag) {
    tag.textContent = asText(strategy.name);
    tag.className = "tag tag-" + asText(strategy.name);
  }
  const tools = document.getElementById("attacker-tools");
  tools.replaceChildren();
  for (const tool of clean.tools || []) {
    const item = document.createElement("li");
    item.textContent = asText(tool);
    item.className = "mono";
    tools.appendChild(item);
  }
  const commands = document.getElementById("attacker-commands");
  commands.replaceChildren();
  for (const command of clean.commandNames || []) {
    const item = document.createElement("li");
    item.textContent = asText(command);
    item.className = "mono";
    commands.appendChild(item);
  }
  const techniques = document.getElementById("attacker-techniques");
  techniques.replaceChildren();
  for (const id of attackerTechniques(clean)) {
    const item = document.createElement("li");
    item.textContent = id + " " + asText(tacticFor(id));
    item.className = "mono";
    techniques.appendChild(item);
  }
}

function renderSessions(sessions) {
  const tbody = document.getElementById("sessions-rows");
  tbody.replaceChildren();
  show("sessions-empty", sessions.length === 0);
  for (const session of sessions) {
    const clean = stripForbidden(session).clean;
    const row = document.createElement("tr");
    const cells = [clean.sessionId, clean.service, clean.firstSeen, clean.lastSeen, clean.durationMs, clean.closed, clean.eventCount];
    for (const value of cells) {
      const cell = document.createElement("td");
      cell.textContent = asText(value);
      row.appendChild(cell);
    }
    tbody.appendChild(row);
  }
}

function renderProfiles(profiles) {
  const list = document.getElementById("profiles-list");
  list.replaceChildren();
  show("profiles-empty", profiles.length === 0);
  for (const profile of profiles) {
    const clean = stripForbidden(profile).clean;
    const classification = clean.classification || {};
    const item = document.createElement("li");
    item.textContent = asText(clean.sessionId) + " " + asText(clean.service) + " " + asText(classification.intent) + "/" + asText(classification.skillLevel) + " tools:" + asText((classification.tools || []).join(",")) + " confidence:" + asText(classification.confidence);
    item.className = "mono";
    list.appendChild(item);
  }
}

async function fetchJson(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error("fetch failed: " + response.status);
  return response.json();
}

async function boot() {
  const params = new URLSearchParams(window.location.search);
  const ip = params.get("ip");
  const error = ipError(ip);
  if (error) {
    setText("attacker-error", error);
    show("attacker-error", true);
    return;
  }
  try {
    const attackerResult = await fetchJson("/api/attackers/" + encodeURIComponent(ip));
    renderAttacker(attackerResult.data);
    const sessionsResult = await fetchJson("/api/sessions?sourceIp=" + encodeURIComponent(ip) + "&limit=200");
    renderSessions(filterSessionsBySourceIp(sessionsResult.data || [], ip));
    const profilesResult = await fetchJson("/api/profiles?limit=200");
    renderProfiles(filterProfilesBySourceIp(profilesResult.data || [], ip));
  } catch {
    setText("attacker-error", "Failed to load attacker data. Check that the API is running.");
    show("attacker-error", true);
  }
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => { void boot(); });
  else void boot();
}
