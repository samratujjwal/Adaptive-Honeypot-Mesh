import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { normalize } from "./normalize.js";

const rulesPath = join(dirname(fileURLToPath(import.meta.url)), "rules.json");
let cachedRules = null;

/**
 * Load the local rules file. Falls back to an empty list on any error.
 *
 * @returns {Array<object>}
 */
export function loadRules() {
  if (cachedRules) return cachedRules;
  try {
    cachedRules = JSON.parse(readFileSync(rulesPath, "utf8"));
  } catch {
    cachedRules = [];
  }
  return cachedRules;
}

function firstToken(text) {
  return text.split(/\s+/)[0] || "";
}

function matchRule(rule, segment) {
  if (rule.match === "exact") {
    return firstToken(segment) === rule.pattern ? rule.pattern : null;
  }
  if (rule.match === "keyword") {
    const tokens = segment.split(/[^a-z0-9_]+/).filter(Boolean);
    return tokens.includes(rule.pattern) ? rule.pattern : null;
  }
  if (rule.match === "regex") {
    try {
      const found = segment.match(new RegExp(rule.pattern));
      return found ? found[0].slice(0, 64) : null;
    } catch {
      return null;
    }
  }
  return null;
}

function splitSegments(text) {
  return text.split(/;|&&|\|\|?/).map((part) => normalize(part)).filter(Boolean);
}

/**
 * Decode percent-encoding exactly once. Never throws.
 *
 * @param {unknown} text
 * @param {boolean} [plusAsSpace]
 * @returns {string}
 */
export function decodeOnce(text, plusAsSpace) {
  if (typeof text !== "string" || !text) return "";
  const input = plusAsSpace ? text.replace(/\+/g, " ") : text;
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

function httpText(payload) {
  const rawTarget = typeof payload.rawTarget === "string" && payload.rawTarget ? payload.rawTarget : (payload.path || "");
  const parts = [decodeOnce(rawTarget, false), payload.method || "", decodeOnce(payload.query || "", true), decodeOnce(payload.bodyPreview || "", false)];
  return normalize(parts.join(" "));
}

function commandText(payload) {
  if (typeof payload.command === "string" && payload.command) return payload.command;
  if (typeof payload.tool === "string" && payload.tool) return `${payload.tool} ${payload.url || ""}`;
  return "";
}

/**
 * Classify one event into MITRE techniques using only local rules.
 *
 * @param {object} event
 * @returns {Array<{ techniqueId: string, tactic: string, confidence: number, ruleId: string, matched: string }>}
 */
export function classify(event) {
  try {
    if (!event || typeof event !== "object") return [];
    const service = event.service || (event.honeypot && event.honeypot.service) || null;
    const payload = event.payload && typeof event.payload === "object" ? event.payload : {};
    const byTechnique = new Map();
    const add = (item) => {
      const existing = byTechnique.get(item.techniqueId);
      if (!existing || item.confidence > existing.confidence) byTechnique.set(item.techniqueId, item);
    };
    if (event.eventType === "auth_attempt") {
      add({ techniqueId: "T1110.001", tactic: "Credential Access", confidence: 0.4, ruleId: "auth-guess", matched: "auth_attempt" });
      if (payload.success === true) {
        add({ techniqueId: "T1078", tactic: "Initial Access", confidence: 0.4, ruleId: "auth-valid", matched: "auth_attempt success" });
      }
      return [...byTechnique.values()].sort((a, b) => b.confidence - a.confidence || a.techniqueId.localeCompare(b.techniqueId)).slice(0, 5);
    }
    if (event.eventType === "honeytoken") {
      if (payload.action === "used") {
        add({ techniqueId: "T1552.001", tactic: "Credential Access", confidence: 0.9, ruleId: "honeytoken-used", matched: "honeytoken used" });
      }
      return [...byTechnique.values()];
    }
    let segments = [];
    let isHttp = false;
    if (event.eventType === "http_request") {
      isHttp = true;
      segments = [httpText(payload)];
    } else {
      const text = commandText(payload);
      if (!text) return [];
      segments = splitSegments(text);
    }
    const rules = loadRules();
    for (const segment of segments) {
      for (const rule of rules) {
        if (!rule.services.includes(service)) continue;
        if (isHttp && !rule.services.includes("http")) continue;
        if (!isHttp && rule.services.includes("http") && !rule.services.includes(service)) continue;
        const matched = matchRule(rule, segment);
        if (matched !== null) {
          add({ techniqueId: rule.techniqueId, tactic: rule.tactic, confidence: rule.confidence, ruleId: rule.ruleId, matched });
        }
      }
    }
    return [...byTechnique.values()].sort((a, b) => b.confidence - a.confidence || a.techniqueId.localeCompare(b.techniqueId)).slice(0, 5);
  } catch {
    return [];
  }
}
