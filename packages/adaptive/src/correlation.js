import { ALLOWED_TOOLS } from "../../profile/src/rules.js";
import { decideStrategy } from "./strategy.js";

const SKILL_ORDER = ["unknown", "beginner", "intermediate", "advanced"];
const INTENT_ORDER = ["unknown", "recon", "credential_access", "exploitation", "exfiltration", "persistence"];

/**
 * Correlate closed-session profiles from one source IP into a
 * single attacker profile. Rules only, deterministic, no LLM,
 * no network, no file I/O. Throws a plain Error on mixed
 * sourceIps, never silently merges them.
 *
 * @param {object[]} profiles
 * @returns {object}
 */
export function correlateProfiles(profiles) {
  if (!Array.isArray(profiles) || profiles.length === 0) throw new Error("correlateProfiles requires a non-empty array of profiles");
  const sourceIp = profiles[0].sourceIp;
  if (typeof sourceIp !== "string" || sourceIp === "") throw new Error("correlateProfiles requires a sourceIp on every profile");
  for (const profile of profiles) {
    if (profile.sourceIp !== sourceIp) throw new Error("correlateProfiles refuses mixed sourceIps");
  }
  const sessionIds = [];
  for (const profile of profiles) {
    if (profile.sessionId && !sessionIds.includes(profile.sessionId)) sessionIds.push(profile.sessionId);
  }
  const services = [...new Set(profiles.map((p) => p.service).filter(Boolean))].sort();
  const mitreTechniqueIds = [...new Set(profiles.flatMap((p) => Array.isArray(p.mitreTechniqueIds) ? p.mitreTechniqueIds : []))].sort();
  const mitreTactics = [...new Set(profiles.flatMap((p) => Array.isArray(p.mitreTactics) ? p.mitreTactics : []))].sort();
  const tools = [...new Set(profiles.flatMap((p) => {
    const fromProfile = p.classification && Array.isArray(p.classification.tools) ? p.classification.tools : [];
    return fromProfile.filter((tool) => ALLOWED_TOOLS.includes(tool));
  }))].sort().slice(0, 10);
  const commandNames = [];
  for (const profile of profiles) {
    const names = Array.isArray(profile.commandNames) ? profile.commandNames : [];
    for (const name of names) {
      const token = String(name).trim().split(/\s+/)[0] || "";
      if (token && !commandNames.includes(token)) commandNames.push(token);
      if (commandNames.length >= 50) break;
    }
    if (commandNames.length >= 50) break;
  }
  let skillLevel = "unknown";
  for (const profile of profiles) {
    const skill = profile.classification ? profile.classification.skillLevel : "unknown";
    if (SKILL_ORDER.indexOf(skill) > SKILL_ORDER.indexOf(skillLevel)) skillLevel = skill;
  }
  const actorCounts = { bot: 0, human: 0, unknown: 0 };
  for (const profile of profiles) {
    const actor = profile.classification ? profile.classification.actorType : "unknown";
    if (actor === "bot" || actor === "human") actorCounts[actor] += 1;
    else actorCounts.unknown += 1;
  }
  let actorType = "unknown";
  if (actorCounts.bot > profiles.length / 2) actorType = "bot";
  else if (actorCounts.human > profiles.length / 2) actorType = "human";
  let intent = "unknown";
  let llmIntentMismatch = false;
  for (const profile of profiles) {
    const storedIntent = profile.classification ? profile.classification.intent : "unknown";
    const rulesIntent = typeof profile.rulesIntent === "string" ? profile.rulesIntent : storedIntent;
    if (typeof profile.rulesIntent === "string" && profile.rulesIntent !== storedIntent) llmIntentMismatch = true;
    if (INTENT_ORDER.indexOf(rulesIntent) > INTENT_ORDER.indexOf(intent)) intent = rulesIntent;
  }
  let confidence = 0;
  for (const profile of profiles) {
    const value = profile.classification && typeof profile.classification.confidence === "number" ? profile.classification.confidence : 0;
    if (value > confidence) confidence = value;
  }
  const firstSeen = profiles.map((p) => p.firstSeen).filter(Boolean).sort()[0] || new Date(0).toISOString();
  const lastSeen = profiles.map((p) => p.lastSeen).filter(Boolean).sort().pop() || new Date(0).toISOString();
  const crossService = services.length >= 2;
  const attacker = {
    attackerId: sourceIp,
    sourceIp,
    firstSeen,
    lastSeen,
    sessionCount: sessionIds.length,
    serviceCount: services.length,
    services,
    sessionIds: sessionIds.slice(0, 50),
    mitreTechniqueIds,
    mitreTactics,
    tools,
    commandNames,
    classification: { actorType, skillLevel, intent, confidence: Math.min(1, Math.max(0, confidence)), llmIntentMismatch },
    strategy: { name: "observe", reason: "default", crossService },
    updatedAt: new Date().toISOString(),
  };
  attacker.strategy = decideStrategy(attacker);
  return attacker;
}

const SKILL_ORDER_EXPORT = SKILL_ORDER;
const INTENT_ORDER_EXPORT = INTENT_ORDER;

/**
 * Merge an existing attacker document with a freshly correlated
 * one. Session and service lists are unioned, skill and intent
 * keep the highest, actor keeps only on agreement, confidence
 * keeps the maximum, and strategy is recomputed.
 *
 * @param {object} existing
 * @param {object} fresh
 * @returns {object}
 */
export function mergeAttacker(existing, fresh) {
  if (!existing || typeof existing !== "object") return fresh;
  const sessionIds = [...new Set([...(existing.sessionIds || []), ...(fresh.sessionIds || [])])].slice(0, 50);
  const services = [...new Set([...(existing.services || []), ...(fresh.services || [])])].sort();
  const mitreTechniqueIds = [...new Set([...(existing.mitreTechniqueIds || []), ...(fresh.mitreTechniqueIds || [])])].sort();
  const mitreTactics = [...new Set([...(existing.mitreTactics || []), ...(fresh.mitreTactics || [])])].sort();
  const tools = [...new Set([...(existing.tools || []), ...(fresh.tools || [])])].filter((tool) => ALLOWED_TOOLS.includes(tool)).sort().slice(0, 10);
  const commandNames = [...new Set([...(existing.commandNames || []), ...(fresh.commandNames || [])])].slice(0, 50);
  const existingClassification = existing.classification || {};
  const freshClassification = fresh.classification || {};
  let skillLevel = existingClassification.skillLevel || "unknown";
  if (SKILL_ORDER.indexOf(freshClassification.skillLevel) > SKILL_ORDER.indexOf(skillLevel)) skillLevel = freshClassification.skillLevel;
  let intent = existingClassification.intent || "unknown";
  if (INTENT_ORDER.indexOf(freshClassification.intent) > INTENT_ORDER.indexOf(intent)) intent = freshClassification.intent;
  const actorType = existingClassification.actorType === freshClassification.actorType ? existingClassification.actorType : "unknown";
  const confidence = Math.max(existingClassification.confidence || 0, freshClassification.confidence || 0);
  const merged = {
    attackerId: fresh.attackerId,
    sourceIp: fresh.sourceIp,
    firstSeen: [existing.firstSeen, fresh.firstSeen].filter(Boolean).sort()[0],
    lastSeen: [existing.lastSeen, fresh.lastSeen].filter(Boolean).sort().pop(),
    sessionCount: sessionIds.length,
    serviceCount: services.length,
    services,
    sessionIds,
    mitreTechniqueIds,
    mitreTactics,
    tools,
    commandNames,
    classification: { actorType, skillLevel, intent, confidence: Math.min(1, Math.max(0, confidence)), llmIntentMismatch: Boolean(existingClassification.llmIntentMismatch || freshClassification.llmIntentMismatch) },
    strategy: { name: "observe", reason: "default", crossService: services.length >= 2 },
    updatedAt: new Date().toISOString(),
  };
  merged.strategy = decideStrategy(merged);
  return merged;
}
