import { ALLOWED_TOOLS, TOOL_USER_AGENTS, TECHNIQUE_TACTICS, AUTH_ONLY_TECHNIQUES, SKILL_EXCLUDED_COMMANDS } from "./rules.js";

const BEGINNER_COMMANDS = new Set(["whoami", "ls", "pwd", "id"]);
const ADVANCED_TECHNIQUES = new Set(["T1190", "T1547", "T1027", "T1003", "T1105", "T1046"]);

function firstToken(command) {
  return String(command || "").trim().split(/\s+/)[0] || "";
}

function commandNamesFrom(commands) {
  const out = [];
  for (const command of Array.isArray(commands) ? commands : []) {
    const token = firstToken(command).toLowerCase();
    if (token && !out.includes(token)) out.push(token);
    if (out.length >= 20) break;
  }
  return out;
}

function detectTools(input) {
  const tools = [];
  const add = (tool) => { if (ALLOWED_TOOLS.includes(tool) && !tools.includes(tool)) tools.push(tool); };
  for (const name of input.commandNames || []) {
    add(name);
  }
  for (const agent of input.userAgents || []) {
    const lower = String(agent).toLowerCase();
    for (const entry of TOOL_USER_AGENTS) {
      if (lower.includes(entry.tool)) add(entry.tool);
    }
  }
  return tools.slice(0, 10);
}

function classifyActor(input) {
  const durationSec = input.durationMs > 0 ? input.durationMs / 1000 : 0;
  const authRate = durationSec > 0 ? input.authAttempts / durationSec : 0;
  const hasToolAgent = (input.userAgents || []).some((agent) => TOOL_USER_AGENTS.some((entry) => String(agent).toLowerCase().includes(entry.tool)));
  const avgTypingMs = input.totalKeystrokes > 0 ? input.totalTypingMs / input.totalKeystrokes : 0;
  const fastTyping = input.totalKeystrokes > 0 && avgTypingMs < 50;
  const slowTyping = input.totalKeystrokes > 0 && avgTypingMs > 200;
  if (hasToolAgent && (authRate > 0.5 || fastTyping)) return { actorType: "bot", confidence: 0.9 };
  if (hasToolAgent) return { actorType: "bot", confidence: 0.7 };
  if (authRate > 0.5) return { actorType: "bot", confidence: 0.7 };
  if (input.backspaceCount > 0 && slowTyping) return { actorType: "human", confidence: 0.7 };
  const uniqueRatio = input.commandCount > 0 ? (input.commandNames || []).length / input.commandCount : 0;
  if (input.commandCount >= 5 && uniqueRatio < 0.3) return { actorType: "bot", confidence: 0.5 };
  if (input.eventCount >= 20 && input.durationMs < 10000) return { actorType: "bot", confidence: 0.5 };
  if (input.commandCount >= 5 && uniqueRatio > 0.8) return { actorType: "human", confidence: 0.5 };
  return { actorType: "unknown", confidence: 0.3 };
}

function postAuthTechniques(input) {
  const techniques = (input.mitreTechniqueIds || []).filter((id) => !AUTH_ONLY_TECHNIQUES.includes(id));
  const tactics = [...new Set(techniques.map((id) => TECHNIQUE_TACTICS[id]).filter(Boolean))];
  return { techniques, tactics };
}

function classifySkill(input) {
  const { techniques } = postAuthTechniques(input);
  const techSet = new Set(techniques);
  const advancedCount = [...techSet].filter((t) => ADVANCED_TECHNIQUES.has(t)).length;
  if (techSet.has("T1190") || techSet.has("T1547") || techSet.has("T1027") || techSet.has("T1003") || advancedCount >= 3) return "advanced";
  const names = (input.commandNames || []).filter((n) => !SKILL_EXCLUDED_COMMANDS.includes(n));
  const hasIntermediate = names.some((n) => ["ps", "netstat", "wget", "curl"].includes(n)) || techSet.has("T1552.001") || (input.httpLoginAttempts || 0) > 0;
  if (hasIntermediate) return "intermediate";
  if (names.length > 0 && names.every((n) => BEGINNER_COMMANDS.has(n)) && [...techSet].every((id) => ["T1033", "T1083"].includes(id))) return "beginner";
  if (names.length > 0 && names.every((n) => BEGINNER_COMMANDS.has(n)) && techSet.size === 0) return "beginner";
  return "unknown";
}

function classifyIntent(input) {
  const { techniques, tactics } = postAuthTechniques(input);
  if (tactics.includes("Persistence")) return "persistence";
  if (tactics.includes("Credential Access")) return "credential_access";
  if (input.fileTransferOutSensitive) return "exfiltration";
  if (tactics.includes("Initial Access") || techniques.includes("T1105")) return "exploitation";
  if (tactics.includes("Discovery") || tactics.includes("Reconnaissance")) return "recon";
  return "unknown";
}

/**
 * Build a rules-only profile from a session summary. Never throws.
 *
 * @param {object} input
 * @returns {object}
 */
export function classifyProfile(input) {
  try {
    const safe = input && typeof input === "object" ? input : {};
    const commandNames = commandNamesFrom(safe.commands || safe.commandNames || []);
    const mitreTechniqueIds = [...new Set(Array.isArray(safe.mitreTechniqueIds) ? safe.mitreTechniqueIds : [])];
    const mitreTactics = [...new Set(Array.isArray(safe.mitreTactics) ? safe.mitreTactics : [])];
    const normalized = {
      ...safe,
      commandNames,
      mitreTechniqueIds,
      mitreTactics,
      userAgents: Array.isArray(safe.userAgents) ? safe.userAgents : [],
      totalTypingMs: typeof safe.totalTypingMs === "number" ? safe.totalTypingMs : 0,
      totalKeystrokes: typeof safe.totalKeystrokes === "number" ? safe.totalKeystrokes : 0,
      backspaceCount: typeof safe.backspaceCount === "number" ? safe.backspaceCount : 0,
      fileTransferOut: Boolean(safe.fileTransferOut),
      httpLoginAttempts: typeof safe.httpLoginAttempts === "number" ? safe.httpLoginAttempts : 0,
    };
    const actor = classifyActor(normalized);
    const skillLevel = classifySkill(normalized);
    const intent = classifyIntent(normalized);
    const tools = detectTools(normalized);
    const confidence = actor.confidence;
    return {
      sessionId: String(safe.sessionId || "unknown"),
      service: String(safe.service || "unknown"),
      nodeId: String(safe.nodeId || "unknown"),
      sourceIp: String(safe.sourceIp || "unknown"),
      firstSeen: safe.firstSeen || new Date(0).toISOString(),
      lastSeen: safe.lastSeen || new Date(0).toISOString(),
      durationMs: Math.max(0, Math.floor(safe.durationMs || 0)),
      closed: Boolean(safe.closed),
      eventCount: Math.max(0, Math.floor(safe.eventCount || 0)),
      commandCount: Math.max(0, Math.floor(safe.commandCount || 0)),
      authAttempts: Math.max(0, Math.floor(safe.authAttempts || 0)),
      authSuccess: Math.max(0, Math.floor(safe.authSuccess || 0)),
      commandNames,
      mitreTechniqueIds,
      mitreTactics,
      classification: { actorType: actor.actorType, skillLevel, intent, tools, confidence },
      llm: { used: false, cached: false, fallback: false, model: null, latencyMs: null },
      updatedAt: new Date().toISOString(),
    };
  } catch {
    return {
      sessionId: "unknown", service: "unknown", nodeId: "unknown", sourceIp: "unknown",
      firstSeen: new Date(0).toISOString(), lastSeen: new Date(0).toISOString(), durationMs: 0, closed: false,
      eventCount: 0, commandCount: 0, authAttempts: 0, authSuccess: 0, commandNames: [], mitreTechniqueIds: [], mitreTactics: [],
      classification: { actorType: "unknown", skillLevel: "unknown", intent: "unknown", tools: [], confidence: 0.3 },
      llm: { used: false, cached: false, fallback: false, model: null, latencyMs: null },
      updatedAt: new Date().toISOString(),
    };
  }
}
