import { z } from "zod";

const FORBIDDEN_KEYS = ["password", "token", "credential", "credentials", "rawQuery", "rawBody", "rawTarget", "summary"];

function hasForbiddenKey(value, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.includes(key)) return true;
    if (hasForbiddenKey(child, seen)) return true;
  }
  return false;
}

export const attackerSchema = z.object({
  attackerId: z.string().min(1),
  sourceIp: z.string().min(1),
  firstSeen: z.string().datetime({ offset: true }),
  lastSeen: z.string().datetime({ offset: true }),
  sessionCount: z.number().int().min(0),
  serviceCount: z.number().int().min(0),
  services: z.array(z.string()),
  sessionIds: z.array(z.string()).max(50),
  mitreTechniqueIds: z.array(z.string()),
  mitreTactics: z.array(z.string()),
  tools: z.array(z.string()).max(10),
  commandNames: z.array(z.string()).max(50),
  classification: z.object({
    actorType: z.enum(["bot", "human", "unknown"]),
    skillLevel: z.enum(["beginner", "intermediate", "advanced", "unknown"]),
    intent: z.enum(["recon", "credential_access", "exploitation", "persistence", "exfiltration", "unknown"]),
    confidence: z.number().min(0).max(1),
    llmIntentMismatch: z.boolean(),
  }),
  strategy: z.object({
    name: z.enum(["engage", "deceive", "contain", "observe"]),
    reason: z.string().min(1),
    crossService: z.boolean(),
  }),
  updatedAt: z.string().datetime({ offset: true }),
}).strict();

/**
 * Validate an attacker profile. Returns the parsed profile or
 * null, never throws. Any forbidden secret field rejects it.
 *
 * @param {unknown} value
 * @returns {object|null}
 */
export function validateAttacker(value) {
  try {
    if (hasForbiddenKey(value)) return null;
    const result = attackerSchema.safeParse(value);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}
