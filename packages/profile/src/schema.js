import { z } from "zod";

export const profileSchema = z.object({
  sessionId: z.string().min(1),
  service: z.string().min(1),
  nodeId: z.string().min(1),
  sourceIp: z.string().min(1),
  firstSeen: z.string().datetime({ offset: true }),
  lastSeen: z.string().datetime({ offset: true }),
  durationMs: z.number().int().min(0),
  closed: z.boolean(),
  eventCount: z.number().int().min(0),
  commandCount: z.number().int().min(0),
  authAttempts: z.number().int().min(0),
  authSuccess: z.number().int().min(0),
  commandNames: z.array(z.string()).max(20),
  mitreTechniqueIds: z.array(z.string()),
  mitreTactics: z.array(z.string()),
  classification: z.object({
    actorType: z.enum(["bot", "human", "unknown"]),
    skillLevel: z.enum(["beginner", "intermediate", "advanced", "unknown"]),
    intent: z.enum(["recon", "credential_access", "exploitation", "persistence", "exfiltration", "unknown"]),
    tools: z.array(z.string()).max(10),
    confidence: z.number().min(0).max(1),
  }),
  llm: z.object({
    used: z.boolean(),
    cached: z.boolean(),
    fallback: z.boolean(),
    model: z.string().nullable(),
    latencyMs: z.number().nullable(),
  }),
  updatedAt: z.string().datetime({ offset: true }),
});

/**
 * Validate a profile. Returns the parsed profile or null.
 *
 * @param {unknown} value
 * @returns {object|null}
 */
export function validateProfile(value) {
  try {
    const result = profileSchema.safeParse(value);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}
