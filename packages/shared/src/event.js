import { v4 as uuidv4 } from "uuid";
import { z } from "zod";

export const MAX_PAYLOAD_BYTES = 65536;

export const eventSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.string().datetime({ offset: true }),
  honeypot: z.object({
    service: z.enum(["ssh", "http", "ftp"]),
    nodeId: z.string().min(1),
  }),
  sessionId: z.string().min(1).max(128),
  source: z.object({
    ip: z.union([z.string().ipv4().max(45), z.string().ipv6().max(45)]),
    port: z.number().int().min(0).max(65535),
  }),
  eventType: z.enum([
    "connection_open",
    "auth_attempt",
    "command",
    "http_request",
    "ftp_command",
    "file_transfer",
    "llm_response",
    "connection_close",
  ]),
  payload: z.object({}).passthrough(),
  llm: z
    .object({
      used: z.boolean(),
      cached: z.boolean(),
      fallback: z.boolean(),
      latencyMs: z.number().min(0),
      model: z.string().min(1),
    })
    .optional(),
  mitre: z
    .array(
      z.object({
        techniqueId: z.string().min(1),
        tactic: z.string().min(1),
        confidence: z.number().min(0).max(1),
      }),
    )
    .optional(),
}).superRefine((value, ctx) => {
  if (value.payload !== undefined) {
    const serialized = JSON.stringify(value.payload);
    if (serialized !== undefined && Buffer.byteLength(serialized, "utf8") > MAX_PAYLOAD_BYTES) {
      ctx.addIssue({
        code: "custom",
        path: ["payload"],
        message: `payload exceeds ${MAX_PAYLOAD_BYTES} bytes`,
      });
    }
  }
});

/**
 * Build a valid event, filling in id and timestamp when the caller
 * does not supply them. Throws a ZodError on invalid input.
 *
 * @param {Record<string, unknown>} partial
 * @returns {z.infer<typeof eventSchema>}
 */
export function createEvent(partial) {
  const candidate = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    ...partial,
  };
  return eventSchema.parse(candidate);
}

/**
 * Validate an event object without throwing.
 *
 * @param {unknown} obj
 * @returns {{ ok: true, data: z.infer<typeof eventSchema> } | { ok: false, errors: Array<{ path: string, message: string }> }}
 */
export function validateEvent(obj) {
  const result = eventSchema.safeParse(obj);
  if (result.success) {
    return { ok: true, data: result.data };
  }
  return {
    ok: false,
    errors: result.error.issues.map((issue) => ({
      path: issue.path.join("."),
      message: issue.message,
    })),
  };
}
