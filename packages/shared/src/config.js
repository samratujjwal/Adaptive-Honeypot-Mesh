import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

const configSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).default("info"),
    SSH_PORT: z.coerce.number().int().min(1).max(65535).default(2222),
    HTTP_PORT: z.coerce.number().int().min(1).max(65535).default(8080),
    FTP_PORT: z.coerce.number().int().min(1).max(65535).default(2121),
    BIND_HOST: z.string().ip().default("127.0.0.1"),
    LLM_MODE: z.enum(["mock", "real"]).default("mock"),
    GEMINI_API_KEY: z.string().optional(),
    GEMINI_MODEL: z.string().min(1).default("gemini-2.5-flash"),
    KAFKA_BROKERS: z.string().min(1).default("localhost:9092"),
    ELASTICSEARCH_URL: z.string().url().default("http://localhost:9200"),
    NODE_ID: z.string().min(1).default("node-01"),
  })
  .superRefine((value, ctx) => {
    if (value.LLM_MODE === "real" && (!value.GEMINI_API_KEY || value.GEMINI_API_KEY.trim() === "")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["GEMINI_API_KEY"],
        message: "GEMINI_API_KEY is required when LLM_MODE is 'real'",
      });
    }
  });

/**
 * Validate a raw environment object and return the typed config.
 * Throws one Error listing every bad field, so a bad setup fails
 * loudly at startup instead of halfway through a run.
 *
 * @param {Record<string, string | undefined>} env
 * @returns {z.infer<typeof configSchema>}
 */
export function loadConfig(env = process.env) {
  const result = configSchema.safeParse(env);
  if (!result.success) {
    const lines = result.error.issues.map((issue) => {
      const field = issue.path.length > 0 ? issue.path.join(".") : "(config)";
      return `- ${field}: ${issue.message}`;
    });
    throw new Error(`Invalid configuration:\n${lines.join("\n")}`);
  }
  return result.data;
}

export const config = loadConfig();
export { configSchema };
