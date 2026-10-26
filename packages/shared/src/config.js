import dotenv from "dotenv";
import { z } from "zod";

try {
  dotenv.config();
} catch {
  /* A missing or unreadable .env must not crash config loading. */
}

const configSchema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).default("info"),
    SSH_PORT: z.coerce.number().int().min(1).max(65535).default(2222),
    HTTP_PORT: z.coerce.number().int().min(1).max(65535).default(8080),
    HTTP_SERVER_HEADER: z.string().min(1).default("nginx/1.18.0 (Ubuntu)"),
    HTTP_MAX_BODY_BYTES: z.coerce.number().int().min(1).default(65536),
    HTTP_MAX_CONNECTIONS: z.coerce.number().int().min(1).default(200),
    HTTP_MAX_CONNECTIONS_PER_IP: z.coerce.number().int().min(1).default(20),
    HTTP_MAX_REQ_PER_MIN_PER_IP: z.coerce.number().int().min(1).default(300),
    HTTP_REQUEST_TIMEOUT_MS: z.coerce.number().int().min(1).default(10000),
    HTTP_LLM_ENABLED: z.union([z.boolean(), z.enum(["true", "false"])]).transform((value) => value === true || value === "true").default(true),
    HTTP_LLM_DEADLINE_MS: z.coerce.number().int().min(1).default(5000),
    HTTP_SESSION_WINDOW_MS: z.coerce.number().int().min(1).default(1800000),
    FTP_PORT: z.coerce.number().int().min(1).max(65535).default(2121),
    FTP_BANNER: z.string().min(1).default("(vsFTPd 3.0.5)"),
    FTP_MAX_CONNECTIONS: z.coerce.number().int().min(1).default(50),
    FTP_MAX_CONNECTIONS_PER_IP: z.coerce.number().int().min(1).default(5),
    FTP_MAX_AUTH_ATTEMPTS: z.coerce.number().int().min(1).default(5),
    FTP_AUTH_FAIL_DELAY_MS: z.coerce.number().int().min(0).default(1000),
    FTP_IDLE_TIMEOUT_MS: z.coerce.number().int().min(1).default(60000),
    FTP_MAX_SESSION_MS: z.coerce.number().int().min(1).default(600000),
    FTP_MAX_LINE: z.coerce.number().int().min(1).default(512),
    FTP_MAX_CMDS_PER_MIN: z.coerce.number().int().min(1).default(120),
    FTP_PASV_MIN_PORT: z.coerce.number().int().min(1).max(65535).default(40000),
    FTP_PASV_MAX_PORT: z.coerce.number().int().min(1).max(65535).default(40100),
    FTP_PASV_ADDRESS: z.string().ipv4().default("127.0.0.1"),
    FTP_DATA_TIMEOUT_MS: z.coerce.number().int().min(1).default(10000),
    FTP_MAX_UPLOAD_BYTES: z.coerce.number().int().min(1).default(1048576),
    FTP_MAX_SESSION_BYTES: z.coerce.number().int().min(1).default(2097152),
    FTP_MAX_NODES: z.coerce.number().int().min(1).default(500),
    BIND_HOST: z.union([z.string().ipv4(), z.string().ipv6()]).default("127.0.0.1"),
    SSH_IDLE_TIMEOUT_MS: z.coerce.number().int().min(0).default(120000),
    SSH_MAX_SESSION_MS: z.coerce.number().int().min(0).default(600000),
    SSH_MAX_CONNECTIONS: z.coerce.number().int().min(1).default(50),
    SSH_MAX_CONNECTIONS_PER_IP: z.coerce.number().int().min(1).default(5),
    SSH_MAX_AUTH_ATTEMPTS: z.coerce.number().int().min(1).default(6),
    SSH_LLM_DEADLINE_MS: z.coerce.number().int().min(1).default(8000),
    SSH_MAX_FILE_BYTES: z.coerce.number().int().min(1).default(65536),
    SSH_MAX_NODES: z.coerce.number().int().min(1).default(2000),
    SSH_MAX_PENDING_INPUT: z.coerce.number().int().min(1).default(4096),
    HONEYPOT_STATIC_FIRST: z.union([z.boolean(), z.enum(["true", "false"])]).transform((value) => value === true || value === "true").default(true),
    SSH_IDENT: z.string().min(1).default("OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"),
    HONEYPOT_HOSTNAME: z.string().min(1).default("srv-web-01"),
    PERSONA_SEED: z.string().min(8).max(64).default("change-me-default-seed"),
    HONEYPOT_DOMAIN: z.string().min(1).optional(),
    HONEYTOKENS_ENABLED: z.union([z.boolean(), z.enum(["true", "false"])]).transform((value) => value === true || value === "true").default(true),
    ALLOW_PUBLIC_BIND: z
      .union([z.boolean(), z.enum(["true", "false"])])
      .transform((value) => value === true || value === "true")
      .default(false),
    EVENT_DIR: z.string().min(1).default("data/events"),
    SSH_HOST_KEY_PATH: z.string().min(1).default("data/ssh/host_ed25519"),
    LLM_MODE: z.enum(["mock", "real"]).default("mock"),
    GEMINI_API_KEY: z.string().optional(),
    GEMINI_MODEL: z.string().min(1).default("gemini-2.5-flash-lite"),
    GEMINI_FALLBACK_MODEL: z.string().min(1).default("gemini-2.5-flash"),
    LLM_TIMEOUT_MS: z.coerce.number().int().min(1).default(8000),
    LLM_RPM: z.coerce.number().int().min(1).default(8),
    LLM_DAILY_LIMIT: z.coerce.number().int().min(1).default(400),
    LLM_SESSION_LIMIT: z.coerce.number().int().min(1).default(40),
    LLM_CACHE_MAX: z.coerce.number().int().min(1).default(500),
    LLM_CACHE_TTL_MS: z.coerce.number().int().min(1).default(3600000),
    LLM_MAX_OUTPUT_CHARS: z.coerce.number().int().min(1).default(4000),
    LLM_MAX_OUTPUT_TOKENS: z.coerce.number().int().min(1).default(2048),
    LLM_TEMPERATURE: z.coerce.number().min(0).max(1).default(0.4),
    GEMINI_THINKING_BUDGET: z.coerce.number().int().min(0).default(0),
    LLM_USAGE_FILE: z.string().min(1).default("data/llm-usage.json"),
    KAFKA_ENABLED: z.union([z.boolean(), z.enum(["true", "false"])]).transform((value) => value === true || value === "true").default(false),
    KAFKA_BROKERS: z.string().min(1).default("localhost:9092"),
    KAFKA_TOPIC: z.string().min(1).refine((value) => !value.includes(" "), "KAFKA_TOPIC must not contain spaces").default("honeypot.events"),
    KAFKA_CLIENT_ID_PREFIX: z.string().min(1).default("honeypot"),
    KAFKA_BUFFER_MAX: z.coerce.number().int().positive().default(5000),
    KAFKA_BATCH_MAX: z.coerce.number().int().positive().default(200),
    KAFKA_FLUSH_MS: z.coerce.number().int().positive().default(500),
    KAFKA_SEND_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),
    KAFKA_SHUTDOWN_FLUSH_MS: z.coerce.number().int().positive().default(3000),
    KAFKA_MAX_MESSAGE_BYTES: z.coerce.number().int().positive().default(262144),
    ELASTICSEARCH_URL: z.string().url().default("http://localhost:9200"),
    NODE_ID: z.string().min(1).default("node-01"),
  })
  .superRefine((value, ctx) => {
    if (value.LLM_MODE === "real" && (!value.GEMINI_API_KEY || value.GEMINI_API_KEY.trim() === "")) {
      ctx.addIssue({
        code: "custom",
        path: ["GEMINI_API_KEY"],
        message: "GEMINI_API_KEY is required when LLM_MODE is 'real'",
      });
    }
    if (value.SSH_LLM_DEADLINE_MS >= value.SSH_IDLE_TIMEOUT_MS) {
      ctx.addIssue({ code: "custom", path: ["SSH_LLM_DEADLINE_MS"], message: "SSH_LLM_DEADLINE_MS must be less than SSH_IDLE_TIMEOUT_MS" });
    }
    if (value.FTP_PASV_MIN_PORT > value.FTP_PASV_MAX_PORT) {
      ctx.addIssue({ code: "custom", path: ["FTP_PASV_MIN_PORT"], message: "FTP_PASV_MIN_PORT must be less than or equal to FTP_PASV_MAX_PORT" });
    }
    for (const item of String(value.KAFKA_BROKERS).split(",")) {
      const trimmed = item.trim();
      if (!/^[^: \s]+:\d+$/.test(trimmed)) {
        ctx.addIssue({ code: "custom", path: ["KAFKA_BROKERS"], message: "KAFKA_BROKERS must be a comma separated list of host:port" });
        break;
      }
    }
    if ((value.BIND_HOST === "0.0.0.0" || value.BIND_HOST === "::") && !value.ALLOW_PUBLIC_BIND) {
      ctx.addIssue({
        code: "custom",
        path: ["BIND_HOST"],
        message: "BIND_HOST is public (0.0.0.0 or ::) but ALLOW_PUBLIC_BIND is not true",
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
