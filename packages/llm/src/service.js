import { makePersona } from "./persona.js";
import { buildSystemPrompt, buildUserMessage } from "./prompt.js";
import { parseModelOutput } from "./output.js";
import { createCache, isTimeDependent, makeKey } from "./cache.js";
import { createLimiter } from "./limiter.js";
import { createGeminiClient } from "./gemini.js";
import { staticRespond } from "./static.js";

function noOpLogger() {
  return { info: () => {}, warn: () => {}, error: () => {} };
}

function stripKey(text, apiKey) {
  if (!apiKey || typeof text !== "string") return text;
  return text.split(apiKey).join("[REDACTED]");
}

/**
 * Convert service meta into the object for an event "llm" field.
 * The result passes validateEvent when embedded in an event.
 *
 * @param {object} meta
 * @returns {{ used: boolean, cached: boolean, fallback: boolean, latencyMs: number, model: string }}
 */
export function toEventLlm(meta) {
  const source = meta && meta.source ? meta.source : "static";
  return {
    used: source === "llm" || source === "cache",
    cached: Boolean(meta && meta.cached),
    fallback: Boolean(meta && meta.fallback),
    latencyMs: typeof meta && typeof meta.latencyMs === "number" && meta.latencyMs >= 0 ? Math.floor(meta.latencyMs) : 0,
    model: meta && meta.model ? meta.model : "static",
  };
}

/**
 * Create the LLM service. Never throws or rejects; always resolves
 * with a usable answer.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {object} [options.logger]
 * @param {(url: string, init: object) => Promise<object>} [options.fetchImpl]
 * @param {() => number} [options.now]
 * @returns {{ respond: (args: object) => Promise<object>, toEventLlm: typeof toEventLlm }}
 */
export function createLlmService({ config, logger, fetchImpl, now }) {
  const log = logger || noOpLogger();
  const cache = createCache({ max: config.LLM_CACHE_MAX, ttlMs: config.LLM_CACHE_TTL_MS, now });
  const limiter = createLimiter({
    rpm: config.LLM_RPM,
    dailyLimit: config.LLM_DAILY_LIMIT,
    sessionLimit: config.LLM_SESSION_LIMIT,
    now,
    usageFile: config.LLM_USAGE_FILE,
    logger: log,
  });
  const client = createGeminiClient({
    apiKey: config.GEMINI_API_KEY || "",
    fetchImpl,
    timeoutMs: config.LLM_TIMEOUT_MS,
    temperature: config.LLM_TEMPERATURE,
    thinkingBudget: config.GEMINI_THINKING_BUDGET,
    logger: log,
    now,
  });

  async function respond({ command, ctx }) {
    const startMs = Date.now();
    const safeCtx = ctx || {};
    const user = safeCtx.user || "root";
    const cwd = safeCtx.cwd || "/root";
    const hostname = safeCtx.hostname || config.HONEYPOT_HOSTNAME;
    const sessionId = safeCtx.sessionId || "unknown";
    const persona = makePersona(hostname);
    const trimmedCommand = String(command || "").trim();
    function finish(output, exitCode, meta) {
      const latencyMs = Math.max(0, Date.now() - startMs);
      return { output, exitCode, meta: { ...meta, latencyMs } };
    }
    try {
      if (config.LLM_MODE === "mock") {
        const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
        return finish(staticResult.output, staticResult.exitCode, {
          source: "mock",
          model: "static",
          cached: false,
          fallback: false,
          reason: null,
        });
      }
      const timeDependent = isTimeDependent(trimmedCommand);
      const key = makeKey({ personaId: persona.id, hostname, user, cwd, command: trimmedCommand });
      if (!timeDependent) {
        const cached = cache.get(key);
        if (cached) {
          return finish(cached.output, cached.exitCode, {
            source: "cache",
            model: cached.model || "static",
            cached: true,
            fallback: Boolean(cached.fallback),
            reason: null,
          });
        }
      }
      const system = buildSystemPrompt(persona, { user, cwd });
      const userMessage = buildUserMessage(trimmedCommand);
      const primaryAcquire = limiter.tryAcquire(sessionId);
      if (!primaryAcquire.ok) {
        const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
        return finish(staticResult.output, staticResult.exitCode, {
          source: "static",
          model: "static",
          cached: false,
          fallback: false,
          reason: `rate:${primaryAcquire.reason}`,
        });
      }
      const primary = await client.generate({ model: config.GEMINI_MODEL, system, user: userMessage });
      if (primary.ok) {
        const parsed = parseModelOutput(primary.text, { maxChars: config.LLM_MAX_OUTPUT_CHARS });
        if (parsed.ok) {
          if (!timeDependent) {
            cache.set(key, { output: parsed.output, exitCode: parsed.exitCode, model: config.GEMINI_MODEL, fallback: false });
          }
          return finish(parsed.output, parsed.exitCode, {
            source: "llm",
            model: config.GEMINI_MODEL,
            cached: false,
            fallback: false,
            reason: null,
          });
        }
        const fallbackAcquire = limiter.tryAcquire(sessionId);
        if (!fallbackAcquire.ok) {
          const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
          return finish(staticResult.output, staticResult.exitCode, {
            source: "static",
            model: "static",
            cached: false,
            fallback: false,
            reason: `rate:${fallbackAcquire.reason}`,
          });
        }
        const fallbackResult = await client.generate({ model: config.GEMINI_FALLBACK_MODEL, system, user: userMessage });
        if (fallbackResult.ok) {
          const fallbackParsed = parseModelOutput(fallbackResult.text, { maxChars: config.LLM_MAX_OUTPUT_CHARS });
          if (fallbackParsed.ok) {
            if (!timeDependent) {
              cache.set(key, { output: fallbackParsed.output, exitCode: fallbackParsed.exitCode, model: config.GEMINI_FALLBACK_MODEL, fallback: true });
            }
            return finish(fallbackParsed.output, fallbackParsed.exitCode, {
              source: "llm",
              model: config.GEMINI_FALLBACK_MODEL,
              cached: false,
              fallback: true,
              reason: null,
            });
          }
          const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
          return finish(staticResult.output, staticResult.exitCode, {
            source: "static",
            model: "static",
            cached: false,
            fallback: false,
            reason: `llm_failed:${parsed.reason}:${fallbackParsed.reason}`,
          });
        }
        const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
        return finish(staticResult.output, staticResult.exitCode, {
          source: "static",
          model: "static",
          cached: false,
          fallback: false,
          reason: `llm_failed:${parsed.reason}:${fallbackResult.reason || "error"}`,
        });
      }
      const fallbackAcquire = limiter.tryAcquire(sessionId);
      if (!fallbackAcquire.ok) {
        const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
        return finish(staticResult.output, staticResult.exitCode, {
          source: "static",
          model: "static",
          cached: false,
          fallback: false,
          reason: `rate:${fallbackAcquire.reason}`,
        });
      }
      const fallbackResult = await client.generate({ model: config.GEMINI_FALLBACK_MODEL, system, user: userMessage });
      if (fallbackResult.ok) {
        const fallbackParsed = parseModelOutput(fallbackResult.text, { maxChars: config.LLM_MAX_OUTPUT_CHARS });
        if (fallbackParsed.ok) {
          if (!timeDependent) {
            cache.set(key, { output: fallbackParsed.output, exitCode: fallbackParsed.exitCode, model: config.GEMINI_FALLBACK_MODEL, fallback: true });
          }
          return finish(fallbackParsed.output, fallbackParsed.exitCode, {
            source: "llm",
            model: config.GEMINI_FALLBACK_MODEL,
            cached: false,
            fallback: true,
            reason: null,
          });
        }
        const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
        return finish(staticResult.output, staticResult.exitCode, {
          source: "static",
          model: "static",
          cached: false,
          fallback: false,
          reason: `llm_failed:${primary.reason || "error"}:${fallbackParsed.reason}`,
        });
      }
      const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
      return finish(staticResult.output, staticResult.exitCode, {
        source: "static",
        model: "static",
        cached: false,
        fallback: false,
        reason: `llm_failed:${primary.reason || "error"}:${fallbackResult.reason || "error"}`,
      });
    } catch (error) {
      try {
        const safeReason = stripKey(error && error.message ? "internal_error" : "internal_error", config.GEMINI_API_KEY);
        const staticResult = staticRespond(trimmedCommand, { user, cwd, hostname });
        return finish(staticResult.output, staticResult.exitCode, {
          source: "static",
          model: "static",
          cached: false,
          fallback: false,
          reason: safeReason,
        });
      } catch {
        return finish("", 127, {
          source: "static",
          model: "static",
          cached: false,
          fallback: false,
          reason: "internal_error",
        });
      }
    }
  }

  return { respond, toEventLlm };
}
