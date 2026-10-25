const API_BASE = "https://generativelanguage.googleapis.com/v1beta/models";
const SAFETY_CATEGORIES = [
  "HARM_CATEGORY_HARASSMENT",
  "HARM_CATEGORY_HATE_SPEECH",
  "HARM_CATEGORY_SEXUALLY_EXPLICIT",
  "HARM_CATEGORY_DANGEROUS_CONTENT",
];
const RESPONSE_SCHEMA = {
  type: "OBJECT",
  properties: {
    output: { type: "STRING" },
    exitCode: { type: "INTEGER" },
  },
  required: ["output", "exitCode"],
  propertyOrdering: ["output", "exitCode"],
};

function getHeader(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === "function") {
    return headers.get(name) || headers.get(name.toLowerCase()) || null;
  }
  return headers[name] || headers[name.toLowerCase()] || null;
}

function safeLog(log, level, fields, message) {
  try {
    if (log && typeof log[level] === "function") log[level](fields, message);
  } catch {
    /* Logging must never crash the client. */
  }
}

function stripKeyFromText(text, apiKey) {
  if (!apiKey || typeof text !== "string" || text === "") return text;
  return text.split(apiKey).join("[REDACTED]");
}

/**
 * Create a Gemini API client with per-model cooldown after 429.
 * Every generate call returns per-attempt diagnostics in
 * result.attempt. Errors are returned as data, never thrown, and
 * never contain the API key or request headers.
 *
 * @param {object} options
 * @param {string} options.apiKey
 * @param {(url: string, init: object) => Promise<object>} [options.fetchImpl]
 * @param {number} options.timeoutMs
 * @param {number} options.temperature
 * @param {number} options.thinkingBudget
 * @param {number} [options.maxOutputTokens]
 * @param {object} [options.logger]
 * @param {() => number} [options.now]
 * @returns {{ generate: (args: object) => Promise<object> }}
 */
export function createGeminiClient({ apiKey, fetchImpl, timeoutMs, temperature, thinkingBudget, maxOutputTokens, logger, now }) {
  const fetchFn = typeof fetchImpl === "function" ? fetchImpl : fetch;
  const clock = typeof now === "function" ? now : Date.now;
  const tokenCap = typeof maxOutputTokens === "number" ? maxOutputTokens : 2048;
  const cooldowns = new Map();

  function makeAttempt(model, status, finishReason, promptTokens, outputTokens, latencyMs, errorKind, rawText) {
    return {
      model,
      status: status === undefined ? null : status,
      finishReason: finishReason === undefined ? null : finishReason,
      promptTokens: promptTokens === undefined ? null : promptTokens,
      outputTokens: outputTokens === undefined ? null : outputTokens,
      latencyMs: Math.max(0, Math.floor(latencyMs)),
      errorKind: errorKind === undefined ? null : errorKind,
      rawPreview: rawText ? stripKeyFromText(rawText.slice(0, 200), apiKey) : "",
    };
  }

  async function generate({ model, system, user }) {
    const startMs = Date.now();
    try {
      const cooldownUntil = cooldowns.get(model);
      if (cooldownUntil && clock() < cooldownUntil) {
        const attempt = makeAttempt(model, 429, null, null, null, Date.now() - startMs, "cooldown", "");
        return { ok: false, status: 429, reason: "cooldown", attempt };
      }
      const generationConfig = {
        temperature,
        maxOutputTokens: tokenCap,
        responseMimeType: "application/json",
        responseSchema: RESPONSE_SCHEMA,
      };
      if (typeof model === "string" && model.startsWith("gemini-2.5")) {
        generationConfig.thinkingConfig = { thinkingBudget };
      }
      const body = {
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: "user", parts: [{ text: user }] }],
        generationConfig,
        safetySettings: SAFETY_CATEGORIES.map((category) => ({ category, threshold: "BLOCK_ONLY_HIGH" })),
      };
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let response;
      try {
        response = await fetchFn(`${API_BASE}/${encodeURIComponent(model)}:generateContent`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": apiKey,
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (error) {
        clearTimeout(timer);
        if (error && (error.name === "AbortError" || error.name === "TimeoutError")) {
          const attempt = makeAttempt(model, null, null, null, null, Date.now() - startMs, "timeout", "");
          return { ok: false, reason: "timeout", attempt };
        }
        safeLog(logger, "warn", { model }, "Gemini request failed");
        const attempt = makeAttempt(model, null, null, null, null, Date.now() - startMs, "network", "");
        return { ok: false, reason: "network", attempt };
      }
      clearTimeout(timer);
      if (!response.ok) {
        const status = response.status;
        if (status === 429) {
          const retryAfter = getHeader(response.headers, "Retry-After");
          let seconds = 60;
          if (retryAfter !== null && retryAfter !== undefined) {
            const parsed = Number.parseInt(String(retryAfter), 10);
            if (Number.isFinite(parsed) && parsed >= 0) seconds = Math.min(parsed, 300);
          }
          cooldowns.set(model, clock() + seconds * 1000);
          const attempt = makeAttempt(model, status, null, null, null, Date.now() - startMs, "rate_limit", "");
          return { ok: false, status, reason: "rate_limit", attempt };
        }
        if (status >= 500) {
          const attempt = makeAttempt(model, status, null, null, null, Date.now() - startMs, "server_error", "");
          return { ok: false, status, reason: "server_error", attempt };
        }
        const attempt = makeAttempt(model, status, null, null, null, Date.now() - startMs, "http_error", "");
        return { ok: false, status, reason: "http_error", attempt };
      }
      let data;
      try {
        data = await response.json();
      } catch {
        const attempt = makeAttempt(model, response.status, null, null, null, Date.now() - startMs, "bad_response", "");
        return { ok: false, reason: "bad_response", attempt };
      }
      const usage = data && data.usageMetadata ? data.usageMetadata : {};
      const promptTokens = typeof usage.promptTokenCount === "number" ? usage.promptTokenCount : null;
      const outputTokens = typeof usage.candidatesTokenCount === "number" ? usage.candidatesTokenCount : null;
      if (data && data.promptFeedback && data.promptFeedback.blockReason) {
        const attempt = makeAttempt(model, response.status, null, promptTokens, outputTokens, Date.now() - startMs, "blocked", "");
        return { ok: false, reason: "blocked", attempt };
      }
      const candidates = data && Array.isArray(data.candidates) ? data.candidates : [];
      if (candidates.length === 0) {
        const attempt = makeAttempt(model, response.status, null, promptTokens, outputTokens, Date.now() - startMs, "empty", "");
        return { ok: false, reason: "empty", attempt };
      }
      const first = candidates[0] || {};
      const finishReason = typeof first.finishReason === "string" ? first.finishReason : null;
      const parts = first.content && Array.isArray(first.content.parts) ? first.content.parts : [];
      if (parts.length === 0 || typeof parts[0].text !== "string") {
        const attempt = makeAttempt(model, response.status, finishReason, promptTokens, outputTokens, Date.now() - startMs, "empty", "");
        return { ok: false, reason: "empty", attempt };
      }
      const text = parts[0].text;
      if (finishReason === "MAX_TOKENS") {
        const attempt = makeAttempt(model, response.status, finishReason, promptTokens, outputTokens, Date.now() - startMs, "truncated", text);
        return { ok: false, status: response.status, reason: "truncated", attempt };
      }
      const attempt = makeAttempt(model, response.status, finishReason, promptTokens, outputTokens, Date.now() - startMs, null, text);
      return { ok: true, text, status: response.status, attempt };
    } catch {
      const attempt = makeAttempt(model, null, null, null, null, Date.now() - startMs, "network", "");
      return { ok: false, reason: "network", attempt };
    }
  }

  return { generate };
}
