const API_BASE = "https://generativelanguage.googleapis.com/v1beta/models";
const SAFETY_CATEGORIES = [
  "HARM_CATEGORY_HARASSMENT",
  "HARM_CATEGORY_HATE_SPEECH",
  "HARM_CATEGORY_SEXUALLY_EXPLICIT",
  "HARM_CATEGORY_DANGEROUS_CONTENT",
];

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

/**
 * Create a Gemini API client with per-model cooldown after 429.
 * Errors are returned as data, never thrown, and never contain
 * the API key or request headers.
 *
 * @param {object} options
 * @param {string} options.apiKey
 * @param {(url: string, init: object) => Promise<object>} [options.fetchImpl]
 * @param {number} options.timeoutMs
 * @param {number} options.temperature
 * @param {number} options.thinkingBudget
 * @param {object} [options.logger]
 * @param {() => number} [options.now]
 * @returns {{ generate: (args: object) => Promise<object> }}
 */
export function createGeminiClient({ apiKey, fetchImpl, timeoutMs, temperature, thinkingBudget, logger, now }) {
  const fetchFn = typeof fetchImpl === "function" ? fetchImpl : fetch;
  const clock = typeof now === "function" ? now : Date.now;
  const cooldowns = new Map();

  async function generate({ model, system, user }) {
    try {
      const cooldownUntil = cooldowns.get(model);
      if (cooldownUntil && clock() < cooldownUntil) {
        return { ok: false, status: 429, reason: "cooldown" };
      }
      const generationConfig = {
        temperature,
        maxOutputTokens: 1024,
        responseMimeType: "application/json",
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
          return { ok: false, reason: "timeout" };
        }
        safeLog(logger, "warn", { model }, "Gemini request failed");
        return { ok: false, reason: "network" };
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
          return { ok: false, status, reason: "rate_limit" };
        }
        if (status >= 500) return { ok: false, status, reason: "server_error" };
        return { ok: false, status, reason: "http_error" };
      }
      let data;
      try {
        data = await response.json();
      } catch {
        return { ok: false, reason: "bad_response" };
      }
      if (data && data.promptFeedback && data.promptFeedback.blockReason) {
        return { ok: false, reason: "blocked" };
      }
      const candidates = data && Array.isArray(data.candidates) ? data.candidates : [];
      if (candidates.length === 0) return { ok: false, reason: "empty" };
      const parts = candidates[0] && candidates[0].content && Array.isArray(candidates[0].content.parts) ? candidates[0].content.parts : [];
      if (parts.length === 0 || typeof parts[0].text !== "string") return { ok: false, reason: "empty" };
      return { ok: true, text: parts[0].text };
    } catch {
      return { ok: false, reason: "network" };
    }
  }

  return { generate };
}
