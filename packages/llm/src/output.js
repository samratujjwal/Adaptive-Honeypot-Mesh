import { z } from "zod";

const outputSchema = z.object({
  output: z.string(),
  exitCode: z.number().int().min(0).max(255),
}).passthrough();

const DISCLOSURE = /(as an ai|language model|i am an ai|i'm an ai|honeypot|i cannot (assist|help|comply|fulfill)|i can't (assist|help|comply))/i;

const SECRET_PATTERN = /(AIza[0-9A-Za-z\-_]{20,}|GEMINI_API_KEY\s*[:=]|sk-[A-Za-z0-9]{16,}|api[_-]?key\s*[:=]\s*\S{8,})/i;
const REAL_PATH_PATTERN = /(\/home\/hatch|\/Users\/|\/private\/|C:\\Users|C:\\Windows|D:\\Samrat|Samrat-Ujjwal)/;
const REAL_COMMAND_PATTERN = /((run|execute) (this|that|the following) command on (your )?real (system|machine|computer)|paste (this|it) into your terminal|curl\s+\S+\s*\|\s*(bash|sh)\b)/i;

export function validateOutputText(text, options = {}) {
  if (typeof text !== "string") return { ok: false, reason: "malformed" };
  if (text.length > 32768) return { ok: false, reason: "too_long" };
  if (SECRET_PATTERN.test(text)) return { ok: false, reason: "secret" };
  if (REAL_PATH_PATTERN.test(text)) return { ok: false, reason: "real_path" };
  if (REAL_COMMAND_PATTERN.test(text)) return { ok: false, reason: "instruction" };
  const systemPrompt = options.systemPrompt;
  if (typeof systemPrompt === "string" && systemPrompt.length > 0) {
    const normalized = text.replace(/\s+/g, " ");
    for (const line of systemPrompt.split("\n")) {
      const clean = line.replace(/\s+/g, " ").trim();
      if (clean.length >= 40 && normalized.includes(clean)) return { ok: false, reason: "system_prompt_echo" };
    }
  }
  return { ok: true, reason: null };
}

function extractJson(text) {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    /* Fall through to fence and brace extraction. */
  }
  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) {
    try {
      return JSON.parse(fenceMatch[1].trim());
    } catch {
      /* Fall through to brace extraction. */
    }
  }
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start >= 0 && end > start) {
    try {
      return JSON.parse(trimmed.slice(start, end + 1));
    } catch {
      /* Rejected below. */
    }
  }
  return null;
}

function sanitize(output, maxChars) {
  let cleaned = output.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  cleaned = cleaned.replace(/\u001b\[[0-9;?]*[a-zA-Z]/g, "");
  cleaned = cleaned.replace(/\u001b\][^\u0007]*\u0007/g, "");
  cleaned = cleaned.replace(/\u001b./g, "");
  cleaned = cleaned.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
  if (typeof maxChars === "number") cleaned = cleaned.slice(0, maxChars);
  const lines = cleaned.split("\n");
  if (lines.length > 80) cleaned = lines.slice(0, 80).join("\n");
  return cleaned;
}

/**
 * Parse model output text into a terminal result. Never throws;
 * failures are returned as { ok: false, reason }.
 *
 * @param {string} text
 * @param {object} [options]
 * @param {number} [options.maxChars]
 * @returns {{ ok: true, output: string, exitCode: number } | { ok: false, reason: string }}
 */
export function parseModelOutput(text, options = {}) {
  try {
    if (typeof text !== "string") return { ok: false, reason: "malformed_json" };
    const parsed = extractJson(text);
    if (parsed === null || typeof parsed !== "object") return { ok: false, reason: "malformed_json" };
    const result = outputSchema.safeParse(parsed);
    if (!result.success) return { ok: false, reason: "schema" };
    if (DISCLOSURE.test(result.data.output)) return { ok: false, reason: "disclosure" };
    const validation = validateOutputText(result.data.output, { systemPrompt: options.systemPrompt });
    if (!validation.ok) return { ok: false, reason: validation.reason };
    const output = sanitize(result.data.output, options.maxChars);
    return { ok: true, output, exitCode: result.data.exitCode };
  } catch {
    return { ok: false, reason: "malformed_json" };
  }
}
