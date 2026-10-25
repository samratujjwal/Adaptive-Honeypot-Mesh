import { z } from "zod";

const outputSchema = z.object({
  output: z.string(),
  exitCode: z.number().int().min(0).max(255),
}).passthrough();

const DISCLOSURE = /(as an ai|language model|i am an ai|i'm an ai|honeypot|i cannot (assist|help|comply|fulfill)|i can't (assist|help|comply))/i;

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
    const output = sanitize(result.data.output, options.maxChars);
    return { ok: true, output, exitCode: result.data.exitCode };
  } catch {
    return { ok: false, reason: "malformed_json" };
  }
}
