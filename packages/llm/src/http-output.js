const STATUS_ALLOWLIST = new Set([200, 301, 302, 400, 401, 403, 404, 500]);
const CONTENT_TYPE_ALLOWLIST = new Set([
  "text/html; charset=UTF-8",
  "application/json",
  "text/plain",
  "text/xml",
]);
const DISCLOSURE = /(as an ai|language model|i am an ai|i'm an ai|honeypot|i cannot (assist|help|comply|fulfill)|i can't (assist|help|comply))/i;

function stripControl(text) {
  let out = "";
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if ((code < 0x20 && ch !== "\n" && ch !== "\r" && ch !== "\t") || code === 0x7f) continue;
    out += ch;
  }
  return out;
}

function parseJsonText(text) {
  const trimmed = String(text || "").trim();
  if (trimmed === "") return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenced) {
      try {
        return JSON.parse(fenced[1].trim());
      } catch {
        return null;
      }
    }
    return null;
  }
}

/**
 * Parse and validate a model HTTP page. Never throws.
 *
 * @param {string} text
 * @returns {{ ok: boolean, status?: number, contentType?: string, body?: string, reason?: string }}
 */
export function parseHttpOutput(text) {
  try {
    const parsed = parseJsonText(text);
    if (!parsed || typeof parsed !== "object") return { ok: false, reason: "bad_json" };
    if (!STATUS_ALLOWLIST.has(parsed.status)) return { ok: false, reason: "bad_status" };
    if (!CONTENT_TYPE_ALLOWLIST.has(parsed.contentType)) return { ok: false, reason: "bad_content_type" };
    if (typeof parsed.body !== "string") return { ok: false, reason: "bad_body" };
    if (DISCLOSURE.test(parsed.body)) return { ok: false, reason: "disclosure" };
    const cleaned = stripControl(parsed.body);
    const bytes = Buffer.byteLength(cleaned, "utf8");
    const body = bytes > 32768 ? Buffer.from(cleaned, "utf8").subarray(0, 32768).toString("utf8") : cleaned;
    return { ok: true, status: parsed.status, contentType: parsed.contentType, body };
  } catch {
    return { ok: false, reason: "bad_json" };
  }
}
