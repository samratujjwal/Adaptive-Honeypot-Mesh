const ALLOWED_HEADERS = new Set([
  "host",
  "user-agent",
  "accept",
  "accept-language",
  "content-type",
  "content-length",
  "referer",
  "cookie",
  "authorization",
  "x-forwarded-for",
  "x-real-ip",
  "connection",
]);

/**
 * Filter headers to the allowlist, capping each value at 512 chars.
 *
 * @param {object} headers
 * @returns {object} allowlisted headers
 */
export function filterHeaders(headers) {
  const out = {};
  const source = headers || {};
  for (const name of Object.keys(source)) {
    const lower = name.toLowerCase();
    if (ALLOWED_HEADERS.has(lower)) {
      out[lower] = String(source[name]).slice(0, 512);
    }
  }
  return out;
}

/**
 * Build an http_request event payload.
 *
 * @param {object} fields
 * @returns {object} payload
 */
export function buildHttpPayload(fields) {
  const payload = {
    method: fields.method,
    path: String(fields.path || "").slice(0, 2048),
    query: String(fields.query || "").slice(0, 2048),
    httpVersion: fields.httpVersion || "1.1",
    headers: filterHeaders(fields.headers),
    bodyPreview: String(fields.bodyPreview || "").slice(0, 4096),
    bodyBytes: typeof fields.bodyBytes === "number" ? fields.bodyBytes : 0,
    bodyTruncated: Boolean(fields.bodyTruncated),
    matchedRoute: fields.matchedRoute || "not_found",
    responseStatus: typeof fields.responseStatus === "number" ? fields.responseStatus : 0,
    responseBytes: typeof fields.responseBytes === "number" ? fields.responseBytes : 0,
    authenticated: Boolean(fields.authenticated),
  };
  if (fields.credentials) {
    payload.credentials = {
      username: String(fields.credentials.username || ""),
      password: String(fields.credentials.password || ""),
    };
  }
  return payload;
}

/**
 * Build an llm_response event payload for an HTTP page.
 *
 * @param {object} fields
 * @returns {object} payload
 */
export function buildLlmPayload(fields) {
  return {
    command: fields.command,
    exitCode: typeof fields.exitCode === "number" ? fields.exitCode : 0,
    outputLength: typeof fields.outputLength === "number" ? fields.outputLength : 0,
    outputPreview: String(fields.outputPreview || "").slice(0, 500),
  };
}
