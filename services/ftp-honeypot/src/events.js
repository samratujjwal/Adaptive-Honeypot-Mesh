/**
 * Build event payloads for FTP events.
 *
 * @param {object} fields
 * @returns {object} payload
 */
export function buildConnectionOpenPayload() {
  return { clientVersion: null };
}

/**
 * Build an auth_attempt payload.
 *
 * @param {object} fields
 * @returns {object} payload
 */
export function buildAuthPayload(fields) {
  return {
    method: "password",
    username: fields.username || "",
    password: fields.password || "",
    success: Boolean(fields.success),
  };
}

/**
 * Build an ftp_command payload. PASS arg is redacted by the caller.
 *
 * @param {object} fields
 * @returns {object} payload
 */
export function buildCommandPayload(fields) {
  return {
    verb: fields.verb,
    arg: String(fields.arg || "").slice(0, 512),
    loggedIn: Boolean(fields.loggedIn),
    user: fields.user || "",
    responseCode: typeof fields.responseCode === "number" ? fields.responseCode : 0,
  };
}

/**
 * Build a file_transfer payload.
 *
 * @param {object} fields
 * @returns {object} payload
 */
export function buildFileTransferPayload(fields) {
  return {
    tool: "ftp",
    direction: fields.direction,
    path: fields.path,
    size: typeof fields.size === "number" ? fields.size : 0,
    sha256: fields.sha256 || "",
    previewText: String(fields.previewText || "").slice(0, 256),
    previewHex: String(fields.previewHex || "").slice(0, 128),
    saved: false,
    completed: Boolean(fields.completed),
    truncated: Boolean(fields.truncated),
  };
}

/**
 * Build a connection_close payload.
 *
 * @param {object} fields
 * @returns {object} payload
 */
export function buildClosePayload(fields) {
  return {
    durationMs: typeof fields.durationMs === "number" ? fields.durationMs : 0,
    commandCount: typeof fields.commandCount === "number" ? fields.commandCount : 0,
    authAttempts: typeof fields.authAttempts === "number" ? fields.authAttempts : 0,
    bytesIn: typeof fields.bytesIn === "number" ? fields.bytesIn : 0,
    bytesOut: typeof fields.bytesOut === "number" ? fields.bytesOut : 0,
    reason: fields.reason || "client_disconnect",
  };
}
