import { randomUUID } from "node:crypto";

/**
 * Create a per-connection FTP session.
 *
 * @param {object} options
 * @param {object} options.config
 * @param {object} options.vfs
 * @param {string} options.sourceIp
 * @returns {object} session
 */
export function createFtpSession({ config, vfs, sourceIp }) {
  return {
    sessionId: randomUUID(),
    sourceIp,
    vfs,
    username: null,
    pendingUser: null,
    loggedIn: false,
    anonymous: false,
    cwd: "/",
    authAttempts: 0,
    commandCount: 0,
    bytesIn: 0,
    bytesOut: 0,
    startMs: Date.now(),
    lastActivityMs: Date.now(),
    commandTimes: [],
    restOffset: 0,
    renameFrom: null,
    dataListener: null,
    dataSocket: null,
    dataSocketPromise: null,
    dataSocketResolve: null,
    sessionBytes: 0,
    type: "I",
  };
}

/**
 * Resolve an FTP path argument against the session cwd, clamped at /.
 *
 * @param {object} session
 * @param {string} arg
 * @returns {string} absolute normalized path
 */
export function resolveFtpPath(session, arg) {
  if (!arg) return session.cwd;
  return session.vfs.resolve(session.cwd, arg, "/");
}
