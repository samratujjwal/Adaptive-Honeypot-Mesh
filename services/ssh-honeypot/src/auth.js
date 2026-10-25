import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * Load the weak-credential allowlist from a JSON file. The file holds
 * an array of { username, password } pairs.
 *
 * @param {string} filePath
 * @returns {Array<{ username: string, password: string }>}
 */
export function loadCredentials(filePath) {
  const parsed = JSON.parse(readFileSync(filePath, "utf8"));
  if (!Array.isArray(parsed)) {
    throw new Error("credentials file must contain an array");
  }
  return parsed;
}

/**
 * Check whether a username and password pair is in the allowlist.
 * The comparison is exact and case-sensitive.
 *
 * @param {string} username
 * @param {string} password
 * @param {Array<{ username: string, password: string }>} credentials
 * @returns {boolean}
 */
export function checkPassword(username, password, credentials) {
  return credentials.some((pair) => pair.username === username && pair.password === password);
}

/**
 * Compute the OpenSSH-style SHA256 fingerprint of a public key blob.
 *
 * @param {Buffer} keyData
 * @returns {string}
 */
export function publicKeyFingerprint(keyData) {
  const digest = createHash("sha256").update(keyData).digest("base64").replace(/=+$/, "");
  return `SHA256:${digest}`;
}
