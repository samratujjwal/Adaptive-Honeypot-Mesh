import { readdirSync, readFileSync, existsSync } from "node:fs";
import { dirname, join, extname } from "node:path";
import { fileURLToPath } from "node:url";

function defaultPagesDir() {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "pages");
}

function defaultCredentialsPath() {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "config", "web-credentials.json");
}

/**
 * Load pages and credentials once at startup into memory. This is
 * the only file allowed to use node:fs, and only at startup.
 *
 * @param {object} [options]
 * @param {string} [options.pagesDir]
 * @param {string} [options.credentialsPath]
 * @returns {{ pages: Map<string, Buffer>, credentials: Array<{ username: string, password: string }> }}
 */
export function loadPages({ pagesDir, credentialsPath } = {}) {
  const dir = pagesDir || defaultPagesDir();
  const pages = new Map();
  if (existsSync(dir)) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const full = join(dir, entry.name);
      const data = readFileSync(full);
      pages.set(entry.name, data);
    }
  }
  let credentials = [];
  const credPath = credentialsPath || defaultCredentialsPath();
  if (existsSync(credPath)) {
    try {
      const parsed = JSON.parse(readFileSync(credPath, "utf8"));
      if (Array.isArray(parsed)) credentials = parsed;
    } catch {
      credentials = [];
    }
  }
  return { pages, credentials };
}

export function pagesDirForTest() {
  return defaultPagesDir();
}

export function credentialsPathForTest() {
  return defaultCredentialsPath();
}

export function extToContentType(ext) {
  if (ext === ".html") return "text/html; charset=UTF-8";
  if (ext === ".css") return "text/css";
  if (ext === ".js") return "application/javascript";
  if (ext === ".png") return "image/png";
  if (ext === ".ico") return "image/x-icon";
  if (ext === ".svg") return "image/svg+xml";
  if (ext === ".txt") return "text/plain";
  if (ext === ".json") return "application/json";
  return "text/plain";
}

export function extnameOf(name) {
  return extname(name).toLowerCase();
}
