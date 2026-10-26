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
export function loadPages({ pagesDir, credentialsPath, persona, honeytokens } = {}) {
  const replacements = {};
  if (persona) {
    const byKind = {};
    if (honeytokens) for (const token of honeytokens.tokens) byKind[token.kind] = token.value;
    replacements["{{COMPANY}}"] = persona.company.name;
    replacements["{{DOMAIN}}"] = persona.company.domain;
    replacements["{{THEME}}"] = persona.web.theme;
    replacements["{{WP_VERSION}}"] = persona.versions.wordpress;
    replacements["{{DB_NAME}}"] = persona.web.dbName;
    replacements["{{DB_USER}}"] = persona.web.dbUser;
    replacements["{{DB_PASSWORD}}"] = byKind.db_password || "";
    replacements["{{API_KEY}}"] = byKind.api_key || "";
    replacements["{{WP_PASSWORD}}"] = byKind.wp_password || "";
    replacements["{{ADMIN_EMAIL}}"] = persona.company.adminEmail;
    replacements["{{TAGLINE}}"] = persona.company.tagline;
    replacements["ExampleCorp"] = persona.company.name;
    replacements["example.com"] = persona.company.domain;
    replacements["example.org"] = persona.company.domain;
  }
  const dir = pagesDir || defaultPagesDir();
  const pages = new Map();
  if (existsSync(dir)) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const full = join(dir, entry.name);
      let data = readFileSync(full);
      if (persona && (entry.name.endsWith(".html") || entry.name.endsWith(".txt"))) {
        let text = data.toString("utf8");
        for (const [key, value] of Object.entries(replacements)) text = text.split(key).join(value);
        data = Buffer.from(text, "utf8");
      }
      pages.set(entry.name, data);
    }
  }
  if (persona) {
    const byKind = {};
    if (honeytokens) for (const token of honeytokens.tokens) byKind[token.kind] = token.value;
    const bak = [
      "<?php",
      `define( 'DB_NAME', '${persona.web.dbName}' );`,
      `define( 'DB_USER', '${persona.web.dbUser}' );`,
      `define( 'DB_PASSWORD', '${byKind.db_password || ""}' );`,
      "define( 'DB_HOST', 'localhost' );",
      `// ${persona.company.name} site configuration`,
    ].join("\n") + "\n";
    pages.set("wp-config.bak", Buffer.from(bak, "utf8"));
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
