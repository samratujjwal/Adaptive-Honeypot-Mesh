import { createPersona } from "../../../packages/persona/src/persona.js";
import { extnameOf, extToContentType } from "./pages.js";

const STATIC_DIRS = ["/wp-includes", "/wp-admin", "/wp-content", "/phpmyadmin", "/static", "/assets"];
const WP_HASH = "a1b2c3d4e5f60718293a4b5c6d7e8f90";

function escapeHtml(text) {
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of String(cookieHeader).split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) out[name] = value;
  }
  return out;
}

function parseForm(bodyText) {
  const out = {};
  if (!bodyText) return out;
  for (const pair of String(bodyText).split("&")) {
    if (!pair) continue;
    const index = pair.indexOf("=");
    const rawName = index < 0 ? pair : pair.slice(0, index);
    const rawValue = index < 0 ? "" : pair.slice(index + 1);
    try {
      const name = decodeURIComponent(rawName.replace(/\+/g, " "));
      const value = decodeURIComponent(rawValue.replace(/\+/g, " "));
      out[name] = value;
    } catch {
      out[rawName] = rawValue;
    }
  }
  return out;
}

function nginxPage(serverHeader, status, title) {
  return `<html>\r\n<head><title>${status} ${title}</title></head>\r\n<body>\r\n<center><h1>${status} ${title}</h1></center>\r\n<hr><center>${serverHeader}</center>\r\n</body>\r\n</html>\r\n`;
}

function isInterestingPath(path, authenticated, method) {
  if (method !== "GET" && method !== "POST") return false;
  const lower = path.toLowerCase();
  const prefixes = ["/api/", "/v1/", "/v2/", "/rest/", "/graphql", "/admin/", "/dashboard", "/backup", "/config", "/db", "/dump", "/login", "/user", "/users", "/account"];
  if (prefixes.some((prefix) => lower.startsWith(prefix))) return true;
  const suffixes = [".sql", ".bak", ".json", ".yml", ".yaml", ".xml", ".conf", ".ini", ".log", ".txt"];
  if (suffixes.some((suffix) => lower.endsWith(suffix))) return true;
  if (authenticated && (lower.startsWith("/wp-admin/") || lower.startsWith("/admin/"))) return true;
  return false;
}

function isStaticAsset(path) {
  const lower = path.toLowerCase();
  if (!STATIC_DIRS.some((dir) => lower.startsWith(dir))) return false;
  const ext = extnameOf(lower);
  return [".css", ".js", ".png", ".ico", ".svg"].includes(ext);
}

function staticAssetBody(path) {
  const ext = extnameOf(path.toLowerCase());
  if (ext === ".css") return "/* site styles */\nbody { margin: 0; }\n";
  if (ext === ".js") return "// site script\nconsole.log('loaded');\n";
  if (ext === ".png") return Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (ext === ".ico") return Buffer.from([0, 0, 1, 0, 1, 0]);
  if (ext === ".svg") return '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>';
  return "";
}

/**
 * Route one HTTP request in memory. No fs, no network, no execution.
 *
 * @param {object} options
 * @param {string} options.method
 * @param {string} options.path
 * @param {string} options.query
 * @param {object} options.headers
 * @param {string} options.bodyText
 * @param {Map<string, Buffer>} options.pages
 * @param {Array<{ username: string, password: string }>} options.credentials
 * @param {object} options.tokenStore
 * @param {string} options.sourceIp
 * @param {string} options.serverHeader
 * @returns {object} route result
 */
export function routeRequest({ method, path, query, headers, bodyText, pages, credentials, tokenStore, sourceIp, serverHeader, persona, honeytokens }) {
  const facts = persona || createPersona({ seed: "change-me-default-seed" });
  const companyName = facts.company.name;
  const theme = facts.web.theme;
  const wpVersion = facts.versions.wordpress;
  const cookies = parseCookies(headers && (headers.cookie || headers.Cookie));
  const wpCookieName = `wordpress_logged_in_${WP_HASH}`;
  const wpUser = tokenStore ? tokenStore.validate(cookies[wpCookieName], sourceIp, "wp") : null;
  const adminUser = tokenStore ? tokenStore.validate(cookies.hp_admin, sourceIp, "admin") : null;
  const authenticated = Boolean(wpUser || adminUser);
  const header = serverHeader || "nginx/1.18.0 (Ubuntu)";
  const htmlType = "text/html; charset=UTF-8";

  function page(name) {
    const data = pages ? pages.get(name) : null;
    return data ? data.toString("utf8") : "";
  }

  function staticHeaders(bodyText) {
    const lastModified = new Date(facts.host.bootTime).toUTCString();
    const mtimeHex = Math.floor(Date.parse(facts.host.bootTime) / 1000).toString(16);
    const sizeHex = Buffer.byteLength(String(bodyText || ""), "utf8").toString(16);
    const etag = `\"${mtimeHex}-${sizeHex}\"`;
    return { "Last-Modified": lastModified, ETag: etag };
  }
  function notFound() {
    return { status: 404, contentType: "text/html", body: nginxPage(header, 404, "Not Found"), headers: {}, matchedRoute: "not_found", authenticated, llmEligible: false, credentials: null };
  }

  if (method === "HEAD" || method === "GET" || method === "POST" || method === "OPTIONS" || method === "PUT" || method === "DELETE" || method === "PATCH" || method === "TRACE" || method === "CONNECT") {
    // handled below per route; unsupported methods fall through to 405 for known paths
  }

  if (method === "OPTIONS") {
    return { status: 200, contentType: "text/plain", body: "", headers: { Allow: "GET, HEAD, POST, OPTIONS" }, matchedRoute: "options", authenticated, llmEligible: false, credentials: null };
  }

  if (method !== "GET" && method !== "HEAD" && method !== "POST") {
    return { status: 405, contentType: "text/html", body: nginxPage(header, 405, "Not Allowed"), headers: { Allow: "GET, HEAD, POST, OPTIONS" }, matchedRoute: "method_not_allowed", authenticated, llmEligible: false, credentials: null };
  }

  const isHead = method === "HEAD";
  function withHead(result) {
    return result;
  }

  if (path === "/") {
    const homeBody = (page("index.html") || `<html><body><h1>${companyName}</h1></body></html>`).replace(/ExampleCorp/g, companyName);
    return withHead({ status: 200, contentType: htmlType, body: homeBody, headers: staticHeaders(homeBody), matchedRoute: "home", authenticated, llmEligible: false, credentials: null });
  }

  if (path === "/wp-login.php") {
    if (method === "GET" || isHead) {
      const loginBody = (page("wp-login.html") || "").replace(/ExampleCorp/g, companyName);
      return withHead({ status: 200, contentType: htmlType, body: loginBody, headers: staticHeaders(loginBody), matchedRoute: "wp_login", authenticated, llmEligible: false, credentials: null });
    }
    const form = parseForm(bodyText);
    const username = form.log || form.username || "";
    const password = form.pwd || form.password || "";
    const credentialsOut = { username, password };
    const weak = (credentials || []).some((entry) => entry.username === username && entry.password === password);
    if (weak && tokenStore) {
      const token = tokenStore.create(sourceIp, username, "wp");
      return { status: 302, contentType: htmlType, body: "", headers: { Location: "/wp-admin/", "Set-Cookie": `${wpCookieName}=${token}; Path=/; HttpOnly` }, matchedRoute: "wp_login", authenticated: true, llmEligible: false, credentials: credentialsOut };
    }
    const body = `<!DOCTYPE html>\n<html><body>\n<p><strong>Error:</strong> The password you entered for the username <b>${escapeHtml(username)}</b> is incorrect.</p>\n</body></html>\n`;
    return { status: 200, contentType: htmlType, body, headers: {}, matchedRoute: "wp_login", authenticated, llmEligible: false, credentials: credentialsOut };
  }

  if (path === "/wp-admin/" || path === "/wp-admin") {
    if (!wpUser) {
      const redirect = `/wp-login.php?redirect_to=${encodeURIComponent("/wp-admin/")}`;
      return { status: 302, contentType: htmlType, body: "", headers: { Location: redirect }, matchedRoute: "wp_admin", authenticated: false, llmEligible: false, credentials: null };
    }
    return withHead({ status: 200, contentType: htmlType, body: page("wp-admin.html"), headers: {}, matchedRoute: "wp_admin", authenticated: true, llmEligible: false, credentials: null });
  }

  if (path === "/wp-admin/users.php") {
    if (!wpUser) {
      return { status: 302, contentType: htmlType, body: "", headers: { Location: "/wp-login.php?redirect_to=%2Fwp-admin%2Fusers.php" }, matchedRoute: "wp_admin", authenticated: false, llmEligible: false, credentials: null };
    }
    return withHead({ status: 200, contentType: htmlType, body: page("wp-admin-users.html"), headers: {}, matchedRoute: "wp_admin", authenticated: true, llmEligible: false, credentials: null });
  }

  if (path === "/wp-admin/plugins.php") {
    if (!wpUser) {
      return { status: 302, contentType: htmlType, body: "", headers: { Location: "/wp-login.php?redirect_to=%2Fwp-admin%2Fplugins.php" }, matchedRoute: "wp_admin", authenticated: false, llmEligible: false, credentials: null };
    }
    return withHead({ status: 200, contentType: htmlType, body: page("wp-admin-plugins.html"), headers: {}, matchedRoute: "wp_admin", authenticated: true, llmEligible: false, credentials: null });
  }

  if (path === "/xmlrpc.php") {
    if (method === "GET" || isHead) {
      return withHead({ status: 405, contentType: "text/plain", body: "XML-RPC server accepts POST requests only.", headers: { Allow: "POST" }, matchedRoute: "xmlrpc", authenticated, llmEligible: false, credentials: null });
    }
    return { status: 200, contentType: "text/xml", body: '<?xml version="1.0"?><methodResponse><params><param><value><string>ok</string></value></param></params></methodResponse>', headers: {}, matchedRoute: "xmlrpc", authenticated, llmEligible: false, credentials: null };
  }

  if (path === "/phpmyadmin/" || path === "/phpMyAdmin/" || path === "/pma/" || path === "/phpmyadmin" || path === "/phpMyAdmin" || path === "/pma") {
    if (method === "GET" || isHead) {
      return withHead({ status: 200, contentType: htmlType, body: page("phpmyadmin.html"), headers: {}, matchedRoute: "phpmyadmin", authenticated, llmEligible: false, credentials: null });
    }
    const form = parseForm(bodyText);
    const username = form.pma_username || form.username || "";
    const password = form.pma_password || form.password || "";
    const body = `<!DOCTYPE html>\n<html><body>\n<p>#1045 - Access denied for user '${escapeHtml(username || "root")}'@'localhost' (using password: YES)</p>\n</body></html>\n`;
    return { status: 200, contentType: htmlType, body, headers: {}, matchedRoute: "phpmyadmin", authenticated, llmEligible: false, credentials: { username, password } };
  }

  if (path === "/admin" || path === "/admin/login" || path === "/administrator/") {
    if (method === "GET" || isHead) {
      if (adminUser && path === "/admin") {
        return withHead({ status: 200, contentType: htmlType, body: page("admin-dashboard.html"), headers: {}, matchedRoute: "admin_login", authenticated: true, llmEligible: false, credentials: null });
      }
      return withHead({ status: 200, contentType: htmlType, body: page("admin-login.html"), headers: {}, matchedRoute: "admin_login", authenticated, llmEligible: false, credentials: null });
    }
    const form = parseForm(bodyText);
    const username = form.username || form.user || "";
    const password = form.password || form.pass || "";
    const credentialsOut = { username, password };
    const weak = (credentials || []).some((entry) => entry.username === username && entry.password === password);
    if (weak && tokenStore) {
      const token = tokenStore.create(sourceIp, username, "admin");
      return { status: 200, contentType: htmlType, body: page("admin-dashboard.html"), headers: { "Set-Cookie": `hp_admin=${token}; Path=/; HttpOnly` }, matchedRoute: "admin_login", authenticated: true, llmEligible: false, credentials: credentialsOut };
    }
    return { status: 200, contentType: htmlType, body: page("admin-login.html"), headers: {}, matchedRoute: "admin_login", authenticated, llmEligible: false, credentials: credentialsOut };
  }

  if (path === "/.env") {
    const envBody = page("env.txt");
    return withHead({ status: 200, contentType: "text/plain", body: envBody, headers: staticHeaders(envBody), matchedRoute: "sensitive_env", authenticated, llmEligible: false, credentials: null });
  }

  if (path === "/wp-config.php.bak") {
    const bakBody = page("wp-config.bak") || page("env.txt");
    return withHead({ status: 200, contentType: "text/plain", body: bakBody, headers: staticHeaders(bakBody), matchedRoute: "wp_config_bak", authenticated, llmEligible: false, credentials: null });
  }

  if (path === "/.git/config") {
    return withHead({ status: 200, contentType: "text/plain", body: page("git-config.txt"), headers: {}, matchedRoute: "git_config", authenticated, llmEligible: false, credentials: null });
  }

  if (path === "/.git/HEAD") {
    return withHead({ status: 200, contentType: "text/plain", body: page("git-head.txt"), headers: {}, matchedRoute: "git_head", authenticated, llmEligible: false, credentials: null });
  }

  if (path.startsWith("/.git/")) {
    return withHead(notFound());
  }

  if (path === "/robots.txt") {
    return withHead({ status: 200, contentType: "text/plain", body: page("robots.txt"), headers: {}, matchedRoute: "robots", authenticated, llmEligible: false, credentials: null });
  }

  if (path === "/server-status") {
    return withHead({ status: 403, contentType: "text/html", body: nginxPage(header, 403, "Forbidden"), headers: {}, matchedRoute: "server_status", authenticated, llmEligible: false, credentials: null });
  }

  if (path === "/favicon.ico") {
    const data = pages ? pages.get("favicon.ico") : null;
    const body = data || Buffer.from([0, 0, 1, 0, 1, 0]);
    return { status: 200, contentType: "image/x-icon", body, headers: {}, matchedRoute: "favicon", authenticated, llmEligible: false, credentials: null };
  }

  if (isStaticAsset(path)) {
    const body = staticAssetBody(path);
    return withHead({ status: 200, contentType: extToContentType(extnameOf(path)), body, headers: staticHeaders(body), matchedRoute: "static_asset", authenticated, llmEligible: false, credentials: null });
  }

  if (isInterestingPath(path, authenticated, method)) {
    return { status: 0, contentType: htmlType, body: "", headers: {}, matchedRoute: "llm", authenticated, llmEligible: true, credentials: null };
  }

  return withHead(notFound());
}

export function nginxPageForTest(serverHeader, status, title) {
  return nginxPage(serverHeader, status, title);
}

export function wpCookieNameForTest() {
  return `wordpress_logged_in_${WP_HASH}`;
}
