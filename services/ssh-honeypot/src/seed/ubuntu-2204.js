import { createPersona } from "../../../../packages/persona/src/persona.js";
import { createHoneytokens } from "../../../../packages/persona/src/honeytokens.js";

const MTIME = "2024-03-05T10:21:00.000Z";

function dirNode(owner, group, mode) {
  return { type: "dir", mode, owner, group, mtime: MTIME, children: {} };
}

function fileNode(content, owner, group, mode) {
  return { type: "file", mode, owner, group, mtime: MTIME, content };
}

/**
 * Build the Ubuntu 22.04 seed tree. Accepts a hostname string (legacy),
 * a persona object, or { persona, honeytokens }.
 *
 * @param {string|object} hostnameOrPersona
 * @param {object} [extra]
 * @returns {object} seed tree root node
 */
export function buildSeed(hostnameOrPersona, extra) {
  let persona = null;
  let honeytokens = null;
  if (typeof hostnameOrPersona === "string") {
    persona = createPersona({ seed: "change-me-default-seed", hostname: hostnameOrPersona || "srv-web-01" });
  } else if (hostnameOrPersona && hostnameOrPersona.company) {
    persona = hostnameOrPersona;
    honeytokens = extra && extra.honeytokens ? extra.honeytokens : null;
  } else if (hostnameOrPersona && hostnameOrPersona.persona) {
    persona = hostnameOrPersona.persona;
    honeytokens = hostnameOrPersona.honeytokens || null;
  } else {
    persona = createPersona({ seed: "change-me-default-seed", hostname: "srv-web-01" });
  }
  if (!honeytokens) honeytokens = createHoneytokens(persona, { enabled: true });
  const host = persona.host.hostname;
  const tokenByKind = {};
  for (const token of honeytokens.tokens) tokenByKind[token.kind] = token.value;
  const dbPass = tokenByKind.db_password || "";
  const apiKey = tokenByKind.api_key || "";
  const sshPass = tokenByKind.ssh_password || "";
  const ftpPass = tokenByKind.ftp_password || "";
  const wpPass = tokenByKind.wp_password || "";
  const passwd = persona.users.map((user) => `${user.username}:x:${user.uid}:${user.gid}:${user.gecos}:${user.home}:${user.shell}`).join("\n") + "\n";
  const shadow = persona.users.map((user) => `${user.username}:${user.username === "root" ? "*" : "!"}:19000:0:99999:7:::`).join("\n") + "\n";
  const bashrcRoot = ["# .bashrc", "export PS1='\\u@\\h:\\w\\$ '", "alias ll='ls -alF'", "alias la='ls -A'"].join("\n") + "\n";
  const profileRoot = ["# .profile", 'if [ -n "$BASH_VERSION" ]; then', '  if [ -f "$HOME/.bashrc" ]; then', '    . "$HOME/.bashrc"', "  fi", "fi"].join("\n") + "\n";
  const bashrcUbuntu = ["# .bashrc", "export PS1='\\u@\\h:\\w\\$ '", "alias ll='ls -alF'"].join("\n") + "\n";
  const authLog = [
    `Mar  5 10:21:01 ${host} sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2`,
    `Mar  5 10:22:14 ${host} sshd[1235]: Failed password for root from 10.0.0.9 port 51234 ssh2`,
    `Mar  5 10:23:02 ${host} sshd[1236]: Disconnected from authenticating user root 10.0.0.9 port 51234`,
  ].join("\n") + "\n";
  const indexHtml = ["<!DOCTYPE html>", "<html>", "<head><title>Welcome</title></head>", "<body>", `<h1>Welcome to ${host}</h1>`, "<p>It works!</p>", "</body>", "</html>"].join("\n") + "\n";
  const osRelease = ['NAME="Ubuntu"', 'VERSION="22.04.3 LTS (Jammy Jellyfish)"', "ID=ubuntu", "ID_LIKE=debian", 'PRETTY_NAME="Ubuntu 22.04.3 LTS"', 'VERSION_ID="22.04"', 'HOME_URL="https://www.ubuntu.com/"', 'SUPPORT_URL="https://help.ubuntu.com/"', 'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"', 'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms/ubuntu-privacy-policy"', "VERSION_CODENAME=jammy", "UBUNTU_CODENAME=jammy"].join("\n") + "\n";
  const wpConfig = [
    "<?php",
    `define( 'DB_NAME', '${persona.web.dbName}' );`,
    `define( 'DB_USER', '${persona.web.dbUser}' );`,
    `define( 'DB_PASSWORD', '${dbPass}' );`,
    "define( 'DB_HOST', 'localhost' );",
    `define( 'DB_CHARSET', 'utf8' );`,
    `define( 'WP_ADMIN_USER', '${persona.web.adminUser}' );`,
    `// ${persona.company.name} site configuration`,
  ].join("\n") + "\n";
  const envFile = [
    `APP_NAME=${persona.company.name}`,
    `APP_DOMAIN=${persona.company.domain}`,
    `DB_HOST=localhost`,
    `DB_DATABASE=${persona.web.dbName}`,
    `DB_USERNAME=${persona.web.dbUser}`,
    `DB_PASSWORD=${dbPass}`,
    `API_KEY=${apiKey}`,
  ].join("\n") + "\n";
  const bashHistory = [
    `curl -u backup:${ftpPass} ftp://${persona.company.domain}/backup/`,
    `mysqldump -u ${persona.web.dbUser} -p${dbPass} ${persona.web.dbName} > /tmp/dump.sql`,
    "ls -la",
    "cd /var/www/html",
  ].join("\n") + "\n";
  const notes = [
    `${persona.company.name} notes`,
    `deploy account: deploy / ${sshPass}`,
    `webmaster account: webmaster / ${wpPass}`,
    `backup account: backup / ${ftpPass}`,
  ].join("\n") + "\n";
  function addDir(parent, name, owner, group, mode) {
    const node = dirNode(owner, group, mode);
    parent.children[name] = node;
    return node;
  }
  function addFile(parent, name, content, owner, group, mode) {
    parent.children[name] = fileNode(content, owner, group, mode);
  }
  const root = dirNode("root", "root", "0755");
  const bin = addDir(root, "bin", "root", "root", "0755");
  addDir(root, "boot", "root", "root", "0755");
  addDir(root, "dev", "root", "root", "0755");
  const etc = addDir(root, "etc", "root", "root", "0755");
  const home = addDir(root, "home", "root", "root", "0755");
  addDir(root, "lib", "root", "root", "0755");
  addDir(root, "opt", "root", "root", "0755");
  addDir(root, "proc", "root", "root", "0555");
  const rootHome = addDir(root, "root", "root", "root", "0700");
  addDir(root, "srv", "root", "root", "0755");
  addDir(root, "tmp", "root", "root", "0755");
  addDir(root, "usr", "root", "root", "0755");
  const varDir = addDir(root, "var", "root", "root", "0755");
  const varLog = addDir(varDir, "log", "root", "root", "0755");
  const varWww = addDir(varDir, "www", "root", "root", "0755");
  const varWwwHtml = addDir(varWww, "html", "www-data", "www-data", "0755");
  const ubuntuHome = addDir(home, "ubuntu", "ubuntu", "ubuntu", "0755");
  const deployHome = addDir(home, "deploy", "deploy", "deploy", "0755");
  addFile(etc, "passwd", passwd, "root", "root", "0644");
  addFile(etc, "shadow", shadow, "root", "shadow", "0640");
  addFile(etc, "hostname", host + "\n", "root", "root", "0644");
  addFile(etc, "hosts", `127.0.0.1 localhost\n127.0.1.1 ${host}\n::1 localhost ip6-localhost ip6-loopback\n`, "root", "root", "0644");
  addFile(etc, "os-release", osRelease, "root", "root", "0644");
  addFile(etc, "issue", "Ubuntu 22.04.3 LTS \\n \\l\n\n", "root", "root", "0644");
  addFile(etc, "resolv.conf", "nameserver 8.8.8.8\nnameserver 1.1.1.1\n", "root", "root", "0644");
  addFile(rootHome, ".bashrc", bashrcRoot, "root", "root", "0644");
  addFile(rootHome, ".profile", profileRoot, "root", "root", "0644");
  addFile(ubuntuHome, ".bashrc", bashrcUbuntu, "ubuntu", "ubuntu", "0644");
  addFile(deployHome, ".bash_history", bashHistory, "deploy", "deploy", "0644");
  addFile(deployHome, "notes.txt", notes, "deploy", "deploy", "0644");
  addFile(varLog, "auth.log", authLog, "root", "root", "0644");
  addFile(varWwwHtml, "index.html", indexHtml, "www-data", "www-data", "0644");
  addFile(varWwwHtml, "wp-config.php", wpConfig, "www-data", "www-data", "0644");
  addFile(varWwwHtml, ".env", envFile, "www-data", "www-data", "0644");
  void bin;
  return root;
}

export function uidForUser(username) {
  if (username === "root") return 0;
  if (username === "ubuntu") return 1000;
  const others = ["admin", "guest", "oracle", "pi", "postgres", "test", "user"];
  const index = others.indexOf(username);
  if (index >= 0) return 1001 + index;
  let hash = 0;
  for (const ch of username) hash = (hash * 31 + ch.charCodeAt(0)) % 10000;
  return 2000 + (hash % 5000);
}
