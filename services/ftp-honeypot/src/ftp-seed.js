import { createPersona } from "../../../packages/persona/src/persona.js";
import { createHoneytokens } from "../../../packages/persona/src/honeytokens.js";

const MTIME = "2024-03-05T10:21:00.000Z";
function file(content) {
  return { type: "file", mode: "0644", owner: "ftp", group: "ftp", mtime: MTIME, content };
}
function dir(children, mode) {
  return { type: "dir", mode: mode || "0755", owner: "ftp", group: "ftp", mtime: MTIME, children: children || {} };
}

/**
 * Build the FTP tree. Accepts a persona object, { persona, honeytokens },
 * or nothing (default persona).
 *
 * @param {object} [options]
 * @returns {object} seed tree root
 */
export function buildFtpSeed(options) {
  let persona = null;
  let honeytokens = null;
  if (options && options.company) persona = options;
  else if (options && options.persona) { persona = options.persona; honeytokens = options.honeytokens || null; }
  else persona = createPersona({ seed: "change-me-default-seed", hostname: "srv-web-01" });
  if (!honeytokens) honeytokens = createHoneytokens(persona, { enabled: true });
  const byKind = {};
  for (const token of honeytokens.tokens) byKind[token.kind] = token.value;
  const dbPass = byKind.db_password || "";
  const apiKey = byKind.api_key || "";
  const ftpPass = byKind.ftp_password || "";
  const wpPass = byKind.wp_password || "";
  const sshPass = byKind.ssh_password || "";
  return dir({
    pub: dir({
      "readme.txt": file(`Welcome to the ${persona.company.name} public FTP archive.\nPlease see the release notes for current information.\n`),
      "release-notes.txt": file(`${persona.company.name} release notes, version 1.0.\nChanges: initial release.\n`),
    }),
    incoming: dir({}, "0777"),
    backup: dir({
      "config.bak": file(`APP_NAME=${persona.company.name}\nDB_DATABASE=${persona.web.dbName}\nDB_USERNAME=${persona.web.dbUser}\nDB_PASSWORD=${dbPass}\nAPI_KEY=${apiKey}\nFTP_USER=backup\nFTP_PASSWORD=${ftpPass}\n`),
      "db_backup_2026-09-30.sql": file(`-- Database backup, 2026-09-30\nCREATE TABLE ${persona.web.dbName} (id INTEGER);\n`),
      "notes.txt": file(`${persona.company.name} backup notes.\nwebmaster account: webmaster / ${wpPass}\ndeploy account: deploy / ${sshPass}\n`),
    }),
  });
}
