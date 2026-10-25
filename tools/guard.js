// tools/guard.js : written by the lead reviewer. Muse must NOT edit this file.
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, relative, extname, basename, sep } from "node:path";

const ROOT = process.cwd();
const SKIP_DIRS = new Set(["node_modules", ".git", "coverage", "logs", "data"]);
const SELF = join("tools", "guard.js");
const TEXT_EXT = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".json",
  ".md",
  ".yml",
  ".yaml",
  ".txt",
  ".html",
  ".css",
]);
const CODE_EXT = new Set([".js", ".mjs", ".cjs"]);

const DANGEROUS = [
  [/child_process/, "child_process is banned"],
  [
    /(?<![.\w])(exec|execSync|execFile|spawn|spawnSync|fork)\s*\(/,
    "process execution call",
  ],
  [/(?<![.\w])eval\s*\(/, "eval is banned"],
  [/new\s+Function\s*\(/, "new Function is banned"],
];
const SECRETS = [
  [/AIza[0-9A-Za-z_-]{20,}/, "Google API key pattern"],
  [/\bAQ\.[0-9A-Za-z_-]{20,}/, "Gemini key pattern"],
  [
    /GEMINI_API_KEY\s*=\s*['"]?[^\s'"]{8,}/,
    "key assigned a real-looking value",
  ],
];
const COMPOSE = [
  [/privileged\s*:\s*true/, "privileged container"],
  [/docker\.sock/, "docker socket mount"],
  [/network_mode\s*:\s*['"]?host/, "host network mode"],
];

function* walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(join(dir, e.name));
    } else yield join(dir, e.name);
  }
}

const problems = [];
const add = (file, line, why) =>
  problems.push(`${relative(ROOT, file)}:${line}  ${why}`);

for (const file of walk(ROOT)) {
  const rel = relative(ROOT, file);
  const name = basename(file);
  if (rel === SELF || name === ".env" || name === "package-lock.json") continue;
  const ext = extname(file);
  const isEnvExample = name.startsWith(".env.");
  if (!TEXT_EXT.has(ext) && !isEnvExample) continue;

  const lines = readFileSync(file, "utf8").split(/\r?\n/);
  const isCode = CODE_EXT.has(ext);
  const isCompose = /^docker-compose.*\.ya?ml$/.test(name);

  lines.forEach((text, i) => {
    for (const [re, why] of SECRETS)
      if (re.test(text)) add(file, i + 1, `SECRET: ${why} (value hidden)`);
    if (isCode)
      for (const [re, why] of DANGEROUS)
        if (re.test(text)) add(file, i + 1, `DANGEROUS: ${why}`);
    if (isCompose)
      for (const [re, why] of COMPOSE)
        if (re.test(text)) add(file, i + 1, `COMPOSE: ${why}`);
  });
}

const gi = existsSync(".gitignore")
  ? readFileSync(".gitignore", "utf8")
      .split(/\r?\n/)
      .map((s) => s.trim())
  : [];
if (!gi.includes(".env"))
  problems.push('.gitignore does not contain a ".env" line');

if (problems.length) {
  console.error("GUARD FAILED:\n" + problems.map((p) => " - " + p).join("\n"));
  process.exit(1);
}
console.log(
  "GUARD OK: no dangerous calls, no hardcoded keys, .env ignored, compose safe",
);
