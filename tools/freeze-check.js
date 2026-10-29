import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const TASK_MARKERS = ["TO" + "DO", "FIX" + "ME", "X" + "XX"];
export const SECRET_PATTERNS = [
  /AIza[0-9A-Za-z_-]{20,}/,
  /ghp_[0-9A-Za-z]{20,}/,
  /github_pat_[0-9A-Za-z_]{20,}/,
  /sk-[0-9A-Za-z]{20,}/,
];
export const FINAL_REPORT_STACK_MARKERS = ["Stack change", "Python", "Cowrie", "Node.js", "Gemini", "was not built"];
export const FINAL_REPORT_EVALUATION_MARKERS = ["Day 19", "0.062", "41.434", "845.221", "30.786", "26.67"];
export const FINAL_REPORT_LIMITATION_MARKERS = ["Known limitations", "Grafana"];

export function repoRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function walkJsFiles(dir, includeTests) {
  const found = [];
  const walk = (current) => {
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".js")) {
        const isTest = entry.name.endsWith(".test.js");
        if (isTest === includeTests) found.push(full);
      }
    }
  };
  walk(dir);
  return found;
}

export function findTestFiles(rootDir) {
  return walkJsFiles(rootDir, true);
}

export function toPosixRelative(rootDir, full) {
  return path.relative(rootDir, full).split(path.sep).join("/");
}

export function checkTestList(rootDir) {
  const name = "test files in npm test list";
  let scriptText = "";
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf8"));
    scriptText = (pkg.scripts && pkg.scripts.test) || "";
  } catch (error) {
    return { name, status: "fail", detail: `cannot read test list: ${error.message}` };
  }
  const missing = [];
  for (const full of findTestFiles(rootDir)) {
    const rel = toPosixRelative(rootDir, full);
    if (!scriptText.includes(rel)) missing.push(rel);
  }
  if (missing.length > 0) return { name, status: "fail", detail: `missing from test list: ${missing.join(", ")}` };
  return { name, status: "pass", detail: "" };
}

export function checkReadmeDays(rootDir) {
  const name = "README day paragraphs";
  let text = "";
  try {
    text = fs.readFileSync(path.join(rootDir, "README.md"), "utf8");
  } catch (error) {
    return { name, status: "fail", detail: `cannot read README: ${error.message}` };
  }
  const missing = [];
  for (let day = 1; day <= 20; day += 1) {
    if (!new RegExp(`\\bDay ${day}\\b`).test(text)) missing.push(day);
  }
  if (missing.length > 0) return { name, status: "fail", detail: `missing day paragraphs: ${missing.join(", ")}` };
  return { name, status: "pass", detail: "" };
}

export function checkFinalReport(rootDir) {
  const name = "final report sections";
  let text = "";
  try {
    text = fs.readFileSync(path.join(rootDir, "docs", "final-report.md"), "utf8");
  } catch {
    return { name, status: "fail", detail: "docs/final-report.md missing" };
  }
  const missing = [];
  for (const marker of [...FINAL_REPORT_STACK_MARKERS, ...FINAL_REPORT_EVALUATION_MARKERS, ...FINAL_REPORT_LIMITATION_MARKERS]) {
    if (!text.includes(marker)) missing.push(marker);
  }
  if (missing.length > 0) return { name, status: "fail", detail: `missing markers: ${missing.join(", ")}` };
  return { name, status: "pass", detail: "" };
}

export function scanFilesForPatterns(files, patterns) {
  const hits = [];
  const combined = new RegExp(patterns.map((pattern) => pattern.source).join("|"));
  for (const file of files) {
    let text = "";
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      const match = line.match(combined);
      if (match) hits.push(`${file}:${index + 1} ${match[0]}`);
    });
  }
  return hits;
}

export function productionFiles(rootDir) {
  const dirs = ["services", "packages", "tools"];
  const files = [];
  for (const dir of dirs) files.push(...walkJsFiles(path.join(rootDir, dir), false));
  return files;
}

export function checkTaskMarkers(rootDir) {
  const name = "task markers in production code";
  const hits = scanFilesForPatterns(productionFiles(rootDir), TASK_MARKERS.map((word) => new RegExp(word)));
  if (hits.length > 0) return { name, status: "fail", detail: hits.join("; ") };
  return { name, status: "pass", detail: "" };
}

export function checkTestTaskMarkers(rootDir) {
  const name = "task markers in test files";
  const dirs = ["services", "packages", "tools"];
  const files = [];
  for (const dir of dirs) files.push(...walkJsFiles(path.join(rootDir, dir), true));
  const hits = scanFilesForPatterns(files, TASK_MARKERS.map((word) => new RegExp(word)));
  if (hits.length > 0) return { name, status: "note", detail: hits.join("; ") };
  return { name, status: "pass", detail: "" };
}

export function checkSecrets(rootDir) {
  const name = "hardcoded secrets in production code";
  const hits = scanFilesForPatterns(productionFiles(rootDir), SECRET_PATTERNS);
  if (hits.length > 0) return { name, status: "fail", detail: hits.join("; ") };
  return { name, status: "pass", detail: "" };
}

export function runFreezeCheck(rootDir) {
  const results = [
    checkTestList(rootDir),
    checkReadmeDays(rootDir),
    checkFinalReport(rootDir),
    checkTaskMarkers(rootDir),
    checkTestTaskMarkers(rootDir),
    checkSecrets(rootDir),
  ];
  return { results, failed: results.filter((result) => result.status === "fail").length };
}

export function formatFreezeText(check) {
  return check.results.map((result) => {
    const label = result.status.toUpperCase();
    return result.detail ? `${label} ${result.name}: ${result.detail}` : `${label} ${result.name}`;
  }).join("\n");
}

export function runFreezeCli(argv, deps = {}) {
  const log = deps.logFn || ((line) => console.log(line));
  const rootDir = argv[0] || repoRoot();
  const check = runFreezeCheck(rootDir);
  log(formatFreezeText(check));
  return check.failed > 0 ? 1 : 0;
}

function main() {
  process.exitCode = runFreezeCli(process.argv.slice(2));
}

if (process.argv[1] && process.argv[1].endsWith("freeze-check.js")) {
  main();
}
