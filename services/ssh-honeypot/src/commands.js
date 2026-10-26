import { tokenize, splitCommands, hasUnsupportedSyntax, expandToken } from "./parser.js";
import { staticTableRespond, isStaticTableCommand, staticRespond } from "../../../packages/llm/src/static.js";
import { emulateWget, emulateCurl } from "./transfers.js";

function downloadContentByExtension(savedAs) {
  const name = String(savedAs || "");
  if (name.endsWith(".sh")) return "#!/bin/sh\n";
  if (name.endsWith(".py")) return "#!/usr/bin/env python3\n";
  if (name.endsWith(".php")) return "<?php\n";
  if (name.endsWith(".html") || name.endsWith(".htm")) return "<html></html>\n";
  return "";
}
export { downloadContentByExtension };
const KERNEL_RELEASE = "5.15.0-91-generic";
const KERNEL_VERSION = "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023";
const MACHINE = "x86_64";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const FORBIDDEN_WRITE = ["/root", "/etc", "/bin", "/usr", "/boot", "/var/log"];
const PIPE_SHELLS = new Set(["sh", "bash", "zsh", "dash", "ash", "ksh"]);

function formatDate(iso) {
  const date = new Date(iso);
  const month = MONTHS[date.getUTCMonth()];
  const day = String(date.getUTCDate()).padStart(2, " ");
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  return `${month} ${day} ${hours}:${minutes}`;
}

function modeString(node) {
  const mode = String(node.mode || "0644");
  const digits = [Number.parseInt(mode[mode.length - 3], 10), Number.parseInt(mode[mode.length - 2], 10), Number.parseInt(mode[mode.length - 1], 10)];
  const bits = digits.map((digit) => `${digit & 4 ? "r" : "-"}${digit & 2 ? "w" : "-"}${digit & 1 ? "x" : "-"}`).join("");
  return (node.type === "dir" ? "d" : "-") + bits;
}

function nodeSize(node) {
  if (node.type === "dir") return 4096;
  if (typeof node.size === "number") return node.size;
  return Buffer.byteLength(node.content || "", "utf8");
}

function humanSize(size) {
  if (size >= 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)}M`;
  if (size >= 1024) return `${(size / 1024).toFixed(1)}K`;
  return String(size);
}

function defaultFallback(ctx, line) {
  const firstWord = line.trim().split(/\s+/)[0] || "";
  return { output: `bash: ${firstWord}: command not found\n`, exitCode: 127 };
}

function normalizeFallbackResult(result, line) {
  if (typeof result === "string") return { output: result, exitCode: 127 };
  if (result && typeof result.output === "string") {
    return { output: result.output, exitCode: typeof result.exitCode === "number" ? result.exitCode : 127 };
  }
  return defaultFallback(null, line);
}

function isCommandNotFound(output, exitCode) {
  return exitCode === 127 && typeof output === "string" && output.startsWith("bash: ") && output.includes("command not found");
}

function isForbiddenPath(absPath) {
  for (const prefix of FORBIDDEN_WRITE) {
    if (absPath === prefix || absPath.startsWith(prefix + "/")) return true;
  }
  return false;
}

function splitPipeSegments(line) {
  const segments = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inSingle) {
      current += ch;
      if (ch === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      current += ch;
      if (ch === '"' && line[i - 1] !== "\\") inDouble = false;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      current += ch;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      current += ch;
      continue;
    }
    if (ch === "\\" && i + 1 < line.length) {
      current += ch + line[i + 1];
      i += 1;
      continue;
    }
    if (ch === "|" && line[i + 1] === "|") {
      current += "||";
      i += 1;
      continue;
    }
    if (ch === "|") {
      segments.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  segments.push(current);
  return segments;
}

function isPipeToShell(line) {
  if (!line.includes("|")) return false;
  const segments = splitPipeSegments(line);
  if (segments.length < 2) return false;
  const last = segments[segments.length - 1].trim();
  if (last === "") return false;
  const firstWord = tokenize(last)[0] || "";
  return PIPE_SHELLS.has(firstWord);
}

function parseRedirect(line) {
  let inSingle = false;
  let inDouble = false;
  let redirectIndex = -1;
  let redirectOp = null;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inSingle) {
      if (ch === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (ch === '"' && line[i - 1] !== "\\") inDouble = false;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      continue;
    }
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (ch === ">" && line[i + 1] === ">") {
      redirectIndex = i;
      redirectOp = ">>";
      i += 1;
      continue;
    }
    if (ch === ">") {
      redirectIndex = i;
      redirectOp = ">";
      continue;
    }
  }
  if (redirectIndex < 0) return null;
  const commandPart = line.slice(0, redirectIndex).trim();
  const filePart = line.slice(redirectIndex + redirectOp.length).trim();
  if (commandPart === "" || filePart === "") return null;
  const fileTokens = tokenize(filePart);
  if (fileTokens.length !== 1) return null;
  const firstWord = tokenize(commandPart)[0] || "";
  if (firstWord !== "echo" && firstWord !== "printf") return null;
  if (hasUnsupportedSyntax(commandPart)) return null;
  return { commandPart, operator: redirectOp, fileArg: fileTokens[0] };
}

/**
 * Create a command engine bound to one session's vfs copy, user
 * and hostname. The engine never touches the real filesystem.
 *
 * @param {object} options
 * @param {object} options.vfs
 * @param {object} options.user
 * @param {string} options.hostname
 * @param {(ctx: object, line: string) => object | string} [options.fallback]
 * @param {object} [options.llm]
 * @param {object} [options.config]
 * @param {string} [options.sessionId]
 * @param {string} [options.sourceIp]
 * @param {(() => number) | number} [options.now]
 * @returns {{ run: (line: string, opts?: object) => Promise<object>, prompt: () => string, cwd: () => string, getNotes: () => string[] }}
 */
export function createCommandEngine({ vfs, user, hostname, fallback, llm, config, sessionId, sourceIp, now, persona }) {
  const home = user.name === "root" ? "/root" : `/home/${user.name}`;
  let cwd = home;
  let oldpwd = null;
  const fallbackFn = typeof fallback === "function" ? fallback : defaultFallback;
  const cfg = config || {};
  const deadlineMs = typeof cfg.SSH_LLM_DEADLINE_MS === "number" ? cfg.SSH_LLM_DEADLINE_MS : 8000;
  const maxFileBytes = typeof cfg.SSH_MAX_FILE_BYTES === "number" ? cfg.SSH_MAX_FILE_BYTES : 65536;
  const maxNodes = typeof cfg.SSH_MAX_NODES === "number" ? cfg.SSH_MAX_NODES : 2000;
  const staticFirst = cfg.HONEYPOT_STATIC_FIRST !== false;
  const sessionIdValue = sessionId || "session";
  const sourceIpValue = sourceIp || "127.0.0.1";
  const nowFn = typeof now === "function" ? now : () => (typeof now === "number" ? now : Date.now());
  let notes = [];
  let psSeq = 0;

  function nowIso() {
    return new Date(nowFn()).toISOString();
  }

  function addNote(text) {
    const trimmed = String(text).trim().slice(0, 120);
    if (trimmed === "") return;
    notes.push(trimmed);
    if (notes.length > 10) notes = notes.slice(-10);
  }

  function getNotes() {
    return [...notes];
  }

  function displayPath(path) {
    if (path === home) return "~";
    if (path.startsWith(home + "/")) return "~" + path.slice(home.length);
    return path;
  }

  function prompt() {
    const marker = user.name === "root" ? "#" : "$";
    return `${user.name}@${hostname}:${displayPath(cwd)}${marker} `;
  }

  function canWritePath(absPath) {
    if (user.uid === 0) return true;
    if (isForbiddenPath(absPath)) return false;
    let current = absPath;
    while (true) {
      const node = vfs.get(current);
      if (node && node.type === "dir") {
        if (current === "/tmp") return true;
        if (node.owner === user.name) return true;
        return vfs.canWrite(user, node);
      }
      if (current === "/") return false;
      const parts = current.split("/").filter((part) => part !== "");
      parts.pop();
      current = "/" + parts.join("/");
    }
  }

  function runCd(args) {
    if (args.length === 0) {
      oldpwd = cwd;
      cwd = home;
      return { output: "", exitCode: 0, handled: true };
    }
    if (args.length > 1) {
      return { output: "bash: cd: too many arguments\n", exitCode: 1, handled: true };
    }
    const arg = args[0];
    if (arg === "-") {
      if (oldpwd === null) {
        return { output: "bash: cd: OLDPWD not set\n", exitCode: 1, handled: true };
      }
      const previous = cwd;
      cwd = oldpwd;
      oldpwd = previous;
      return { output: cwd + "\n", exitCode: 0, handled: true };
    }
    const target = vfs.resolve(cwd, arg, home);
    const node = vfs.get(target);
    if (!node) {
      return { output: `bash: cd: ${arg}: No such file or directory\n`, exitCode: 1, handled: true };
    }
    if (node.type !== "dir") {
      return { output: `bash: cd: ${arg}: Not a directory\n`, exitCode: 1, handled: true };
    }
    if (!vfs.canRead(user, node)) {
      return { output: `bash: cd: ${arg}: Permission denied\n`, exitCode: 1, handled: true };
    }
    oldpwd = cwd;
    cwd = target;
    return { output: "", exitCode: 0, handled: true };
  }

  function runLs(args, tty) {
    const flags = { a: false, capitalA: false, l: false, h: false, one: false };
    const paths = [];
    let flagsDone = false;
    for (const arg of args) {
      if (!flagsDone && arg === "--") {
        flagsDone = true;
        continue;
      }
      if (!flagsDone && arg.startsWith("-") && arg.length > 1 && arg !== "-") {
        if (arg.startsWith("--")) {
          return { output: `ls: unrecognized option '${arg}'\nTry 'ls --help' for more information.\n`, exitCode: 2, handled: true };
        }
        for (const flag of arg.slice(1)) {
          if (flag === "a") flags.a = true;
          else if (flag === "A") flags.capitalA = true;
          else if (flag === "l") flags.l = true;
          else if (flag === "h") flags.h = true;
          else if (flag === "1") flags.one = true;
          else {
            return { output: `ls: invalid option -- '${flag}'\nTry 'ls --help' for more information.\n`, exitCode: 2, handled: true };
          }
        }
        continue;
      }
      flagsDone = true;
      paths.push(arg);
    }
    const targets = paths.length === 0 ? [cwd] : paths;
    const multiple = targets.length > 1;
    let exitCode = 0;
    const sections = [];
    for (const targetArg of targets) {
      const target = vfs.resolve(cwd, targetArg, home);
      const node = vfs.get(target);
      if (!node) {
        sections.push(`ls: cannot access '${targetArg}': No such file or directory\n`);
        exitCode = 2;
        continue;
      }
      if (node.type === "file") {
        if (flags.l) {
          sections.push(`${modeString(node)} 1 ${node.owner} ${node.group} ${flags.h ? humanSize(nodeSize(node)) : nodeSize(node)} ${formatDate(node.mtime)} ${targetArg.split("/").pop()}\n`);
        } else {
          sections.push(targetArg.split("/").pop() + "\n");
        }
        continue;
      }
      if (!vfs.canRead(user, node)) {
        sections.push(`ls: cannot open directory '${targetArg}': Permission denied\n`);
        exitCode = 2;
        continue;
      }
      let entries = vfs.list(target) || [];
      entries = entries.filter((entry) => {
        if (flags.a || flags.capitalA) return true;
        return !entry.name.startsWith(".");
      });
      entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
      if (flags.l) {
        let total = 0;
        const lines = [];
        for (const entry of entries) {
          const size = nodeSize(entry.node);
          total += Math.ceil(size / 4096) * 4;
          const linkCount = entry.node.type === "dir" ? 2 : 1;
          lines.push(`${modeString(entry.node)} ${linkCount} ${entry.node.owner} ${entry.node.group} ${flags.h ? humanSize(size) : size} ${formatDate(entry.node.mtime)} ${entry.name}`);
        }
        let body = `total ${total}\n`;
        if (flags.a) {
          body += `${modeString(node)} 2 ${node.owner} ${node.group} ${flags.h ? humanSize(4096) : 4096} ${formatDate(node.mtime)} .\n`;
          const parentPath = target === "/" ? "/" : target.split("/").slice(0, -1).join("/") || "/";
          const parentNode = vfs.get(parentPath);
          if (parentNode) {
            body += `${modeString(parentNode)} 2 ${parentNode.owner} ${parentNode.group} ${flags.h ? humanSize(4096) : 4096} ${formatDate(parentNode.mtime)} ..\n`;
          }
        }
        body += lines.map((line) => line + "\n").join("");
        sections.push(multiple ? `${targetArg}:\n${body}` : body);
      } else {
        let names = entries.map((entry) => entry.name);
        if (flags.a) names = [".", "..", ...names];
        let body = "";
        if (flags.one || !tty) {
          body = names.map((name) => name + "\n").join("");
        } else {
          let line = "";
          for (const name of names) {
            const piece = line === "" ? name : "  " + name;
            if (line !== "" && line.length + piece.length > 80) {
              body += line + "\n";
              line = name;
            } else {
              line += piece;
            }
          }
          if (line !== "") body += line + "\n";
        }
        sections.push(multiple ? `${targetArg}:\n${body}` : body);
      }
    }
    return { output: sections.join("\n"), exitCode, handled: true };
  }

  function runCat(args) {
    if (args.length === 0) {
      return { output: "", exitCode: 0, handled: true };
    }
    let output = "";
    let exitCode = 0;
    for (const arg of args) {
      const target = vfs.resolve(cwd, arg, home);
      const node = vfs.get(target);
      if (!node) {
        output += `cat: ${arg}: No such file or directory\n`;
        exitCode = 1;
        continue;
      }
      if (node.type === "dir") {
        output += `cat: ${arg}: Is a directory\n`;
        exitCode = 1;
        continue;
      }
      if (!vfs.canRead(user, node)) {
        output += `cat: ${arg}: Permission denied\n`;
        exitCode = 1;
        continue;
      }
      output += node.content;
    }
    return { output, exitCode, handled: true };
  }

  function runId(args) {
    const uid = user.uid;
    const group = user.name;
    if (args.length === 0) {
      return { output: `uid=${uid}(${user.name}) gid=${uid}(${group}) groups=${uid}(${group})\n`, exitCode: 0, handled: true };
    }
    if (args.length === 1 && args[0] === "-u") return { output: `${uid}\n`, exitCode: 0, handled: true };
    if (args.length === 1 && args[0] === "-g") return { output: `${uid}\n`, exitCode: 0, handled: true };
    if (args.length === 1 && args[0] === "-un") return { output: `${user.name}\n`, exitCode: 0, handled: true };
    if (args.length === 1 && args[0] === "-gn") return { output: `${group}\n`, exitCode: 0, handled: true };
    const bad = args.find((arg) => arg.startsWith("-"));
    if (bad) {
      const flag = bad.replace(/^-+/, "")[0] || "";
      return { output: `id: invalid option -- '${flag}'\nTry 'id --help' for more information.\n`, exitCode: 1, handled: true };
    }
    return { output: `uid=${uid}(${user.name}) gid=${uid}(${group}) groups=${uid}(${group})\n`, exitCode: 0, handled: true };
  }

  function runUname(args) {
    const wanted = new Set();
    for (const arg of args) {
      if (arg === "-a") {
        return { output: `Linux ${hostname} ${KERNEL_RELEASE} ${KERNEL_VERSION} ${MACHINE} ${MACHINE} ${MACHINE} GNU/Linux\n`, exitCode: 0, handled: true };
      }
      if (arg.startsWith("-") && arg.length > 1 && !arg.startsWith("--")) {
        for (const flag of arg.slice(1)) {
          if (!["s", "n", "r", "v", "m", "o"].includes(flag)) {
            return { output: `uname: invalid option -- '${flag}'\nTry 'uname --help' for more information.\n`, exitCode: 1, handled: true };
          }
          wanted.add(flag);
        }
      } else if (arg.startsWith("-")) {
        return { output: `uname: invalid option -- '${arg.replace(/^-+/, "")[0] || ""}'\nTry 'uname --help' for more information.\n`, exitCode: 1, handled: true };
      }
    }
    if (wanted.size === 0) wanted.add("s");
    const values = { s: "Linux", n: hostname, r: KERNEL_RELEASE, v: KERNEL_VERSION, m: MACHINE, o: "GNU/Linux" };
    const ordered = ["s", "n", "r", "v", "m", "o"].filter((flag) => wanted.has(flag)).map((flag) => values[flag]);
    return { output: ordered.join(" ") + "\n", exitCode: 0, handled: true };
  }

  function runEcho(args) {
    let noNewline = false;
    let interpret = false;
    const rest = [];
    let parsingFlags = true;
    for (const arg of args) {
      if (parsingFlags && arg.startsWith("-") && arg.length > 1 && /^[ne]+$/.test(arg.slice(1))) {
        if (arg.includes("n")) noNewline = true;
        if (arg.includes("e")) interpret = true;
        continue;
      }
      parsingFlags = false;
      rest.push(arg);
    }
    let text = rest.join(" ");
    if (interpret) {
      text = text.replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\\\/g, "\\");
    }
    return { output: noNewline ? text : text + "\n", exitCode: 0, handled: true };
  }

  function runPrintf(args) {
    if (args.length === 0) {
      return { output: "", exitCode: 0, handled: true };
    }
    const format = args[0];
    const rest = args.slice(1);
    let argIndex = 0;
    let out = "";
    for (let i = 0; i < format.length; i += 1) {
      const ch = format[i];
      if (ch === "\\" && i + 1 < format.length) {
        const next = format[i + 1];
        if (next === "n") out += "\n";
        else if (next === "t") out += "\t";
        else if (next === "r") out += "\r";
        else if (next === "\\") out += "\\";
        else out += next;
        i += 1;
        continue;
      }
      if (ch === "%" && i + 1 < format.length) {
        const spec = format[i + 1];
        if (spec === "%") {
          out += "%";
          i += 1;
          continue;
        }
        if (spec === "s") {
          out += argIndex < rest.length ? rest[argIndex] : "";
          argIndex += 1;
          i += 1;
          continue;
        }
        if (spec === "d" || spec === "i") {
          const value = argIndex < rest.length ? Number.parseInt(rest[argIndex], 10) : 0;
          out += Number.isFinite(value) ? String(value) : "0";
          argIndex += 1;
          i += 1;
          continue;
        }
        if (spec === "c") {
          out += argIndex < rest.length && rest[argIndex].length > 0 ? rest[argIndex][0] : "";
          argIndex += 1;
          i += 1;
          continue;
        }
        out += ch + spec;
        i += 1;
        continue;
      }
      out += ch;
    }
    return { output: out, exitCode: 0, handled: true };
  }

  function countSubtree(node) {
    if (!node) return 0;
    if (node.type !== "dir") return 1;
    let count = 1;
    for (const child of Object.values(node.children || {})) count += countSubtree(child);
    return count;
  }

  function deepCopyVfsNode(node) {
    if (node.type === "file") {
      const copy = { type: "file", mode: node.mode, owner: user.name, group: user.name, mtime: nowIso(), content: node.content };
      if (typeof node.size === "number") copy.size = node.size;
      return copy;
    }
    const children = {};
    for (const [name, child] of Object.entries(node.children || {})) {
      children[name] = deepCopyVfsNode(child);
    }
    return { type: "dir", mode: node.mode, owner: user.name, group: user.name, mtime: nowIso(), children };
  }

  function runMkdir(args) {
    let parents = false;
    const paths = [];
    for (const arg of args) {
      if (arg === "-p" || arg === "--parents") {
        parents = true;
        continue;
      }
      if (arg.startsWith("-") && arg.length > 1 && !arg.startsWith("--")) {
        const flags = arg.slice(1);
        if ([...flags].every((flag) => flag === "p")) {
          parents = true;
          continue;
        }
        return { output: `mkdir: invalid option -- '${flags[0]}'\nTry 'mkdir --help' for more information.\n`, exitCode: 1, handled: true };
      }
      paths.push(arg);
    }
    if (paths.length === 0) {
      return { output: "mkdir: missing operand\n", exitCode: 1, handled: true };
    }
    let output = "";
    let exitCode = 0;
    for (const arg of paths) {
      const target = vfs.resolve(cwd, arg, home);
      const existing = vfs.get(target);
      if (existing) {
        if (parents && existing.type === "dir") continue;
        output += `mkdir: cannot create directory '${arg}': File exists\n`;
        exitCode = 1;
        continue;
      }
      if (!canWritePath(target)) {
        output += `mkdir: cannot create directory '${arg}': Permission denied\n`;
        exitCode = 1;
        continue;
      }
      const parts = target.split("/").filter((part) => part !== "");
      let currentPath = "";
      const toCreate = [];
      for (const part of parts) {
        currentPath += "/" + part;
        if (!vfs.get(currentPath)) toCreate.push(currentPath);
      }
      if (!parents && toCreate.length > 1) {
        output += `mkdir: cannot create directory '${arg}': No such file or directory\n`;
        exitCode = 1;
        continue;
      }
      if (vfs.countNodes() + toCreate.length > maxNodes) {
        output += `mkdir: cannot create directory '${arg}': No space left on device\n`;
        exitCode = 1;
        continue;
      }
      for (const path of toCreate) {
        vfs.mkdirNode(path, { type: "dir", mode: "0755", owner: user.name, group: user.name, mtime: nowIso(), children: {} });
      }
    }
    return { output, exitCode, handled: true };
  }

  function runTouch(args) {
    if (args.length === 0) {
      return { output: "touch: missing file operand\n", exitCode: 1, handled: true };
    }
    let output = "";
    let exitCode = 0;
    for (const arg of args) {
      if (arg.startsWith("-") && arg !== "-") continue;
      const target = vfs.resolve(cwd, arg, home);
      const existing = vfs.get(target);
      if (existing) {
        if (existing.type === "dir") {
          existing.mtime = nowIso();
          continue;
        }
        existing.mtime = nowIso();
        continue;
      }
      if (!canWritePath(target)) {
        output += `touch: cannot touch '${arg}': Permission denied\n`;
        exitCode = 1;
        continue;
      }
      const parentPath = target.split("/").slice(0, -1).join("/") || "/";
      const parent = vfs.get(parentPath);
      if (!parent || parent.type !== "dir") {
        output += `touch: cannot touch '${arg}': No such file or directory\n`;
        exitCode = 1;
        continue;
      }
      if (vfs.countNodes() + 1 > maxNodes) {
        output += `touch: cannot touch '${arg}': No space left on device\n`;
        exitCode = 1;
        continue;
      }
      vfs.mkdirNode(target, { type: "file", mode: "0644", owner: user.name, group: user.name, mtime: nowIso(), content: "" });
    }
    return { output, exitCode, handled: true };
  }

  function runRm(args) {
    let recursive = false;
    let force = false;
    const paths = [];
    for (const arg of args) {
      if (arg === "--") continue;
      if (arg.startsWith("-") && arg.length > 1 && arg !== "-") {
        const flags = arg.slice(1);
        if ([...flags].every((flag) => ["r", "R", "f"].includes(flag))) {
          if (flags.includes("r") || flags.includes("R")) recursive = true;
          if (flags.includes("f")) force = true;
          continue;
        }
        return { output: `rm: invalid option -- '${flags[0]}'\nTry 'rm --help' for more information.\n`, exitCode: 1, handled: true };
      }
      paths.push(arg);
    }
    if (paths.length === 0) {
      return { output: "rm: missing operand\n", exitCode: 1, handled: true };
    }
    for (const arg of paths) {
      if ((arg === "/" || arg === "/*") && recursive) {
        return { output: "rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe\n", exitCode: 1, handled: true };
      }
    }
    let output = "";
    let exitCode = 0;
    for (const arg of paths) {
      const target = vfs.resolve(cwd, arg, home);
      if (target === "/" && recursive) {
        output += "rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe\n";
        exitCode = 1;
        continue;
      }
      const node = vfs.get(target);
      if (!node) {
        if (force) continue;
        output += `rm: cannot remove '${arg}': No such file or directory\n`;
        exitCode = 1;
        continue;
      }
      if (node.type === "dir" && !recursive) {
        output += `rm: cannot remove '${arg}': Is a directory\n`;
        exitCode = 1;
        continue;
      }
      if (!canWritePath(target)) {
        output += `rm: cannot remove '${arg}': Permission denied\n`;
        exitCode = 1;
        continue;
      }
      vfs.removeNode(target);
    }
    return { output, exitCode, handled: true };
  }

  function runRmdir(args) {
    if (args.length === 0) {
      return { output: "rmdir: missing operand\n", exitCode: 1, handled: true };
    }
    let output = "";
    let exitCode = 0;
    for (const arg of args) {
      const target = vfs.resolve(cwd, arg, home);
      const node = vfs.get(target);
      if (!node) {
        output += `rmdir: failed to remove '${arg}': No such file or directory\n`;
        exitCode = 1;
        continue;
      }
      if (node.type !== "dir") {
        output += `rmdir: failed to remove '${arg}': Not a directory\n`;
        exitCode = 1;
        continue;
      }
      if (Object.keys(node.children || {}).length > 0) {
        output += `rmdir: failed to remove '${arg}': Directory not empty\n`;
        exitCode = 1;
        continue;
      }
      if (!canWritePath(target)) {
        output += `rmdir: failed to remove '${arg}': Permission denied\n`;
        exitCode = 1;
        continue;
      }
      vfs.removeNode(target);
    }
    return { output, exitCode, handled: true };
  }

  function runCp(args) {
    let recursive = false;
    const rest = [];
    for (const arg of args) {
      if (arg === "-r" || arg === "-R" || arg === "--recursive") {
        recursive = true;
        continue;
      }
      rest.push(arg);
    }
    if (rest.length < 2) {
      return { output: "cp: missing file operand\n", exitCode: 1, handled: true };
    }
    if (rest.length > 2) {
      return { output: "cp: too many arguments\n", exitCode: 1, handled: true };
    }
    const [sourceArg, destArg] = rest;
    const sourcePath = vfs.resolve(cwd, sourceArg, home);
    const source = vfs.get(sourcePath);
    if (!source) {
      return { output: `cp: cannot stat '${sourceArg}': No such file or directory\n`, exitCode: 1, handled: true };
    }
    if (source.type === "dir" && !recursive) {
      return { output: `cp: -r not specified; omitting directory '${sourceArg}'\n`, exitCode: 1, handled: true };
    }
    let destPath = vfs.resolve(cwd, destArg, home);
    const destExisting = vfs.get(destPath);
    if (destExisting && destExisting.type === "dir") {
      const base = sourcePath.split("/").filter((part) => part !== "").pop() || sourceArg;
      destPath = destPath === "/" ? `/${base}` : `${destPath}/${base}`;
    }
    if (!canWritePath(destPath)) {
      return { output: `cp: cannot create regular file '${destArg}': Permission denied\n`, exitCode: 1, handled: true };
    }
    const parentPath = destPath.split("/").slice(0, -1).join("/") || "/";
    const parent = vfs.get(parentPath);
    if (!parent || parent.type !== "dir") {
      return { output: `cp: cannot create regular file '${destArg}': No such file or directory\n`, exitCode: 1, handled: true };
    }
    if (source.type === "file" && Buffer.byteLength(source.content || "", "utf8") > maxFileBytes) {
      return { output: `cp: cannot create regular file '${destArg}': No space left on device\n`, exitCode: 1, handled: true };
    }
    const newCount = countSubtree(source);
    const existingDest = vfs.get(destPath);
    const netNew = existingDest ? newCount - countSubtree(existingDest) : newCount;
    if (vfs.countNodes() + netNew > maxNodes) {
      return { output: `cp: cannot create regular file '${destArg}': No space left on device\n`, exitCode: 1, handled: true };
    }
    if (existingDest) vfs.removeNode(destPath);
    const copy = deepCopyVfsNode(source);
    if (!vfs.mkdirNode(destPath, copy)) {
      vfs.setNode(destPath, copy);
    }
    return { output: "", exitCode: 0, handled: true };
  }

  function runMv(args) {
    if (args.length !== 2) {
      return { output: args.length < 2 ? "mv: missing file operand\n" : "mv: too many arguments\n", exitCode: 1, handled: true };
    }
    const [sourceArg, destArg] = args;
    const sourcePath = vfs.resolve(cwd, sourceArg, home);
    const source = vfs.get(sourcePath);
    if (!source) {
      return { output: `mv: cannot stat '${sourceArg}': No such file or directory\n`, exitCode: 1, handled: true };
    }
    let destPath = vfs.resolve(cwd, destArg, home);
    const destExisting = vfs.get(destPath);
    if (destExisting && destExisting.type === "dir") {
      const base = sourcePath.split("/").filter((part) => part !== "").pop() || sourceArg;
      destPath = destPath === "/" ? `/${base}` : `${destPath}/${base}`;
    }
    if (destPath === sourcePath) {
      return { output: "", exitCode: 0, handled: true };
    }
    if (!canWritePath(destPath) || !canWritePath(sourcePath)) {
      return { output: `mv: cannot move '${sourceArg}' to '${destArg}': Permission denied\n`, exitCode: 1, handled: true };
    }
    const parentPath = destPath.split("/").slice(0, -1).join("/") || "/";
    const parent = vfs.get(parentPath);
    if (!parent || parent.type !== "dir") {
      return { output: `mv: cannot move '${sourceArg}' to '${destArg}': No such file or directory\n`, exitCode: 1, handled: true };
    }
    const existingDest = vfs.get(destPath);
    if (existingDest) vfs.removeNode(destPath);
    const moved = vfs.removeNode(sourcePath);
    if (!moved) {
      return { output: `mv: cannot move '${sourceArg}' to '${destArg}': Permission denied\n`, exitCode: 1, handled: true };
    }
    if (!vfs.mkdirNode(destPath, moved)) {
      vfs.setNode(destPath, moved);
    }
    return { output: "", exitCode: 0, handled: true };
  }

  function runChmod(args) {
    if (args.length < 2) {
      return { output: "chmod: missing operand\n", exitCode: 1, handled: true };
    }
    const modeArg = args[0];
    const files = args.slice(1);
    let newMode = null;
    let plusX = false;
    let minusX = false;
    if (modeArg === "+x") plusX = true;
    else if (modeArg === "-x") minusX = true;
    else if (/^[0-7]{3,4}$/.test(modeArg)) newMode = modeArg.length === 3 ? "0" + modeArg : modeArg;
    else {
      return { output: `chmod: invalid mode: '${modeArg}'\n`, exitCode: 1, handled: true };
    }
    let output = "";
    let exitCode = 0;
    for (const arg of files) {
      const target = vfs.resolve(cwd, arg, home);
      const node = vfs.get(target);
      if (!node) {
        output += `chmod: cannot access '${arg}': No such file or directory\n`;
        exitCode = 1;
        continue;
      }
      if (user.uid !== 0 && node.owner !== user.name) {
        output += `chmod: changing permissions of '${arg}': Operation not permitted\n`;
        exitCode = 1;
        continue;
      }
      if (newMode) {
        node.mode = newMode;
      } else {
        const mode = String(node.mode || "0644");
        const digits = [mode[mode.length - 3], mode[mode.length - 2], mode[mode.length - 1]].map((digit) => Number.parseInt(digit, 10));
        const changed = digits.map((digit) => (plusX ? digit | 1 : digit & ~1));
        node.mode = "0" + changed.join("");
      }
    }
    return { output, exitCode, handled: true };
  }

  function canExecute(userObj, node) {
    if (!node) return false;
    if (userObj.uid === 0) return true;
    const mode = String(node.mode || "0644");
    const ownerBit = Number.parseInt(mode[mode.length - 3], 10);
    const groupBit = Number.parseInt(mode[mode.length - 2], 10);
    const otherBit = Number.parseInt(mode[mode.length - 1], 10);
    let bits;
    if (node.owner === userObj.name) bits = ownerBit;
    else if (node.group === userObj.name) bits = groupBit;
    else bits = otherBit;
    return (bits & 1) !== 0;
  }

  function runFileCheck(tokens, env) {
    const first = tokens[0];
    let fileArg = null;
    let viaInterpreter = false;
    if (["bash", "sh", "python", "python3"].includes(first) && tokens.length >= 2) {
      fileArg = tokens[1];
      viaInterpreter = true;
    } else if (first && first.includes("/")) {
      fileArg = first;
      viaInterpreter = false;
    } else {
      return null;
    }
    const target = vfs.resolve(cwd, fileArg, home);
    const node = vfs.get(target);
    if (!node) {
      return { output: `bash: ${fileArg}: No such file or directory\n`, exitCode: 127, handled: true, handledBy: "engine", shouldExit: false };
    }
    if (node.type === "dir") {
      return { output: `bash: ${fileArg}: Permission denied\n`, exitCode: 126, handled: true, handledBy: "engine", shouldExit: false };
    }
    if (viaInterpreter) {
      return { output: "", exitCode: 0, handled: true, handledBy: "engine", shouldExit: false };
    }
    if (canExecute(user, node)) {
      return { output: "", exitCode: 0, handled: true, handledBy: "engine", shouldExit: false };
    }
    return { output: `bash: ${fileArg}: Permission denied\n`, exitCode: 126, handled: true, handledBy: "engine", shouldExit: false };
  }

  function runTransfer(tokens, env) {
    const first = tokens[0];
    const args = tokens.slice(1);
    if (first === "wget") {
      if (args.length === 0) {
        return { output: "wget: missing URL\nUsage: wget [OPTION]... [URL]...\nTry 'wget --help' for more information.\n", exitCode: 2, handled: true, handledBy: "engine", shouldExit: false, transfer: null };
      }
      const result = emulateWget(args);
      if (!result.savedAs) {
        return { output: result.output, exitCode: result.exitCode, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "wget", url: result.url, savedAs: null, direction: "download" } };
      }
      const filePath = vfs.resolve(cwd, result.savedAs, home);
      const parentPath = filePath.split("/").slice(0, -1).join("/") || "/";
      const parent = vfs.get(parentPath);
      if (!parent || parent.type !== "dir") {
        return { output: `wget: cannot create file '${result.savedAs}': No such file or directory\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "wget", url: result.url, savedAs: result.savedAs, direction: "download" } };
      }
      if (!canWritePath(filePath)) {
        return { output: `wget: cannot create file '${result.savedAs}': Permission denied\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "wget", url: result.url, savedAs: result.savedAs, direction: "download" } };
      }
      const existing = vfs.get(filePath);
      if (!existing && vfs.countNodes() + 1 > maxNodes) {
        return { output: `wget: cannot create file '${result.savedAs}': No space left on device\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "wget", url: result.url, savedAs: result.savedAs, direction: "download" } };
      }
      if (existing && existing.type === "dir") {
        return { output: `wget: cannot create file '${result.savedAs}': Is a directory\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "wget", url: result.url, savedAs: result.savedAs, direction: "download" } };
      }
      if (existing) vfs.removeNode(filePath);
      vfs.mkdirNode(filePath, { type: "file", mode: "0644", owner: user.name, group: user.name, mtime: nowIso(), content: downloadContentByExtension(result.savedAs), size: result.size });
      return { output: result.output, exitCode: result.exitCode, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "wget", url: result.url, savedAs: result.savedAs, direction: "download" } };
    }
    if (first === "curl") {
      const hasDownloadFlag = args.some((arg) => arg === "-O" || arg === "-o" || arg === "--output" || arg.startsWith("--output="));
      if (!hasDownloadFlag) return null;
      const result = emulateCurl(args);
      if (!result) return null;
      if (!result.savedAs) {
        return { output: result.output, exitCode: result.exitCode, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "curl", url: result.url, savedAs: null, direction: "download" } };
      }
      const filePath = vfs.resolve(cwd, result.savedAs, home);
      const parentPath = filePath.split("/").slice(0, -1).join("/") || "/";
      const parent = vfs.get(parentPath);
      if (!parent || parent.type !== "dir") {
        return { output: `curl: cannot create file '${result.savedAs}': No such file or directory\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "curl", url: result.url, savedAs: result.savedAs, direction: "download" } };
      }
      if (!canWritePath(filePath)) {
        return { output: `curl: cannot create file '${result.savedAs}': Permission denied\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "curl", url: result.url, savedAs: result.savedAs, direction: "download" } };
      }
      const existing = vfs.get(filePath);
      if (!existing && vfs.countNodes() + 1 > maxNodes) {
        return { output: `curl: cannot create file '${result.savedAs}': No space left on device\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "curl", url: result.url, savedAs: result.savedAs, direction: "download" } };
      }
      if (existing && existing.type === "dir") {
        return { output: `curl: cannot create file '${result.savedAs}': Is a directory\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "curl", url: result.url, savedAs: result.savedAs, direction: "download" } };
      }
      if (existing) vfs.removeNode(filePath);
      vfs.mkdirNode(filePath, { type: "file", mode: "0644", owner: user.name, group: user.name, mtime: nowIso(), content: downloadContentByExtension(result.savedAs), size: result.size });
      return { output: result.output, exitCode: result.exitCode, handled: true, handledBy: "engine", shouldExit: false, transfer: { tool: "curl", url: result.url, savedAs: result.savedAs, direction: "download" } };
    }
    return null;
  }

  function runRedirect(redirect, tty) {
    const env = { home, user: user.name, pwd: cwd };
    const tokens = tokenize(redirect.commandPart).map((token) => expandToken(token, env));
    const name = tokens[0];
    const args = tokens.slice(1);
    let text = "";
    if (name === "echo") text = runEcho(args).output;
    else if (name === "printf") text = runPrintf(args).output;
    else return null;
    const filePath = vfs.resolve(cwd, redirect.fileArg, home);
    const existing = vfs.get(filePath);
    if (existing && existing.type === "dir") {
      return { output: `bash: ${redirect.fileArg}: Is a directory\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false };
    }
    if (!canWritePath(filePath)) {
      return { output: `bash: ${redirect.fileArg}: Permission denied\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false };
    }
    const parentPath = filePath.split("/").slice(0, -1).join("/") || "/";
    const parent = vfs.get(parentPath);
    if (!parent || parent.type !== "dir") {
      return { output: `bash: ${redirect.fileArg}: No such file or directory\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false };
    }
    let newContent = text;
    if (redirect.operator === ">>" && existing && existing.type === "file") {
      newContent = (existing.content || "") + text;
    }
    if (Buffer.byteLength(newContent, "utf8") > maxFileBytes) {
      return { output: `bash: ${redirect.fileArg}: No space left on device\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false };
    }
    if (!existing && vfs.countNodes() + 1 > maxNodes) {
      return { output: `bash: ${redirect.fileArg}: No space left on device\n`, exitCode: 1, handled: true, handledBy: "engine", shouldExit: false };
    }
    if (existing) {
      existing.content = newContent;
      existing.mtime = nowIso();
      if (typeof existing.size === "number") delete existing.size;
    } else {
      vfs.mkdirNode(filePath, { type: "file", mode: "0644", owner: user.name, group: user.name, mtime: nowIso(), content: newContent });
    }
    return { output: "", exitCode: 0, handled: true, handledBy: "engine", shouldExit: false };
  }

  async function runLlm(commandString, signal) {
    if (!llm || typeof llm.respond !== "function") {
      const result = normalizeFallbackResult(fallbackFn({ user, hostname, cwd, line: commandString }, commandString), commandString);
      return { output: result.output, exitCode: result.exitCode, handled: false, handledBy: "engine", shouldExit: false, meta: null };
    }
    const ctx = { user: user.name, cwd, hostname, sessionId: sessionIdValue, sourceIp: sourceIpValue, notes: getNotes() };
    let llmPromise;
    try {
      llmPromise = Promise.resolve(llm.respond({ command: commandString, ctx }));
    } catch {
      llmPromise = Promise.resolve(null);
    }
    llmPromise = llmPromise.catch(() => null);
    let timeoutId = null;
    const deadlinePromise = new Promise((resolve) => {
      timeoutId = setTimeout(() => resolve({ deadline: true }), deadlineMs);
    });
    let abortListener = null;
    let abortPromise = null;
    if (signal) {
      if (signal.aborted) {
        clearTimeout(timeoutId);
        return { output: "", exitCode: 130, handled: true, handledBy: "aborted", shouldExit: false, meta: null };
      }
      abortPromise = new Promise((resolve) => {
        abortListener = () => resolve({ aborted: true });
        signal.addEventListener("abort", abortListener, { once: true });
      });
    }
    const racers = [llmPromise.then((value) => ({ value })), deadlinePromise];
    if (abortPromise) racers.push(abortPromise.then(() => ({ aborted: true })));
    const winner = await Promise.race(racers);
    clearTimeout(timeoutId);
    if (signal && abortListener) {
      try {
        signal.removeEventListener("abort", abortListener);
      } catch {
        /* Ignore. */
      }
    }
    if (winner && winner.aborted) {
      return { output: "", exitCode: 130, handled: true, handledBy: "aborted", shouldExit: false, meta: null };
    }
    if (winner && winner.deadline) {
      const staticResult = staticRespond(commandString, { user: user.name, cwd, hostname, sessionId: sessionIdValue, sourceIp: sourceIpValue, now: nowFn, persona });
      return { output: staticResult.output, exitCode: staticResult.exitCode, handled: !isCommandNotFound(staticResult.output, staticResult.exitCode), handledBy: "static", shouldExit: false, meta: null };
    }
    const llmResult = winner && winner.value ? winner.value : null;
    if (!llmResult || typeof llmResult.output !== "string") {
      const staticResult = staticRespond(commandString, { user: user.name, cwd, hostname, sessionId: sessionIdValue, sourceIp: sourceIpValue, now: nowFn, persona });
      return { output: staticResult.output, exitCode: staticResult.exitCode, handled: !isCommandNotFound(staticResult.output, staticResult.exitCode), handledBy: "static", shouldExit: false, meta: null };
    }
    const meta = llmResult.meta || {};
    const source = meta.source || "llm";
    const handledBy = source === "llm" ? "llm" : source === "cache" ? "cache" : source === "mock" ? "mock" : source === "static" ? "static" : "llm";
    return { output: llmResult.output, exitCode: llmResult.exitCode, handled: !isCommandNotFound(llmResult.output, llmResult.exitCode), handledBy, shouldExit: false, meta };
  }

  async function runSingle(commandString, tty, signal) {
    const env = { home, user: user.name, pwd: cwd };
    const rawTokens = tokenize(commandString);
    if (rawTokens.length === 0) {
      return { output: "", exitCode: 0, handled: false, handledBy: "engine", shouldExit: false };
    }
    const tokens = rawTokens.map((token) => expandToken(token, env));
    const name = tokens[0];
    const args = tokens.slice(1);
    if (name === "exit" || name === "logout") {
      return { output: "", exitCode: 0, handled: true, handledBy: "engine", shouldExit: true };
    }
    if (name === "pwd") return { output: cwd + "\n", exitCode: 0, handled: true, handledBy: "engine", shouldExit: false };
    if (name === "cd") return { ...runCd(args), handledBy: "engine", shouldExit: false };
    if (name === "ls") return { ...runLs(args, tty), handledBy: "engine", shouldExit: false };
    if (name === "cat") return { ...runCat(args), handledBy: "engine", shouldExit: false };
    if (name === "whoami") return { output: user.name + "\n", exitCode: 0, handled: true, handledBy: "engine", shouldExit: false };
    if (name === "id") return { ...runId(args), handledBy: "engine", shouldExit: false };
    if (name === "uname") return { ...runUname(args), handledBy: "engine", shouldExit: false };
    if (name === "hostname") return { output: hostname + "\n", exitCode: 0, handled: true, handledBy: "engine", shouldExit: false };
    if (name === "echo") return { ...runEcho(args), handledBy: "engine", shouldExit: false };
    if (name === "printf") return { ...runPrintf(args), handledBy: "engine", shouldExit: false };
    if (name === "clear") return { output: "\x1b[H\x1b[2J", exitCode: 0, handled: true, handledBy: "engine", shouldExit: false };
    if (name === "mkdir") return { ...runMkdir(args), handledBy: "engine", shouldExit: false };
    if (name === "touch") return { ...runTouch(args), handledBy: "engine", shouldExit: false };
    if (name === "rm") return { ...runRm(args), handledBy: "engine", shouldExit: false };
    if (name === "rmdir") return { ...runRmdir(args), handledBy: "engine", shouldExit: false };
    if (name === "cp") return { ...runCp(args), handledBy: "engine", shouldExit: false };
    if (name === "mv") return { ...runMv(args), handledBy: "engine", shouldExit: false };
    if (name === "chmod") return { ...runChmod(args), handledBy: "engine", shouldExit: false };
    if (name === "wget" || name === "curl") {
      const transferResult = runTransfer(tokens, env);
      if (transferResult) return transferResult;
      if (name === "curl" && tokens.length === 1) {
        return { output: "curl: no URL specified!\ncurl: try 'curl --help' for more information\n", exitCode: 2, handled: true, handledBy: "engine", shouldExit: false };
      }
      if (name === "wget" && tokens.length === 1) {
        return { output: "wget: missing URL\nUsage: wget [OPTION]... [URL]...\nTry 'wget --help' for more information.\n", exitCode: 2, handled: true, handledBy: "engine", shouldExit: false };
      }
      if (name === "curl") {
        const llmResult = await runLlm(commandString, signal);
        return llmResult;
      }
      const result = normalizeFallbackResult(fallbackFn({ user, hostname, cwd, line: commandString }, commandString), commandString);
      return { output: result.output, exitCode: result.exitCode, handled: false, handledBy: "engine", shouldExit: false };
    }
    const fileResult = runFileCheck(tokens, env);
    if (fileResult) return fileResult;
    const normalized = commandString.trim().replace(/\s+/g, " ");
    if (isStaticTableCommand(normalized)) {
      if (staticFirst) {
        const isPs = normalized === "ps" || normalized === "ps aux" || normalized === "ps -ef";
        const currentPsSeq = psSeq;
        if (isPs) psSeq += 1;
        const table = staticTableRespond(commandString, { user: user.name, cwd, hostname, sessionId: sessionIdValue, sourceIp: sourceIpValue, now: nowFn, psSeq: currentPsSeq, persona });
        return { output: table.output, exitCode: table.exitCode, handled: true, handledBy: "static", shouldExit: false };
      }
      const llmResult = await runLlm(commandString, signal);
      if (llmResult.handledBy === "static" && llmResult.meta === null) {
        const table = staticTableRespond(commandString, { user: user.name, cwd, hostname, sessionId: sessionIdValue, sourceIp: sourceIpValue, now: nowFn, psSeq, persona });
        if (normalized === "ps" || normalized === "ps aux" || normalized === "ps -ef") psSeq += 1;
        return { output: table.output, exitCode: table.exitCode, handled: true, handledBy: "static", shouldExit: false };
      }
      if (normalized === "ps" || normalized === "ps aux" || normalized === "ps -ef") psSeq += 1;
      return llmResult;
    }
    const llmResult = await runLlm(commandString, signal);
    return llmResult;
  }

  async function run(line, opts) {
    const tty = Boolean(opts && opts.tty);
    const signal = opts && opts.signal ? opts.signal : null;
    if (signal && signal.aborted) {
      return { output: "", exitCode: 130, handled: true, cwd, handledBy: "aborted", shouldExit: false };
    }
    if (!line || line.trim() === "") {
      return { output: "", exitCode: 0, handled: false, cwd, handledBy: "engine", shouldExit: false };
    }
    if (isPipeToShell(line) && !line.includes(";") && !line.includes("&&") && !line.includes("||")) {
      return { output: "", exitCode: 0, handled: true, cwd, handledBy: "engine", shouldExit: false };
    }
    const redirect = parseRedirect(line);
    if (redirect && !line.includes(";") && !line.includes("&&") && !line.includes("||")) {
      const result = runRedirect(redirect, tty);
      return { ...result, cwd };
    }
    const parts = splitCommands(line);
    let output = "";
    let exitCode = 0;
    let handled = false;
    let handledBy = "engine";
    let shouldExit = false;
    let ran = false;
    let transfer = null;
    let lastMeta = null;
    for (const part of parts) {
      if (part.operator === "&&" && exitCode !== 0) continue;
      if (part.operator === "||" && exitCode === 0) continue;
      if (part.command.trim() === "") continue;
      ran = true;
      let single;
      const partTrim = part.command.trim();
      if (isPipeToShell(partTrim)) {
        single = { output: "", exitCode: 0, handled: true, handledBy: "engine", shouldExit: false };
      } else {
        const partRedirect = parseRedirect(part.command);
        if (partRedirect) {
          single = runRedirect(partRedirect, tty);
        } else if (hasUnsupportedSyntax(part.command)) {
          single = await runLlm(part.command, signal);
        } else {
          single = await runSingle(part.command, tty, signal);
        }
      }
      if (single.handledBy === "aborted") {
        return { output: "", exitCode: 130, handled: true, cwd, handledBy: "aborted", shouldExit: false };
      }
      output += single.output;
      exitCode = single.exitCode;
      handled = handled || single.handled;
      handledBy = single.handledBy || "engine";
      if (single.transfer) transfer = single.transfer;
      if (single.meta) lastMeta = single.meta;
      if (single.shouldExit) {
        shouldExit = true;
        break;
      }
      if (single.transfer && single.transfer.savedAs && single.exitCode === 0) {
        addNote(`downloaded ${single.transfer.savedAs} in ${cwd}`);
      }
      if (single.meta && (single.handledBy === "llm" || single.handledBy === "cache" || single.handledBy === "mock")) {
        const tokens = tokenize(part.command).map((token) => expandToken(token, { home, user: user.name, pwd: cwd }));
        const cmdName = tokens[0];
        if (user.name === "root" && ["apt", "apt-get", "yum", "dnf"].includes(cmdName) && single.exitCode === 0) {
          const installIndex = tokens.indexOf("install");
          if (installIndex >= 0) {
            const pkgs = tokens.slice(installIndex + 1).filter((arg) => !arg.startsWith("-"));
            if (pkgs.length > 0) addNote(`installed: ${pkgs.join(" ")}`);
          }
        }
      }
    }
    if (!ran) {
      return { output: "", exitCode: 0, handled: false, cwd, handledBy: "engine", shouldExit: false };
    }
    const result = { output, exitCode, handled, cwd, handledBy, shouldExit };
    if (transfer) result.transfer = transfer;
    if (lastMeta) result.meta = lastMeta;
    return result;
  }

  return { run, prompt, cwd: () => cwd, getNotes };
}
