import { tokenize, splitCommands, hasUnsupportedSyntax, expandToken } from "./parser.js";

const KERNEL_RELEASE = "5.15.0-91-generic";
const KERNEL_VERSION = "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023";
const MACHINE = "x86_64";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

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

/**
 * Create a command engine bound to one session's vfs copy, user
 * and hostname. The engine never touches the real filesystem.
 *
 * @param {object} options
 * @param {object} options.vfs
 * @param {object} options.user
 * @param {string} options.hostname
 * @param {(ctx: object, line: string) => object | string} [options.fallback]
 * @returns {{ run: (line: string, opts?: object) => object, prompt: () => string, cwd: () => string }}
 */
export function createCommandEngine({ vfs, user, hostname, fallback }) {
  const home = user.name === "root" ? "/root" : `/home/${user.name}`;
  let cwd = home;
  let oldpwd = null;
  const fallbackFn = typeof fallback === "function" ? fallback : defaultFallback;

  function displayPath(path) {
    if (path === home) return "~";
    if (path.startsWith(home + "/")) return "~" + path.slice(home.length);
    return path;
  }

  function prompt() {
    const marker = user.name === "root" ? "#" : "$";
    return `${user.name}@${hostname}:${displayPath(cwd)}${marker} `;
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
          sections.push(`${modeString(node)} 1 ${node.owner} ${node.group} ${flags.h ? humanSize(nodeSize(node)) : nodeSize(node)} ${formatDate(node.mtime)} ${multiple ? targetArg : targetArg.split("/").pop()}\n`);
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

  function runSingle(commandString, tty) {
    const rawTokens = tokenize(commandString);
    if (rawTokens.length === 0) {
      return { output: "", exitCode: 0, handled: false, shouldExit: false };
    }
    const env = { home, user: user.name, pwd: cwd };
    const tokens = rawTokens.map((token) => expandToken(token, env));
    const name = tokens[0];
    const args = tokens.slice(1);
    if (name === "exit" || name === "logout") {
      return { output: "", exitCode: 0, handled: true, shouldExit: true };
    }
    if (name === "pwd") return { output: cwd + "\n", exitCode: 0, handled: true, shouldExit: false };
    if (name === "cd") return { ...runCd(args), shouldExit: false };
    if (name === "ls") return { ...runLs(args, tty), shouldExit: false };
    if (name === "cat") return { ...runCat(args), shouldExit: false };
    if (name === "whoami") return { output: user.name + "\n", exitCode: 0, handled: true, shouldExit: false };
    if (name === "id") return { ...runId(args), shouldExit: false };
    if (name === "uname") return { ...runUname(args), shouldExit: false };
    if (name === "hostname") return { output: hostname + "\n", exitCode: 0, handled: true, shouldExit: false };
    if (name === "echo") return { ...runEcho(args), shouldExit: false };
    if (name === "clear") return { output: "\x1b[H\x1b[2J", exitCode: 0, handled: true, shouldExit: false };
    const result = normalizeFallbackResult(fallbackFn({ user, hostname, cwd, line: commandString }, commandString), commandString);
    return { output: result.output, exitCode: result.exitCode, handled: false, shouldExit: false };
  }

  function run(line, opts) {
    const tty = Boolean(opts && opts.tty);
    if (!line || line.trim() === "") {
      return { output: "", exitCode: 0, handled: false, cwd, shouldExit: false };
    }
    if (hasUnsupportedSyntax(line)) {
      const result = normalizeFallbackResult(fallbackFn({ user, hostname, cwd, line }, line), line);
      return { output: result.output, exitCode: result.exitCode, handled: false, cwd, shouldExit: false };
    }
    const parts = splitCommands(line);
    let output = "";
    let exitCode = 0;
    let handled = false;
    let shouldExit = false;
    let ran = false;
    for (const part of parts) {
      if (part.operator === "&&" && exitCode !== 0) continue;
      if (part.operator === "||" && exitCode === 0) continue;
      if (part.command.trim() === "") continue;
      ran = true;
      const single = runSingle(part.command, tty);
      output += single.output;
      exitCode = single.exitCode;
      handled = handled || single.handled;
      if (single.shouldExit) {
        shouldExit = true;
        break;
      }
    }
    if (!ran) {
      return { output: "", exitCode: 0, handled: false, cwd, shouldExit: false };
    }
    return { output, exitCode, handled, cwd, shouldExit };
  }

  return { run, prompt, cwd: () => cwd };
}
