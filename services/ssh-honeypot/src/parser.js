/**
 * Split a line into whitespace-separated tokens, honoring single
 * quotes, double quotes and backslash escapes. Quotes are removed;
 * escaped characters are kept literally.
 *
 * @param {string} line
 * @returns {string[]} tokens
 */
export function tokenize(line) {
  const tokens = [];
  let current = "";
  let hasToken = false;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      } else {
        current += ch;
      }
      continue;
    }
    if (inDouble) {
      if (ch === '"') {
        inDouble = false;
      } else if (ch === "\\" && i + 1 < line.length && ['"', "\\", "$", "`"].includes(line[i + 1])) {
        current += line[i + 1];
        i += 1;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      hasToken = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      hasToken = true;
      continue;
    }
    if (ch === "\\" && i + 1 < line.length) {
      current += line[i + 1];
      hasToken = true;
      i += 1;
      continue;
    }
    if (ch === " " || ch === "\t") {
      if (hasToken) {
        tokens.push(current);
        current = "";
        hasToken = false;
      }
      continue;
    }
    current += ch;
    hasToken = true;
  }
  if (hasToken) tokens.push(current);
  return tokens;
}

/**
 * Split a line on ; && || outside quotes, keeping the operator
 * that precedes each command. The first command has operator null.
 *
 * @param {string} line
 * @returns {Array<{ command: string, operator: string | null }>}
 */
export function splitCommands(line) {
  const parts = [];
  let current = "";
  let operator = null;
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
    if (ch === ";" ) {
      parts.push({ command: current, operator });
      current = "";
      operator = ";";
      continue;
    }
    if (ch === "&" && line[i + 1] === "&") {
      parts.push({ command: current, operator });
      current = "";
      operator = "&&";
      i += 1;
      continue;
    }
    if (ch === "|" && line[i + 1] === "|") {
      parts.push({ command: current, operator });
      current = "";
      operator = "||";
      i += 1;
      continue;
    }
    current += ch;
  }
  parts.push({ command: current, operator });
  return parts.filter((part, index) => index === 0 || part.command.trim() !== "" || part.operator !== null);
}

/**
 * Detect unsupported shell syntax outside quotes: single |, >,
 * >>, <, single &, backtick, $( and ${. The chaining operators
 * && and || are not unsupported.
 *
 * @param {string} line
 * @returns {boolean} true when unsupported syntax is present
 */
export function hasUnsupportedSyntax(line) {
  let inSingle = false;
  let inDouble = false;
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
    if (ch === "`") return true;
    if (ch === "$" && (line[i + 1] === "(" || line[i + 1] === "{")) return true;
    if (ch === ">" || ch === "<") return true;
    if (ch === "|" && line[i + 1] === "|") {
      i += 1;
      continue;
    }
    if (ch === "|") return true;
    if (ch === "&" && line[i + 1] === "&") {
      i += 1;
      continue;
    }
    if (ch === "&") return true;
  }
  return false;
}

/**
 * Expand a leading ~ and $HOME, $USER, $PWD in one token. Only
 * those variables expand; $ followed by a name character that
 * is not one of them is left alone.
 *
 * @param {string} token
 * @param {object} env
 * @param {string} env.home
 * @param {string} env.user
 * @param {string} env.pwd
 * @returns {string} expanded token
 */
export function expandToken(token, env) {
  let out = token;
  if (out === "~") return env.home;
  if (out.startsWith("~/")) out = env.home + out.slice(1);
  out = out.replace(/\$HOME(?![A-Za-z0-9_])/g, env.home);
  out = out.replace(/\$USER(?![A-Za-z0-9_])/g, env.user);
  out = out.replace(/\$PWD(?![A-Za-z0-9_])/g, env.pwd);
  return out;
}
