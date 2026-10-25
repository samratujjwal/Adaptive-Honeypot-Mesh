/**
 * Pure-data wget/curl emulation. Never opens a socket, never
 * calls fetch, never resolves DNS, never reads the host.
 *
 * @param {string} urlText
 * @returns {{ ok: boolean, protocol: string, host: string, path: string } | { ok: false, reason: string }}
 */
export function parseTransferUrl(urlText) {
  if (typeof urlText !== "string" || urlText.length === 0 || urlText.length > 2048) {
    return { ok: false, reason: "bad_url" };
  }
  let parsed;
  try {
    parsed = new URL(urlText);
  } catch {
    return { ok: false, reason: "bad_url" };
  }
  const protocol = parsed.protocol.replace(":", "");
  if (!["http", "https", "ftp"].includes(protocol)) return { ok: false, reason: "bad_scheme" };
  if (!parsed.hostname) return { ok: false, reason: "bad_url" };
  const path = parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : "/";
  return { ok: true, protocol, host: parsed.hostname, path };
}

function basenameFromPath(path) {
  const parts = path.split("/").filter((part) => part !== "");
  if (parts.length === 0) return "index.html";
  const last = parts[parts.length - 1];
  return last === "" ? "index.html" : last;
}

function fictionalSize(urlText) {
  return 1024 + ((urlText.length * 37) % 50000);
}

/**
 * Emulate wget. Returns output, exit code, saved file info and
 * transfer metadata, or an error result. No I/O happens here;
 * the caller creates the placeholder file in the vfs.
 *
 * @param {string[]} args
 * @returns {{ output: string, exitCode: number, savedAs: string | null, url: string | null, tool: string, size: number }}
 */
export function emulateWget(args) {
  let quiet = false;
  let outputFile = null;
  const urls = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "-q") {
      quiet = true;
      continue;
    }
    if (arg === "-O" && i + 1 < args.length) {
      outputFile = args[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith("-O") && arg.length > 2) {
      outputFile = arg.slice(2);
      continue;
    }
    if (arg.startsWith("-")) continue;
    urls.push(arg);
  }
  if (urls.length === 0) {
    return {
      output: "wget: missing URL\nUsage: wget [OPTION]... [URL]...\nTry 'wget --help' for more information.\n",
      exitCode: 2, savedAs: null, url: null, tool: "wget", size: 0,
    };
  }
  const urlText = urls[0];
  const parsed = parseTransferUrl(urlText);
  if (!parsed.ok) {
    return { output: `wget: ${urlText}: Invalid URL\n`, exitCode: 8, savedAs: null, url: urlText, tool: "wget", size: 0 };
  }
  const savedAs = outputFile || basenameFromPath(parsed.path);
  const size = fictionalSize(urlText);
  if (quiet) {
    return { output: "", exitCode: 0, savedAs, url: urlText, tool: "wget", size };
  }
  const output = [
    `--2026-10-26 14:03:11--  ${urlText}`,
    `Resolving ${parsed.host}... 10.0.0.20`,
    `Connecting to ${parsed.host}|10.0.0.20|:80... connected.`,
    `HTTP request sent, awaiting response... 200 OK`,
    `Length: ${size} (8.0K) [text/html]`,
    `Saving to: '${savedAs}'`,
    "",
    `${savedAs}            100%[===================>]   8.00K  --.-KB/s    in 0.01s`,
    "",
    `2026-10-26 14:03:11 (${size} B/s) - '${savedAs}' saved [${size}/${size}]`,
    "",
  ].join("\n");
  return { output, exitCode: 0, savedAs, url: urlText, tool: "wget", size };
}

/**
 * Emulate curl with -O, -o or --output. Plain curl with a URL
 * is not handled here; it goes to the LLM.
 *
 * @param {string[]} args
 * @returns {{ output: string, exitCode: number, savedAs: string | null, url: string | null, tool: string, size: number } | null} null when not a download curl
 */
export function emulateCurl(args) {
  let outputFile = null;
  let useRemoteName = false;
  const urls = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "-O") {
      useRemoteName = true;
      continue;
    }
    if (arg === "-o" && i + 1 < args.length) {
      outputFile = args[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--output" && i + 1 < args.length) {
      outputFile = args[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith("--output=")) {
      outputFile = arg.slice("--output=".length);
      continue;
    }
    if (arg.startsWith("-") && arg !== "-") continue;
    urls.push(arg);
  }
  if (!outputFile && !useRemoteName) return null;
  if (urls.length === 0) {
    return { output: "curl: no URL specified!\ncurl: try 'curl --help' for more information\n", exitCode: 2, savedAs: null, url: null, tool: "curl", size: 0 };
  }
  const urlText = urls[0];
  const parsed = parseTransferUrl(urlText);
  if (!parsed.ok) {
    return { output: `curl: (3) URL rejected: Bad hostname\n`, exitCode: 3, savedAs: null, url: urlText, tool: "curl", size: 0 };
  }
  const savedAs = outputFile || basenameFromPath(parsed.path);
  const size = fictionalSize(urlText);
  const output = `  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100  ${size}  100  ${size}    0     0   8000      0 --:--:-- --:--:-- --:--:--  8000\n`;
  return { output, exitCode: 0, savedAs, url: urlText, tool: "curl", size };
}
