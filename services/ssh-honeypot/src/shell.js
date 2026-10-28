export const MAX_INPUT_LINE = 4096;
export const MAX_SESSION_INPUT_BYTES = 1024 * 1024;

/**
 * Create a shell session handler for one authenticated stream. The
 * handler echoes input, edits lines with backspace, queues input
 * typed while a command is pending, and turns each completed line
 * into an async command run through the session engine.
 *
 * @param {object} options
 * @param {import("node:stream").Writable} options.stream
 * @param {string} options.username
 * @param {string} options.hostname
 * @param {string} options.sourceIp
 * @param {object} options.engine
 * @param {(event: object) => void} options.onCommand
 * @param {() => void} options.onLogout
 * @param {(bytes: number) => void} [options.onBytesOut]
 * @param {number} [options.maxPendingInput]
 * @param {(pending: boolean) => void} [options.onPendingChange]
 * @returns {{ handleData: (data: Buffer) => void, prompt: () => void, welcome: () => void, isPending: () => boolean }}
 */
export function formatLastLogin(date) {
  const d = date instanceof Date ? date : new Date(date);
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const pad = (n) => String(n).padStart(2, "0");
  const padDay = String(d.getUTCDate()).padStart(2, " ");
  return `${days[d.getUTCDay()]} ${months[d.getUTCMonth()]} ${padDay} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} ${d.getUTCFullYear()}`;
}

export function createShellSession({ stream, username, hostname, sourceIp, engine, onCommand, onLogout, onBytesOut, maxPendingInput, onPendingChange, lastLogin }) {
  let line = "";
  let keystrokeCount = 0;
  let usedBackspace = false;
  let truncated = false;
  let lineStartMs = null;
  let totalInputBytes = 0;
  let escapeState = 0;
  let lastWasEnter = false;
  let pending = false;
  let pendingController = null;
  let suppressPrompt = false;
  let queue = [];
  let queuedBytes = 0;
  let pendingDropped = false;
  const pendingCap = typeof maxPendingInput === "number" ? maxPendingInput : 4096;

  function write(data) {
    const text = String(data);
    if (onBytesOut) onBytesOut(Buffer.byteLength(text, "utf8"));
    stream.write(text);
  }

  function showPrompt() {
    write(engine.prompt());
  }

  function resetLine() {
    line = "";
    keystrokeCount = 0;
    usedBackspace = false;
    truncated = false;
    lineStartMs = null;
  }

  function setPending(value) {
    if (pending === value) return;
    pending = value;
    if (typeof onPendingChange === "function") {
      try {
        onPendingChange(value);
      } catch {
        /* Idle handling must never break the shell. */
      }
    }
  }

  async function runCommand(command, metadata) {
    const controller = new AbortController();
    pendingController = controller;
    setPending(true);
    let result;
    try {
      result = await engine.run(command, { tty: true, signal: controller.signal });
    } catch {
      result = { output: "", exitCode: 1, handled: false, cwd: engine.cwd(), handledBy: "engine", shouldExit: false };
    } finally {
      pendingController = null;
      setPending(false);
    }
    const wasSuppressed = suppressPrompt;
    if (wasSuppressed) suppressPrompt = false;
    const record = {
      command,
      source: "shell",
      keystrokeCount: metadata.keystrokeCount,
      typingDurationMs: metadata.typingDurationMs,
      usedBackspace: metadata.usedBackspace,
      truncated: metadata.truncated || pendingDropped,
      cwd: result.cwd,
      handled: result.handled,
      exitCode: result.exitCode,
      handledBy: result.handledBy || "engine",
    };
    if (result.meta) record.llmMeta = result.meta;
    if (result.transfer) record.transfer = result.transfer;
    record.output = result.output || "";
    if (pendingDropped) pendingDropped = false;
    onCommand(record);
    if (result.shouldExit) {
      onLogout();
      return;
    }
    if (result.handledBy === "aborted") {
      if (!wasSuppressed) {
        write("^C\r\n");
        showPrompt();
      }
      processQueue();
      return;
    }
    const output = result.output.replace(/\n/g, "\r\n");
    if (output !== "") write(output);
    showPrompt();
    processQueue();
  }

  function processQueue() {
    if (pending) return;
    if (queue.length === 0) return;
    const next = queue.shift();
    queuedBytes -= Buffer.byteLength(next.command, "utf8");
    if (queuedBytes < 0) queuedBytes = 0;
    void runCommand(next.command, next.metadata);
  }

  function finishLine() {
    const command = line;
    const metadata = {
      keystrokeCount,
      typingDurationMs: lineStartMs === null ? 0 : Date.now() - lineStartMs,
      usedBackspace,
      truncated,
    };
    resetLine();
    if (command === "") {
      if (!pending) showPrompt();
      return;
    }
    if (pending) {
      const bytes = Buffer.byteLength(command, "utf8");
      if (queuedBytes + bytes > pendingCap) {
        pendingDropped = true;
        return;
      }
      queue.push({ command, metadata });
      queuedBytes += bytes;
      return;
    }
    void runCommand(command, metadata);
  }

  function handleData(data) {
    totalInputBytes += data.length;
    if (totalInputBytes > MAX_SESSION_INPUT_BYTES) {
      onLogout();
      return;
    }
    for (const byte of data) {
      if (escapeState === 1) {
        if (byte === 0x5b) {
          escapeState = 2;
        } else {
          escapeState = 0;
        }
        continue;
      }
      if (escapeState === 2) {
        if (byte >= 0x40 && byte <= 0x7e) {
          escapeState = 0;
        }
        continue;
      }
      if (byte === 0x1b) {
        escapeState = 1;
        continue;
      }
      if (byte === 0x0d || byte === 0x0a) {
        if (lastWasEnter) {
          continue;
        }
        lastWasEnter = true;
        write("\r\n");
        finishLine();
        continue;
      }
      lastWasEnter = false;
      if (byte === 0x03) {
        if (pending && pendingController) {
          suppressPrompt = true;
          try {
            pendingController.abort();
          } catch {
            /* Ignore. */
          }
          queue = [];
          queuedBytes = 0;
          resetLine();
          write("^C\r\n");
          showPrompt();
          continue;
        }
        write("^C\r\n");
        resetLine();
        showPrompt();
        continue;
      }
      if (byte === 0x04) {
        if (line === "" && !pending) {
          onLogout();
        }
        continue;
      }
      if (byte === 0x09) {
        continue;
      }
      if (byte === 0x7f || byte === 0x08) {
        usedBackspace = true;
        keystrokeCount += 1;
        if (lineStartMs === null) lineStartMs = Date.now();
        if (line.length > 0) {
          line = line.slice(0, -1);
          write("\b \b");
        }
        continue;
      }
      if (byte < 0x20) {
        continue;
      }
      if (lineStartMs === null) lineStartMs = Date.now();
      keystrokeCount += 1;
      if (line.length >= MAX_INPUT_LINE) {
        truncated = true;
        continue;
      }
      const character = String.fromCharCode(byte);
      line += character;
      write(character);
    }
  }

  function welcome() {
    write("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n");
    write(" * Documentation:  https://help.ubuntu.com\r\n");
    write(" * Management:     https://landscape.canonical.com\r\n");
    const shown = lastLogin || { time: new Date().toISOString(), sourceIp };
    write(`Last login: ${formatLastLogin(shown.time)} from ${shown.sourceIp}\r\n`);
    showPrompt();
  }

  void username;
  void hostname;
  return { handleData, prompt: showPrompt, welcome, isPending: () => pending };
}
