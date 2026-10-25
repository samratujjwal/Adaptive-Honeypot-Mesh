export const MAX_INPUT_LINE = 4096;
export const MAX_SESSION_INPUT_BYTES = 1024 * 1024;

/**
 * Create a shell session handler for one authenticated stream. The
 * handler echoes input, edits lines with backspace, and turns each
 * completed line into a command record. It never runs a command.
 *
 * @param {object} options
 * @param {import("node:stream").Writable} options.stream
 * @param {string} options.username
 * @param {string} options.hostname
 * @param {string} options.sourceIp
 * @param {(event: object) => void} options.onCommand
 * @param {() => void} options.onLogout
 * @param {(bytes: number) => void} [options.onBytesOut]
 * @returns {{ handleData: (data: Buffer) => void, prompt: () => void }}
 */
export function createShellSession({ stream, username, hostname, sourceIp, onCommand, onLogout, onBytesOut }) {
  const promptText = username === "root" ? `root@${hostname}:~# ` : `${username}@${hostname}:~$ `;
  let line = "";
  let keystrokeCount = 0;
  let usedBackspace = false;
  let truncated = false;
  let lineStartMs = null;
  let totalInputBytes = 0;
  let escapeState = 0;
  let lastWasEnter = false;

  function write(data) {
    const text = String(data);
    if (onBytesOut) onBytesOut(Buffer.byteLength(text, "utf8"));
    stream.write(text);
  }

  function showPrompt() {
    write(promptText);
  }

  function resetLine() {
    line = "";
    keystrokeCount = 0;
    usedBackspace = false;
    truncated = false;
    lineStartMs = null;
  }

  function finishLine() {
    const command = line;
    const count = keystrokeCount;
    const backspaced = usedBackspace;
    const wasTruncated = truncated;
    const duration = lineStartMs === null ? 0 : Date.now() - lineStartMs;
    resetLine();
    if (command === "") {
      showPrompt();
      return;
    }
    const trimmed = command.trim();
    if (trimmed === "exit" || trimmed === "logout") {
      onLogout();
      return;
    }
    const firstWord = trimmed.split(/\s+/)[0];
    onCommand({
      command,
      source: "shell",
      keystrokeCount: count,
      typingDurationMs: duration,
      usedBackspace: backspaced,
      truncated: wasTruncated,
    });
    write(`bash: ${firstWord}: command not found\r\n`);
    showPrompt();
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
        write("^C\r\n");
        resetLine();
        showPrompt();
        continue;
      }
      if (byte === 0x04) {
        if (line === "") {
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
    write(`Last login: ${new Date().toString()} from ${sourceIp}\r\n`);
    showPrompt();
  }

  return { handleData, prompt: showPrompt, welcome };
}
