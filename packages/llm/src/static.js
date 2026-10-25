import { getPersonaFacts } from "./persona-facts.js";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function nowMs(ctx) {
  if (!ctx) return Date.now();
  if (typeof ctx.now === "function") return ctx.now();
  if (ctx.now instanceof Date) return ctx.now.getTime();
  if (typeof ctx.now === "number") return ctx.now;
  return Date.now();
}

function pad2(value) {
  return String(value).padStart(2, "0");
}

function sessionHash(sessionId) {
  let hash = 0;
  const text = String(sessionId || "session");
  for (const ch of text) hash = (hash * 31 + ch.charCodeAt(0)) % 100000;
  return hash;
}

function attackerPids(sessionId) {
  const hash = sessionHash(sessionId);
  const bashPid = 1000 + (hash % 8000);
  const sshdPid = bashPid > 1000 ? bashPid - 1 : 999;
  return { bashPid, sshdPid };
}

function bootStart(bootTime) {
  const date = new Date(bootTime);
  return `${MONTHS[date.getUTCMonth()]}${pad2(date.getUTCDate())}`;
}

function timeHHMM(ms) {
  const date = new Date(ms);
  return `${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}`;
}

function dateUtc(ms) {
  const date = new Date(ms);
  return `${DAYS[date.getUTCDay()]} ${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()} ${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}:${pad2(date.getUTCSeconds())} UTC ${date.getUTCFullYear()}`;
}

function uptimeText(facts, ms) {
  const boot = new Date(facts.bootTime).getTime();
  const diff = Math.max(0, ms - boot);
  const days = Math.floor(diff / 86400000);
  const hours = Math.floor((diff % 86400000) / 3600000);
  const minutes = Math.floor((diff % 3600000) / 60000);
  const time = new Date(ms);
  const clock = `${pad2(time.getUTCHours())}:${pad2(time.getUTCMinutes())}:${pad2(time.getUTCSeconds())}`;
  return ` ${clock} up ${days} days, ${hours}:${pad2(minutes)},  1 user,  load average: ${facts.loadAverage}\n`;
}

function psAux(facts, ctx, command) {
  const ms = nowMs(ctx);
  const user = (ctx && ctx.user) || "root";
  const sessionId = (ctx && ctx.sessionId) || "session";
  const { bashPid, sshdPid } = attackerPids(sessionId);
  const psSeq = ctx && typeof ctx.psSeq === "number" ? ctx.psSeq : 0;
  const psPid = bashPid + 2 + psSeq;
  const start = bootStart(facts.bootTime);
  const nowStart = timeHHMM(ms);
  let out = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n";
  for (const proc of facts.processes) {
    out += `${proc.user.padEnd(12)} ${String(proc.pid).padStart(4)} ${proc.cpu} ${proc.mem} ${String(proc.vsz).padStart(7)} ${String(proc.rss).padStart(5)} ${proc.tty.padEnd(8)} ${proc.stat.padEnd(4)} ${start} ${proc.time.padStart(5)} ${proc.command}\n`;
  }
  out += `${user.padEnd(12)} ${String(sshdPid).padStart(4)} 0.0 0.1  12180  2340 pts/0    Ss   ${nowStart}  0:00 sshd: ${user}@pts/0\n`;
  out += `${user.padEnd(12)} ${String(bashPid).padStart(4)} 0.0 0.2  15800  4100 pts/0    Ss   ${nowStart}  0:00 -bash\n`;
  out += `${user.padEnd(12)} ${String(psPid).padStart(4)} 0.0 0.1  12180  1800 pts/0    R+   ${nowStart}  0:00 ${command}\n`;
  return out;
}

function psEf(facts, ctx, command) {
  const ms = nowMs(ctx);
  const user = (ctx && ctx.user) || "root";
  const sessionId = (ctx && ctx.sessionId) || "session";
  const { bashPid, sshdPid } = attackerPids(sessionId);
  const psSeq = ctx && typeof ctx.psSeq === "number" ? ctx.psSeq : 0;
  const psPid = bashPid + 2 + psSeq;
  const start = bootStart(facts.bootTime);
  const nowStart = timeHHMM(ms);
  let out = "UID          PID    PPID  C STIME TTY          TIME CMD\n";
  for (const proc of facts.processes) {
    out += `${proc.user.padEnd(12)} ${String(proc.pid).padStart(5)} ${String(proc.ppid).padStart(5)}  0 ${start} ${proc.tty.padEnd(12)} ${proc.time.padStart(8)} ${proc.command}\n`;
  }
  out += `${user.padEnd(12)} ${String(sshdPid).padStart(5)} ${String(bashPid).padStart(5)}  0 ${nowStart} pts/0        00:00:00 sshd: ${user}@pts/0\n`;
  out += `${user.padEnd(12)} ${String(bashPid).padStart(5)} ${String(sshdPid).padStart(5)}  0 ${nowStart} pts/0        00:00:00 -bash\n`;
  out += `${user.padEnd(12)} ${String(psPid).padStart(5)} ${String(bashPid).padStart(5)}  0 ${nowStart} pts/0        00:00:00 ${command}\n`;
  return out;
}

function psPlain(facts, ctx, command) {
  const user = (ctx && ctx.user) || "root";
  const sessionId = (ctx && ctx.sessionId) || "session";
  const { bashPid } = attackerPids(sessionId);
  const psSeq = ctx && typeof ctx.psSeq === "number" ? ctx.psSeq : 0;
  const psPid = bashPid + 2 + psSeq;
  return `    PID TTY          TIME CMD\n${String(bashPid).padStart(7)} pts/0    00:00:00 -bash\n${String(psPid).padStart(7)} pts/0    00:00:00 ${command}\n`;
}

function netstatTulpn(facts) {
  let out = "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n";
  for (const entry of facts.listening) {
    out += `tcp        0      0 ${entry.address}:${entry.port}`.padEnd(34) + ` 0.0.0.0:*               LISTEN      ${entry.pid}/${entry.program}\n`;
  }
  return out;
}

function netstatAnt(facts, ctx) {
  const sourceIp = (ctx && ctx.sourceIp) || "10.0.0.5";
  let out = "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\n";
  for (const entry of facts.listening) {
    out += `tcp        0      0 ${entry.address}:${entry.port}`.padEnd(34) + ` 0.0.0.0:*               LISTEN\n`;
  }
  out += `tcp        0      0 10.0.0.15:22            ${sourceIp}:54321           ESTABLISHED\n`;
  return out;
}

function netstatTlnp(facts) {
  let out = "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n";
  for (const entry of facts.listening) {
    out += `tcp        0      0 ${entry.address}:${entry.port}`.padEnd(34) + ` 0.0.0.0:*               LISTEN      ${entry.pid}/${entry.program}\n`;
  }
  return out;
}

function ssTuln(facts) {
  let out = "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n";
  for (const entry of facts.listening) {
    out += `tcp   LISTEN 0      128    ${entry.address}:${entry.port}`.padEnd(34) + ` 0.0.0.0:*\n`;
  }
  return out;
}

function ssTulpn(facts) {
  let out = "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n";
  for (const entry of facts.listening) {
    out += `tcp   LISTEN 0      128    ${entry.address}:${entry.port}`.padEnd(34) + ` 0.0.0.0:* users:(("${entry.program}",pid=${entry.pid},fd=3))\n`;
  }
  return out;
}

function ifconfigOut(facts) {
  let out = "";
  for (const iface of facts.interfaces) {
    if (iface.name === "lo") {
      out += `lo: flags=73<UP,LOOPBACK,RUNNING>  mtu ${iface.mtu}\n        inet ${iface.ip}  netmask 255.0.0.0\n`;
    } else {
      out += `${iface.name}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu ${iface.mtu}\n        inet ${iface.ip}  netmask 255.255.255.0  broadcast ${iface.broadcast}\n        inet6 ${iface.ip6}  prefixlen 64  scopeid 0x20<link>\n        ether ${iface.mac}  txqueuelen 1000  (Ethernet)\n`;
    }
  }
  return out;
}

function ipAddr(facts) {
  let out = "";
  let index = 1;
  for (const iface of facts.interfaces) {
    if (iface.name === "lo") {
      out += `${index}: lo: <LOOPBACK,UP,LOWER_UP> mtu ${iface.mtu} qdisc noqueue state UNKNOWN\n    inet ${iface.ip}/${iface.prefix} scope host lo\n`;
    } else {
      out += `${index}: ${iface.name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu ${iface.mtu} qdisc fq_codel state UP\n    inet ${iface.ip}/${iface.prefix} brd ${iface.broadcast} scope global ${iface.name}\n`;
    }
    index += 1;
  }
  return out;
}

function dfH(facts) {
  let out = "Filesystem      Size  Used Avail Use% Mounted on\n";
  for (const entry of facts.disk) {
    out += `${entry.filesystem.padEnd(15)} ${entry.size.padStart(4)} ${entry.used.padStart(4)} ${entry.avail.padStart(5)} ${entry.use.padStart(4)} ${entry.mount}\n`;
  }
  return out;
}

function freeM(facts) {
  const m = facts.memory;
  return `               total        used        free      shared  buff/cache   available\nMem:           ${String(m.memTotal).padStart(6)} ${String(m.memUsed).padStart(11)} ${String(m.memFree).padStart(11)} ${String(m.memShared).padStart(11)} ${String(m.memBuffCache).padStart(11)} ${String(m.memAvailable).padStart(11)}\nSwap:          ${String(m.swapTotal).padStart(6)} ${String(m.swapUsed).padStart(11)} ${String(m.swapFree).padStart(11)}\n`;
}

function freeH(facts) {
  const m = facts.memory;
  return `               total        used        free      shared  buff/cache   available\nMem:           ${m.memTotalH.padStart(6)} ${m.memUsedH.padStart(11)} ${m.memFreeH.padStart(11)} ${m.memSharedH.padStart(11)} ${m.memBuffCacheH.padStart(11)} ${m.memAvailableH.padStart(11)}\nSwap:          ${m.swapTotalH.padStart(6)} ${m.swapUsedH.padStart(11)} ${m.swapFreeH.padStart(11)}\n`;
}

function wOut(facts, ctx) {
  const ms = nowMs(ctx);
  const user = (ctx && ctx.user) || "root";
  const sourceIp = (ctx && ctx.sourceIp) || "10.0.0.5";
  return uptimeText(facts, ms) + `USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n${user.padEnd(8)} pts/0    ${sourceIp.padEnd(16)} ${timeHHMM(ms)}    0.00s  0.02s  0.00s w\n`;
}

function whoOut(facts, ctx) {
  const ms = nowMs(ctx);
  const user = (ctx && ctx.user) || "root";
  const sourceIp = (ctx && ctx.sourceIp) || "10.0.0.5";
  const date = new Date(ms);
  const when = `${date.getUTCFullYear()}-${pad2(date.getUTCMonth() + 1)}-${pad2(date.getUTCDate())} ${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}`;
  return `${user}   pts/0        ${when} (${sourceIp})\n`;
}

/**
 * Check whether a normalized command is one of the supported
 * static-first table commands (exact flag variants only).
 *
 * @param {string} normalized
 * @returns {boolean}
 */
export function isStaticTableCommand(normalized) {
  const table = new Set([
    "ps", "ps aux", "ps -ef",
    "netstat -tulpn", "netstat -ant", "netstat -tlnp",
    "ss -tuln", "ss -tulpn",
    "ifconfig", "ip a", "ip addr",
    "df -h", "free -m", "free -h",
    "uptime", "w", "who", "date",
  ]);
  return table.has(normalized);
}

/**
 * Return a fictional, persona-consistent output built from the
 * single fact file. Never executes anything; pure data.
 *
 * @param {string} command
 * @param {object} [ctx]
 * @returns {{ output: string, exitCode: number } | null} null when not a static command
 */
export function staticTableRespond(command, ctx) {
  const normalized = String(command || "").trim().replace(/\s+/g, " ");
  if (!isStaticTableCommand(normalized)) return null;
  const facts = getPersonaFacts();
  const ms = nowMs(ctx);
  if (normalized === "ps") return { output: psPlain(facts, ctx, normalized), exitCode: 0 };
  if (normalized === "ps aux") return { output: psAux(facts, ctx, normalized), exitCode: 0 };
  if (normalized === "ps -ef") return { output: psEf(facts, ctx, normalized), exitCode: 0 };
  if (normalized === "netstat -tulpn") return { output: netstatTulpn(facts), exitCode: 0 };
  if (normalized === "netstat -ant") return { output: netstatAnt(facts, ctx), exitCode: 0 };
  if (normalized === "netstat -tlnp") return { output: netstatTlnp(facts), exitCode: 0 };
  if (normalized === "ss -tuln") return { output: ssTuln(facts), exitCode: 0 };
  if (normalized === "ss -tulpn") return { output: ssTulpn(facts), exitCode: 0 };
  if (normalized === "ifconfig") return { output: ifconfigOut(facts), exitCode: 0 };
  if (normalized === "ip a" || normalized === "ip addr") return { output: ipAddr(facts), exitCode: 0 };
  if (normalized === "df -h") return { output: dfH(facts), exitCode: 0 };
  if (normalized === "free -m") return { output: freeM(facts), exitCode: 0 };
  if (normalized === "free -h") return { output: freeH(facts), exitCode: 0 };
  if (normalized === "uptime") return { output: uptimeText(facts, ms), exitCode: 0 };
  if (normalized === "w") return { output: wOut(facts, ctx), exitCode: 0 };
  if (normalized === "who") return { output: whoOut(facts, ctx), exitCode: 0 };
  if (normalized === "date") return { output: dateUtc(ms) + "\n", exitCode: 0 };
  return null;
}

/**
 * Return a canned output for a command, or null when the command
 * is not handled by static. Kept for the LLM service mock mode.
 *
 * @param {string} command
 * @param {object} [ctx]
 * @returns {{ output: string, exitCode: number }}
 */
export function staticRespond(command, ctx) {
  const table = staticTableRespond(command, ctx);
  if (table) return table;
  const normalized = String(command || "").trim().replace(/\s+/g, " ");
  if (normalized === "history") return { output: "", exitCode: 0 };
  const firstWord = normalized.split(" ")[0] || "";
  if (firstWord === "wget" && normalized === "wget") {
    return { output: "wget: missing URL\nUsage: wget [OPTION]... [URL]...\nTry 'wget --help' for more information.\n", exitCode: 2 };
  }
  if (firstWord === "curl" && normalized === "curl") {
    return { output: "curl: no URL specified!\ncurl: try 'curl --help' for more information\n", exitCode: 2 };
  }
  if (firstWord === "sudo") {
    const user = ctx && ctx.user ? ctx.user : "root";
    return { output: `[sudo] password for ${user}: \nsudo: a password is required\n`, exitCode: 1 };
  }
  return { output: `bash: ${firstWord}: command not found\n`, exitCode: 127 };
}
