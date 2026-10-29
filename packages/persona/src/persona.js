import { createHash } from "node:crypto";

const COMPANY_FIRST = ["Northgate", "Harborline", "Meridian", "Cobalt", "Ridgeway", "Silverline", "Westbrook", "Clearwater", "Ironbridge", "Stonefield", "Bluepeak", "Summit", "Riverstone", "Oakridge", "Copperfield", "Lakeside"];
const COMPANY_SECOND = ["Logistics", "Consulting", "Partners", "Solutions", "Freight", "Advisory", "Holdings", "Services", "Transit", "Supply"];
const TAGLINES = ["Moving goods, keeping promises.", "Practical advice, delivered on time.", "Supply chains that stay on schedule.", "Trusted partners for complex operations.", "Clear plans for busy teams."];
const FIRST_NAMES = ["Aarav", "Maya", "Liam", "Sofia", "Noah", "Elena", "Omar", "Priya", "Lucas", "Nina", "Arjun", "Clara", "Felix", "Ivy", "Rohan", "Tara"];
const LAST_NAMES = ["Sharma", "Patel", "Garcia", "Kim", "Novak", "Singh", "Meyer", "Ali", "Costa", "Rossi", "Kaur", "Larsen", "Okafor", "Weber", "Das", "Fischer"];
const THEMES = ["Meridian", "Cobalt", "Ridgeway", "Northlight", "Stonefield"];

function hashBytes(seed, counter) {
  return createHash("sha256").update(`${seed}:${counter}`).digest();
}

function prng(seed) {
  let counter = 0;
  let buffer = Buffer.alloc(0);
  let offset = 0;
  function nextByte() {
    if (offset >= buffer.length) {
      buffer = hashBytes(seed, counter);
      counter += 1;
      offset = 0;
    }
    const value = buffer[offset];
    offset += 1;
    return value;
  }
  function nextInt(max) {
    if (max <= 0) return 0;
    let value = 0;
    for (let i = 0; i < 4; i += 1) value = value * 256 + nextByte();
    return value % max;
  }
  function pick(list) {
    return list[nextInt(list.length)];
  }
  function hex(count) {
    let out = "";
    while (out.length < count) out += nextByte().toString(16).padStart(2, "0");
    return out.slice(0, count);
  }
  return { nextInt, pick, hex };
}

function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

/**
 * Create a deterministic persona from a seed. No randomness, no clock.
 *
 * @param {object} [options]
 * @param {string} [options.nodeId]
 * @param {string} [options.seed]
 * @param {string} [options.hostname]
 * @param {string} [options.domain]
 * @returns {object} frozen persona
 */
export function createPersona(options = {}) {
  const seed = options.seed || "change-me-default-seed";
  const rng = prng(seed);
  const companyName = `${rng.pick(COMPANY_FIRST)} ${rng.pick(COMPANY_SECOND)}`;
  const slug = slugify(companyName);
  const domain = options.domain || `${slug}-group.net`;
  const hostname = options.hostname || `${slug}-srv-01`;
  const tagline = rng.pick(TAGLINES);
  const privateIp = `10.${rng.nextInt(200) + 10}.${rng.nextInt(200)}.${rng.nextInt(200) + 10}`;
  const mac = `02:${rng.hex(2)}:${rng.hex(2)}:${rng.hex(2)}:${rng.hex(2)}:${rng.hex(2)}`;
  const bootDays = rng.nextInt(700);
  let bootDate = new Date(Date.UTC(2023, 0, 1) + bootDays * 86400000 + 6 * 3600000 + 12 * 60000);
  if (options.now !== undefined && options.now !== null) {
    const nowMs = typeof options.now === "function" ? options.now() : (options.now instanceof Date ? options.now.getTime() : Number(options.now));
    const bootRng = prng(`${seed}:boot-time`);
    const daysAgo = 40 + bootRng.nextInt(51);
    bootDate = new Date(nowMs - daysAgo * 86400000);
  }
  const bootTime = bootDate.toISOString().replace(/\.\d+Z$/, "Z");
  const pid = (base) => base + rng.nextInt(40);
  const sshdPid = pid(320);
  const nginxPid = pid(500);
  const postgresPid = pid(280);
  const vsftpdPid = pid(600);
  const phpfpmPid = pid(400);
  const processes = [
    { pid: 1, user: "root", ppid: 0, cpu: "0.0", mem: "0.4", vsz: 168120, rss: 9324, tty: "?", stat: "Ss", time: "0:02", command: "/sbin/init" },
    { pid: 2, user: "root", ppid: 0, cpu: "0.0", mem: "0.0", vsz: 0, rss: 0, tty: "?", stat: "S", time: "0:00", command: "[kthreadd]" },
    { pid: pid(190), user: "root", ppid: 1, cpu: "0.0", mem: "0.1", vsz: 18900, rss: 2100, tty: "?", stat: "Ss", time: "0:00", command: "/usr/sbin/cron -f" },
    { pid: pid(200), user: "syslog", ppid: 1, cpu: "0.0", mem: "0.2", vsz: 22400, rss: 3200, tty: "?", stat: "Ss", time: "0:01", command: "/usr/sbin/rsyslogd -n" },
    { pid: pid(220), user: "root", ppid: 1, cpu: "0.0", mem: "0.2", vsz: 20100, rss: 2800, tty: "?", stat: "Ss", time: "0:00", command: "/lib/systemd/systemd-journald" },
    { pid: postgresPid, user: "postgres", ppid: 1, cpu: "0.0", mem: "0.5", vsz: 152000, rss: 9800, tty: "?", stat: "S", time: "0:03", command: "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main" },
    { pid: sshdPid, user: "root", ppid: 1, cpu: "0.0", mem: "0.1", vsz: 12180, rss: 2340, tty: "?", stat: "Ss", time: "0:00", command: "/usr/sbin/sshd -D" },
    { pid: nginxPid, user: "root", ppid: 1, cpu: "0.0", mem: "0.3", vsz: 125400, rss: 6120, tty: "?", stat: "S", time: "0:01", command: "nginx: master process /usr/sbin/nginx -g daemon on;" },
    { pid: nginxPid + 1, user: "www-data", ppid: nginxPid, cpu: "0.0", mem: "0.2", vsz: 125400, rss: 4100, tty: "?", stat: "S", time: "0:00", command: "nginx: worker process" },
    { pid: nginxPid + 2, user: "www-data", ppid: nginxPid, cpu: "0.0", mem: "0.2", vsz: 125400, rss: 4100, tty: "?", stat: "S", time: "0:00", command: "nginx: worker process" },
    { pid: phpfpmPid, user: "www-data", ppid: 1, cpu: "0.0", mem: "0.3", vsz: 98000, rss: 5400, tty: "?", stat: "S", time: "0:01", command: "php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)" },
    { pid: vsftpdPid, user: "root", ppid: 1, cpu: "0.0", mem: "0.1", vsz: 32000, rss: 2800, tty: "?", stat: "Ss", time: "0:00", command: "/usr/sbin/vsftpd /etc/vsftpd.conf" },
  ];
  const systemUsers = [
    { username: "root", uid: 0, gid: 0, home: "/root", shell: "/bin/bash", gecos: "root" },
    { username: "daemon", uid: 1, gid: 1, home: "/usr/sbin", shell: "/usr/sbin/nologin", gecos: "daemon" },
    { username: "bin", uid: 2, gid: 2, home: "/bin", shell: "/usr/sbin/nologin", gecos: "bin" },
    { username: "sys", uid: 3, gid: 3, home: "/dev", shell: "/usr/sbin/nologin", gecos: "sys" },
    { username: "www-data", uid: 33, gid: 33, home: "/var/www", shell: "/usr/sbin/nologin", gecos: "www-data" },
    { username: "sshd", uid: 110, gid: 65534, home: "/run/sshd", shell: "/usr/sbin/nologin", gecos: "" },
    { username: "postgres", uid: 112, gid: 115, home: "/var/lib/postgresql", shell: "/bin/bash", gecos: "PostgreSQL administrator" },
    { username: "ftp", uid: 113, gid: 115, home: "/srv/ftp", shell: "/usr/sbin/nologin", gecos: "ftp daemon" },
    { username: "ubuntu", uid: 1000, gid: 1000, home: "/home/ubuntu", shell: "/bin/bash", gecos: "Ubuntu" },
  ];
  const staff = [];
  for (let i = 0; i < 3; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const login = first.toLowerCase();
    staff.push({ username: login, uid: 1001 + i, gid: 1001 + i, home: `/home/${login}`, shell: "/bin/bash", gecos: `${first} ${last}` });
  }
  const users = [...systemUsers, ...staff];
  const listening = [
    { proto: "tcp", address: "0.0.0.0", port: 21, pid: vsftpdPid, program: "vsftpd" },
    { proto: "tcp", address: "0.0.0.0", port: 22, pid: sshdPid, program: "sshd" },
    { proto: "tcp", address: "0.0.0.0", port: 80, pid: nginxPid, program: "nginx" },
    { proto: "tcp", address: "0.0.0.0", port: 443, pid: nginxPid, program: "nginx" },
    { proto: "tcp", address: "127.0.0.1", port: 5432, pid: postgresPid, program: "postgres" },
  ];
  const diskSize = 30 + rng.nextInt(30);
  const diskUsed = 8 + rng.nextInt(10);
  const memTotal = 3800 + rng.nextInt(400);
  const prevRng = prng(`${seed}:previous-login`);
  const bootMs = Date.parse(bootTime);
  const prevDays = prevRng.nextInt(20) + 1;
  const prevSeconds = prevRng.nextInt(86400);
  const previousLogin = {
    time: new Date(bootMs + prevDays * 86400000 + prevSeconds * 1000).toISOString().replace(/\.\d+Z$/, "Z"),
    sourceIp: `10.8.0.${prevRng.nextInt(200) + 2}`,
  };
  const persona = {
    seed,
    nodeId: options.nodeId || "node-01",
    company: {
      name: companyName,
      slug,
      tagline,
      domain,
      adminEmail: `admin@${domain}`,
      address: `${10 + rng.nextInt(90)} Harbor Road, Suite ${rng.nextInt(20) + 1}`,
    },
    host: {
      hostname,
      os: "Ubuntu 22.04.3 LTS",
      kernel: "5.15.0-91-generic",
      privateIp,
      mac,
      bootTime,
      previousLogin,
    },
    versions: {
      openssh: "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
      nginx: "nginx/1.18.0 (Ubuntu)",
      vsftpd: "3.0.5",
      postgres: "14.10",
      php: "8.1.2",
      wordpress: "6.4.3",
    },
    users,
    staff,
    processes,
    listening,
    disk: [
      { filesystem: "/dev/sda1", size: `${diskSize}G`, used: `${diskUsed}G`, avail: `${diskSize - diskUsed - 2}G`, use: `${Math.floor((diskUsed / diskSize) * 100)}%`, mount: "/" },
      { filesystem: "tmpfs", size: "1.9G", used: "0", avail: "1.9G", use: "0%", mount: "/dev/shm" },
    ],
    memory: {
      memTotal, memUsed: 1100 + rng.nextInt(300), memFree: 800 + rng.nextInt(200), memShared: 120, memBuffCache: 1700 + rng.nextInt(200), memAvailable: 2300 + rng.nextInt(200),
      swapTotal: 2048, swapUsed: 0, swapFree: 2048,
      memTotalH: "3.8Gi", memUsedH: "1.2Gi", memFreeH: "869Mi", memSharedH: "120Mi", memBuffCacheH: "1.8Gi", memAvailableH: "2.4Gi",
      swapTotalH: "2.0Gi", swapUsedH: "0B", swapFreeH: "2.0Gi",
    },
    loadAverage: "0.12, 0.08, 0.05",
    web: {
      dbName: `${slug.replace(/-/g, "_")}_wp`,
      dbUser: `${slug.replace(/-/g, "_")}_user`,
      dbHost: "localhost",
      tablePrefix: "wp_",
      adminUser: "webmaster",
      theme: rng.pick(THEMES),
    },
  };
  return Object.freeze(JSON.parse(JSON.stringify(persona)));
}

/**
 * Convert a persona to the old static-facts shape used by static answers.
 *
 * @param {object} persona
 * @returns {object} facts
 */
export function personaToFacts(persona) {
  const parts = persona.host.privateIp.split(".");
  const broadcast = `${parts[0]}.${parts[1]}.${parts[2]}.255`;
  return {
    bootTime: persona.host.bootTime,
    processes: persona.processes,
    listening: persona.listening,
    interfaces: [
      { name: "lo", mtu: 65536, ip: "127.0.0.1", prefix: 8, ip6: "::1", mac: null },
      { name: "eth0", mtu: 1500, ip: persona.host.privateIp, prefix: 24, broadcast, ip6: "fe80::a00:27ff:fe12:3456", mac: persona.host.mac },
    ],
    disk: persona.disk,
    memory: persona.memory,
    loadAverage: persona.loadAverage,
  };
}

export { COMPANY_FIRST, COMPANY_SECOND, FIRST_NAMES, LAST_NAMES };
