export const PERSONA_FACTS = {
  bootTime: "2026-09-14T06:12:00Z",
  processes: [
    { pid: 1, user: "root", ppid: 0, cpu: "0.0", mem: "0.4", vsz: 168120, rss: 9324, tty: "?", stat: "Ss", time: "0:02", command: "/sbin/init" },
    { pid: 2, user: "root", ppid: 0, cpu: "0.0", mem: "0.0", vsz: 0, rss: 0, tty: "?", stat: "S", time: "0:00", command: "[kthreadd]" },
    { pid: 201, user: "root", ppid: 1, cpu: "0.0", mem: "0.1", vsz: 18900, rss: 2100, tty: "?", stat: "Ss", time: "0:00", command: "/usr/sbin/cron -f" },
    { pid: 210, user: "syslog", ppid: 1, cpu: "0.0", mem: "0.2", vsz: 22400, rss: 3200, tty: "?", stat: "Ss", time: "0:01", command: "/usr/sbin/rsyslogd -n" },
    { pid: 235, user: "root", ppid: 1, cpu: "0.0", mem: "0.2", vsz: 20100, rss: 2800, tty: "?", stat: "Ss", time: "0:00", command: "/lib/systemd/systemd-journald" },
    { pid: 301, user: "postgres", ppid: 1, cpu: "0.0", mem: "0.5", vsz: 152000, rss: 9800, tty: "?", stat: "S", time: "0:03", command: "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main" },
    { pid: 342, user: "root", ppid: 1, cpu: "0.0", mem: "0.1", vsz: 12180, rss: 2340, tty: "?", stat: "Ss", time: "0:00", command: "/usr/sbin/sshd -D" },
    { pid: 512, user: "root", ppid: 1, cpu: "0.0", mem: "0.3", vsz: 125400, rss: 6120, tty: "?", stat: "S", time: "0:01", command: "nginx: master process /usr/sbin/nginx -g daemon on;" },
    { pid: 513, user: "www-data", ppid: 512, cpu: "0.0", mem: "0.2", vsz: 125400, rss: 4100, tty: "?", stat: "S", time: "0:00", command: "nginx: worker process" },
    { pid: 514, user: "www-data", ppid: 512, cpu: "0.0", mem: "0.2", vsz: 125400, rss: 4100, tty: "?", stat: "S", time: "0:00", command: "nginx: worker process" },
  ],
  listening: [
    { proto: "tcp", address: "0.0.0.0", port: 22, pid: 342, program: "sshd" },
    { proto: "tcp", address: "0.0.0.0", port: 80, pid: 512, program: "nginx" },
    { proto: "tcp", address: "0.0.0.0", port: 443, pid: 512, program: "nginx" },
    { proto: "tcp", address: "127.0.0.1", port: 5432, pid: 301, program: "postgres" },
  ],
  interfaces: [
    { name: "lo", mtu: 65536, ip: "127.0.0.1", prefix: 8, ip6: "::1", mac: null },
    { name: "eth0", mtu: 1500, ip: "10.0.0.15", prefix: 24, broadcast: "10.0.0.255", ip6: "fe80::a00:27ff:fe12:3456", mac: "08:00:27:12:34:56" },
  ],
  disk: [
    { filesystem: "/dev/sda1", size: "40G", used: "12G", avail: "26G", use: "32%", mount: "/" },
    { filesystem: "tmpfs", size: "1.9G", used: "0", avail: "1.9G", use: "0%", mount: "/dev/shm" },
  ],
  memory: {
    memTotal: 3932, memUsed: 1210, memFree: 890, memShared: 120, memBuffCache: 1832, memAvailable: 2450,
    swapTotal: 2048, swapUsed: 0, swapFree: 2048,
    memTotalH: "3.8Gi", memUsedH: "1.2Gi", memFreeH: "869Mi", memSharedH: "120Mi", memBuffCacheH: "1.8Gi", memAvailableH: "2.4Gi",
    swapTotalH: "2.0Gi", swapUsedH: "0B", swapFreeH: "2.0Gi",
  },
  loadAverage: "0.12, 0.08, 0.05",
};

/**
 * Return a fresh copy of the fixed fictional facts, so callers
 * never mutate the shared object.
 *
 * @returns {object} persona facts
 */
export function getPersonaFacts() {
  return JSON.parse(JSON.stringify(PERSONA_FACTS));
}
