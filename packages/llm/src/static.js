const STATIC = {
  "ps aux": "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot           1  0.0  0.4 168120  9324 ?        Ss   Mar05   0:02 /sbin/init\nroot         342  0.0  0.1  12180  2340 ?        Ss   Mar05   0:00 /usr/sbin/sshd -D\nwww-data     512  0.0  0.3  125400  6120 ?        S    Mar05   0:01 nginx: worker process\nubuntu       890  0.0  0.2  15800  4100 pts/0    Ss   10:20   0:00 -bash\n",
  "ps -ef": "UID          PID    PPID  C STIME TTY          TIME CMD\nroot           1       0  0 Mar05 ?        00:00:02 /sbin/init\nroot         342       1  0 Mar05 ?        00:00:00 /usr/sbin/sshd -D\nwww-data     512       1  0 Mar05 ?        00:00:01 nginx: worker process\nubuntu       890     342  0 10:20 pts/0    00:00:00 -bash\n",
  "netstat -tulpn": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      342/sshd\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      512/nginx\ntcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      512/nginx\n",
  "netstat -ant": "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\ntcp        0      0 10.0.0.15:22            10.0.0.5:54321           ESTABLISHED\n",
  "ss -tuln": "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\ntcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*\ntcp   LISTEN 0      128    0.0.0.0:80         0.0.0.0:*\ntcp   LISTEN 0      128    0.0.0.0:443        0.0.0.0:*\n",
  ifconfig: "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255\n        inet6 fe80::a00:27ff:fe12:3456  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:12:34:56  txqueuelen 1000  (Ethernet)\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n",
  "ip a": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n    inet 10.0.0.15/24 brd 10.0.0.255 scope global eth0\n",
  "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   12G   26G  32% /\ntmpfs           1.9G     0  1.9G   0% /dev/shm\n",
  "free -m": "               total        used        free      shared  buff/cache   available\nMem:            3932        1210         890         120        1832        2450\nSwap:           2048           0        2048\n",
  "free -h": "               total        used        free      shared  buff/cache   available\nMem:           3.8Gi       1.2Gi       869Mi       120Mi       1.8Gi       2.4Gi\nSwap:          2.0Gi          0B       2.0Gi\n",
  uptime: " 10:21:01 up 12 days,  3:14,  1 user,  load average: 0.12, 0.08, 0.05\n",
  w: " 10:21:01 up 12 days,  3:14,  1 user,  load average: 0.12, 0.08, 0.05\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nubuntu   pts/0    10.0.0.5         10:20    0.00s  0.02s  0.00s w\n",
  who: "ubuntu   pts/0        2024-03-05 10:20 (10.0.0.5)\n",
  date: "Tue Mar  5 10:21:01 UTC 2024\n",
  history: "",
};

/**
 * Return a canned, fictional, persona-consistent output for a
 * command. Never executes anything; pure data.
 *
 * @param {string} command
 * @param {object} [ctx]
 * @returns {{ output: string, exitCode: number }}
 */
export function staticRespond(command, ctx) {
  const normalized = String(command || "").trim().replace(/\s+/g, " ");
  if (Object.prototype.hasOwnProperty.call(STATIC, normalized)) {
    return { output: STATIC[normalized], exitCode: 0 };
  }
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
