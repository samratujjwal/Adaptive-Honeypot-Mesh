import { io } from "socket.io-client";
import { fileURLToPath } from "node:url";

const BASE = process.argv[2] || "http://127.0.0.1:3001";

function waitFor(socket, event, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.off(event, handler);
      reject(new Error(`TIMEOUT_${event.toUpperCase()}`));
    }, timeoutMs);
    function handler(doc) {
      clearTimeout(timer);
      socket.off(event, handler);
      resolve(doc);
    }
    socket.on(event, handler);
  });
}

/**
 * Check the Day 14 API: GET /api/health, then Socket.IO hello,
 * then one live document if traffic occurs within 10 seconds.
 *
 * @param {string} base
 * @returns {Promise<void>}
 */
export async function apiCheck(base) {
  const healthResponse = await fetch(`${base}/api/health`);
  const health = await healthResponse.json();
  console.log(JSON.stringify(health));
  const socket = io(base, { transports: ["websocket", "polling"] });
  try {
    const hello = await waitFor(socket, "hello", 10000);
    console.log(JSON.stringify(hello));
    try {
      const live = await Promise.race([
        waitFor(socket, "event", 10000),
        waitFor(socket, "profile", 10000),
        waitFor(socket, "attacker", 10000),
      ]);
      console.log(JSON.stringify(live));
    } catch {
      console.log("No live document within 10 seconds.");
    }
  } finally {
    socket.disconnect();
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  apiCheck(BASE).then(() => process.exit(0)).catch((error) => {
    console.error(error.message || "API_CHECK_FAILED");
    process.exit(1);
  });
}
