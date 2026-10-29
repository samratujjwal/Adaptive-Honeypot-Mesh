export const RATE_LIMIT_WINDOW_MS = 60000;
export const RATE_LIMIT_PER_SERVICE_PER_MINUTE = 60;
export const RATE_LIMIT_GLOBAL_PER_MINUTE = 120;
export const RATE_LIMIT_API_PER_MINUTE = 120;

export function createRateLimiter({ now } = {}) {
  const clock = typeof now === "function" ? now : Date.now;
  const serviceWindows = new Map();
  const globalWindows = new Map();
  const apiWindows = new Map();

  function acquire(windows, key, limit) {
    const current = clock();
    let times = windows.get(key) || [];
    times = times.filter((time) => current - time < RATE_LIMIT_WINDOW_MS);
    if (times.length >= limit) {
      windows.set(key, times);
      return { ok: false, reason: "rate_limited" };
    }
    times.push(current);
    windows.set(key, times);
    return { ok: true, reason: null };
  }

  return {
    tryAcquireService: (ip, service) => acquire(serviceWindows, `${service}:${ip}`, RATE_LIMIT_PER_SERVICE_PER_MINUTE),
    tryAcquireGlobal: (ip) => acquire(globalWindows, ip, RATE_LIMIT_GLOBAL_PER_MINUTE),
    tryAcquireApi: (ip) => acquire(apiWindows, ip, RATE_LIMIT_API_PER_MINUTE),
  };
}
