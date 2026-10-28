/**
 * Wait for Kafka and Elasticsearch with backoff, then report clearly.
 *
 * @param {object} options
 * @param {Array<{ name: string, check: () => Promise<void> }>} options.checks
 * @param {object} [options.logger]
 * @param {Function} [options.sleep]
 * @param {number} [options.budgetMs]
 * @returns {Promise<void>}
 */
export async function waitForStartup(options) {
  const checks = options.checks || [];
  const log = options.logger || { info: () => {}, warn: () => {}, error: () => {} };
  const sleep = options.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const budgetMs = typeof options.budgetMs === "number" ? options.budgetMs : 60000;
  let elapsed = 0;
  let delay = 1000;
  while (true) {
    let failed = null;
    for (const check of checks) {
      try {
        await check.check();
      } catch (error) {
        failed = { name: check.name, code: error && error.code ? String(error.code) : (error && error.message ? String(error.message).split("\n")[0].slice(0, 120) : "unknown") };
        break;
      }
    }
    if (!failed) return;
    try { log.warn({ service: failed.name, code: failed.code }, `Waiting for ${failed.name}: ${failed.code}`); } catch {}
    if (elapsed + delay > budgetMs) {
      throw new Error(`Startup failed: ${failed.name} unreachable after 60s (${failed.code})`);
    }
    await sleep(delay);
    elapsed += delay;
    delay *= 2;
  }
}

/**
 * Build startup checks from the real ES and Kafka clients.
 *
 * @param {object} options
 * @param {object} options.es
 * @param {object} [options.kafkaClient]
 * @returns {Array<{ name: string, check: () => Promise<void> }>}
 */
export function createStartupChecks(options) {
  const checks = [];
  if (options.es) {
    checks.push({ name: "elasticsearch", check: async () => { await options.es.info(); } });
  }
  if (options.kafkaClient) {
    checks.push({ name: "kafka", check: async () => {
      const admin = options.kafkaClient.admin();
      try {
        await admin.connect();
        await admin.listTopics();
      } finally {
        try { await admin.disconnect(); } catch {}
      }
    } });
  }
  return checks;
}
