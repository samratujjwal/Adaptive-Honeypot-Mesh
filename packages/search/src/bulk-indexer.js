/**
 * Create a bulk indexer with retry for failed items only.
 *
 * @param {object} options
 * @param {object} options.es
 * @param {object} options.config
 * @param {object} [options.logger]
 * @param {Function} [options.now]
 * @param {Function} [options.sleep]
 * @returns {{ index: (docs: Array<object>) => Promise<object>, close: () => Promise<void> }}
 */
export function createBulkIndexer(options) {
  const es = options.es;
  const config = options.config;
  const log = options.logger || { info: () => {}, warn: () => {}, error: () => {} };
  const sleep = options.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  let closed = false;
  let backoffMs = 1000;

  async function bulkOnce(docs) {
    const body = [];
    for (const doc of docs) {
      body.push({ index: { _index: doc.index, _id: doc.id } });
      body.push(doc.body);
    }
    const response = await es.bulk({ body });
    const result = response && response.body ? response.body : response;
    const items = result && result.items ? result.items : [];
    const failed = [];
    const succeeded = [];
    for (let i = 0; i < docs.length; i += 1) {
      const item = items[i] && items[i].index ? items[i].index : {};
      if (item.error) {
        failed.push({ doc: docs[i], status: item.status, error: item.error });
      } else {
        succeeded.push(docs[i]);
      }
    }
    return { succeeded, failed };
  }

  async function index(docs) {
    let remaining = Array.isArray(docs) ? [...docs] : [];
    const rejected = [];
    let retries = 0;
    while (remaining.length > 0 && !closed) {
      let outcome;
      try {
        outcome = await bulkOnce(remaining);
      } catch (error) {
        retries += 1;
        try { log.error({ error: error && error.message ? error.message : "bulk failed", retries }, "Elasticsearch bulk failed, retrying"); } catch {}
        await sleep(backoffMs);
        backoffMs = Math.min(backoffMs * 2, 30000);
        continue;
      }
      backoffMs = 1000;
      const retryable = [];
      for (const failure of outcome.failed) {
        const status = failure.status;
        if (status === 429 || (status >= 500 && status < 600)) {
          retryable.push(failure.doc);
        } else {
          rejected.push(failure);
          try {
            const err = failure.error || {};
            log.error({ status, errorType: err.type || "error", reason: err.reason || "", index: failure.doc.index, id: failure.doc.id }, "Elasticsearch document rejected");
          } catch {}
        }
      }
      if (retryable.length === 0) {
        remaining = [];
      } else {
        retries += 1;
        remaining = retryable;
        await sleep(backoffMs);
        backoffMs = Math.min(backoffMs * 2, 30000);
      }
    }
    return { rejected, retries, remaining };
  }

  async function close() {
    closed = true;
  }

  return { index, close };
}
