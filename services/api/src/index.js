import { fileURLToPath } from "node:url";
import { config } from "../../../packages/shared/src/config.js";
import { logger } from "../../../packages/shared/src/logger.js";
import { createEsClient } from "../../../packages/search/src/es-client.js";
import { createServer } from "./server.js";

export { createServer };

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const es = createEsClient({ config, logger });
  const server = createServer({ es, logger, config });
  server.listen(config.API_PORT, config.API_HOST, () => {
    logger.info(`API listening on ${config.API_HOST}:${config.API_PORT}`);
    server.startLive();
  });
}
