import { createServer } from "node:http";
import { createApp } from "./app.js";
import { ConfigError, describeConfig, loadConfig } from "./config/index.js";

const SHUTDOWN_TIMEOUT_MS = 10_000;

let config;
try {
  config = loadConfig();
} catch (error) {
  if (!(error instanceof ConfigError)) throw error;
  console.error(error.message);
  process.exit(1);
}

const { app, ctx, close, realtime } = await createApp({ config });
const log = ctx.log;

let server;
let shuttingDown = false;

/** Graceful shutdown: stop accepting connections, let in-flight requests finish, then close Prisma, Redis and RabbitMQ. */
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log.info({ signal }, "Shutting down");
  const forced = setTimeout(() => {
    log.error("Shutdown timed out; forcing exit");
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
  forced.unref();
  try {
    // WebSocket connections are not idle HTTP connections: disconnect them first or `server.close` would wait for them.
    await realtime?.close();
    if (server) {
      await new Promise((resolve) => {
        server.close(resolve);
        server.closeIdleConnections();
      });
    }
    await close();
    process.exit(0);
  } catch (error) {
    log.error({ err: error }, "Shutdown failed");
    process.exit(1);
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => void shutdown(signal));

try {
  server = await new Promise((resolve, reject) => {
    const listening = createServer(app);
    realtime?.start(listening);
    listening.once("error", reject);
    listening.listen(config.http.port, config.http.host, () => resolve(listening));
  });
  log.info(describeConfig(config), "API started");
} catch (error) {
  log.fatal({ err: error }, "API failed to start");
  await close();
  process.exit(1);
}
