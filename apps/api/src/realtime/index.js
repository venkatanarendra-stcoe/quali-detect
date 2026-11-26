import { createProcessedMessageStore } from "@qmentisai/db";
import { createReportingEpochBumper } from "../modules/reporting/read-cache.js";
import { createRealtimeConsumer } from "./consumer.js";
import { createRealtimeRepository } from "./repository.js";
import { createRealtimeServer } from "./server.js";

export { createHintHandler, createHintResolver, createRealtimeConsumer } from "./consumer.js";
export { buildHint, HINT_MESSAGE_TYPES } from "./hints.js";
export { createRealtimeRepository } from "./repository.js";
export { createRealtimeServer, parseCookieHeader } from "./server.js";
export * from "./constants.js";

const RETRY_START_MS = 10_000;

/**
 * Runtime wiring of the realtime layer: the Socket.IO server plus, when RabbitMQ is configured, the `realtime` queue consumer
 * (retried in the background until the broker is reachable; the API and the sockets work without it, clients poll).
 * Returns null when REALTIME_ENABLED is off.
 * @param {{ config: any, infra: any, auth: any, authz: any, logger: import("pino").Logger }} deps
 */
export function createRealtime({ config, infra, auth, authz, logger }) {
  if (!config.realtime.enabled) return null;
  if (!infra.db) throw new Error("REALTIME_ENABLED requires DATABASE_URL.");
  const server = createRealtimeServer({ config, db: infra.db, auth, authz, logger });
  let consumer = null;
  let retryTimer = null;
  let closed = false;
  let closing = null;

  async function startConsumer() {
    if (closed || !infra.rabbit) return;
    try {
      consumer = createRealtimeConsumer({
        connection: infra.rabbit,
        repository: createRealtimeRepository({ db: infra.db }),
        realtime: server,
        idempotency: createProcessedMessageStore({ db: infra.db }),
        logger,
        // Reporting cache epoch (SPEC 17 D-4): one INCR per (tenant, workspace) on every verified finding hint
        onFindingChanged: createReportingEpochBumper({
          redis: infra.redis,
          enabled: config.reporting?.enabled === true,
          log: logger,
        }),
      });
      await consumer.start();
    } catch (error) {
      consumer = null;
      logger.error({ err: error }, "realtime: consumer could not start, retrying");
      if (!closed) {
        retryTimer = setTimeout(() => void startConsumer(), RETRY_START_MS);
        retryTimer.unref();
      }
    }
  }

  return Object.freeze({
    server,
    /** Attaches Socket.IO to the HTTP server and starts consuming hints. @param {import("node:http").Server} httpServer */
    start(httpServer) {
      server.attach(httpServer);
      void startConsumer();
    },
    /** Signal from the session service: disconnect the sockets of a revoked session or subject. */
    onSessionRevoked({ sessionId, subjectId }) {
      if (sessionId) server.disconnectSession(sessionId);
      if (subjectId) server.disconnectUser(subjectId);
    },
    /** Idempotent. */
    close() {
      closing ??= (async () => {
        closed = true;
        clearTimeout(retryTimer);
        await consumer?.stop({ timeoutMs: 5000 }).catch(() => {});
        await server.close();
      })();
      return closing;
    },
  });
}
