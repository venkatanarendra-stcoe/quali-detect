import amqplib from "amqplib";
import { childLogger } from "../logging.js";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Managed RabbitMQ connection. `ensure()` connects on demand (bounded retries with backoff) and reconnects after a
 * drop; channels are created from it. Credentials in the URL are never logged. Long-lived consumers should treat
 * `onClose` as fatal and restart the process (a supervisor restarts workers).
 * @param {{ url: string, logger?: object, heartbeatSeconds?: number, connectAttempts?: number, retryDelayMs?: number }} options
 */
export function createRabbitConnection({
  url,
  logger,
  heartbeatSeconds = 30,
  connectAttempts = 5,
  retryDelayMs = 1000,
}) {
  const log = childLogger(logger, { component: "rabbitmq" });
  let connection = null;
  let connecting = null;
  let closing = false;
  const closeListeners = new Set();

  async function connectWithRetry() {
    let lastError;
    for (let attempt = 1; attempt <= connectAttempts; attempt += 1) {
      try {
        const next = await amqplib.connect(url, { heartbeat: heartbeatSeconds });
        next.on("error", (error) => log.warn({ err: error }, "RabbitMQ connection error"));
        next.on("close", () => {
          if (connection === next) connection = null;
          if (!closing) {
            log.warn("RabbitMQ connection closed");
            for (const listener of closeListeners) listener();
          }
        });
        connection = next;
        return next;
      } catch (error) {
        lastError = error;
        log.warn({ attempt, connectAttempts, err: error }, "RabbitMQ connect failed");
        if (attempt < connectAttempts)
          await sleep(Math.min(retryDelayMs * 2 ** (attempt - 1), 10000));
      }
    }
    throw lastError;
  }

  const api = {
    /** @returns {Promise<import("amqplib").ChannelModel>} */
    async ensure() {
      if (closing) throw new Error("RabbitMQ connection is closed");
      if (connection) return connection;
      connecting ??= connectWithRetry().finally(() => {
        connecting = null;
      });
      return connecting;
    },
    /** Channel without publisher confirms (consuming). */
    async createChannel() {
      return (await api.ensure()).createChannel();
    },
    /** Channel with publisher confirms (publishing; resolves after the broker confirms). */
    async createConfirmChannel() {
      return (await api.ensure()).createConfirmChannel();
    },
    /** Readiness probe: resolves when a connection is open. */
    async ping() {
      await api.ensure();
    },
    /** @param {() => void} listener Called when the connection drops unexpectedly. @returns {() => void} unsubscribe */
    onClose(listener) {
      closeListeners.add(listener);
      return () => closeListeners.delete(listener);
    },
    async close() {
      closing = true;
      const current = connection;
      connection = null;
      if (current) await current.close().catch(() => {});
    },
  };
  return api;
}
