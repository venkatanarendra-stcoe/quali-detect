const DEFAULT_TIMEOUT_MS = 2000;

/**
 * Per-app readiness registry (instance state, not module-global): modules register named async checks for their
 * dependencies (database, Redis, RabbitMQ...). `/ready` runs them all; a check passes when it resolves.
 * Usage: `readiness.register("database", async () => { await db.ping(); })`.
 * @param {{ logger: import("pino").Logger }} deps
 */
export function createReadiness({ logger }) {
  const checks = new Map();
  return Object.freeze({
    /**
     * @param {string} name
     * @param {() => Promise<unknown>} check
     */
    register(name, check) {
      if (checks.has(name)) throw new Error(`Readiness check "${name}" is already registered.`);
      checks.set(name, check);
    },
    /**
     * Runs every check with a timeout.
     * @param {{ timeoutMs?: number }} [options]
     * @returns {Promise<Array<{ name: string, status: "up" | "down" }>>}
     */
    async run({ timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
      return Promise.all(
        [...checks].map(async ([name, check]) => {
          let timer;
          try {
            await Promise.race([
              check(),
              new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
              }),
            ]);
            return { name, status: "up" };
          } catch (error) {
            logger.warn({ check: name, err: error }, "Readiness check failed");
            return { name, status: "down" };
          } finally {
            clearTimeout(timer);
          }
        }),
      );
    },
  });
}
