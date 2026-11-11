import fp from "fastify-plugin";

const DEFAULT_TIMEOUT_MS = 2000;

/**
 * Per-app readiness registry (instance state, not module-global): modules register named async checks for their
 * dependencies (database, Redis, RabbitMQ...). `/ready` runs them all; a check passes when it resolves.
 * Usage: `app.readiness.register("database", async () => { await db.ping(); })`.
 */
export default fp(
  async function readinessPlugin(app) {
    const checks = new Map();

    app.decorate(
      "readiness",
      Object.freeze({
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
                app.log.warn({ check: name, err: error }, "Readiness check failed");
                return { name, status: "down" };
              } finally {
                clearTimeout(timer);
              }
            }),
          );
        },
      }),
    );
  },
  { name: "readiness" },
);
