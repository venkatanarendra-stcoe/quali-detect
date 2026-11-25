import { QUEUE_NAMES } from "@qmentisai/contracts";
import { createDbClient, createFindingsAgentRepository } from "@qmentisai/db";
import {
  closeRedis,
  createPublisher,
  createRabbitConnection,
  createRateLimiter,
  createRedisClient,
  pingRedis,
} from "@qmentisai/infra";
import { runWorker } from "../runtime/run-worker.js";
import { buildAdvisoryCompletedEnvelope } from "./completed.js";
import { createFindingsAgentHandler } from "./handler.js";
import { createRedisTenantRateLimiter } from "./rate-limit.js";
import { createFindingsAgentRuntime } from "./runtime.js";

/**
 * Entry point of the findings-agent worker (docs/modules/findings/SPEC.md 9.2, 9.3). This file is the ONE binding point of the
 * advisory agent (the import-graph check allows `@qmentisai/db` here and nowhere else in this directory): it builds the restricted
 * repository, the provider runtime, the Redis rate limiter and the realtime hint publisher, and hands the handler to the shared worker
 * runtime. The agent code itself (`advise.js`, `handler.js`, ...) never sees a database client.
 *
 * Starts ONLY when `FINDINGS_AGENT_ENABLED=true` (default off). The agent's database connection is `FINDINGS_AGENT_DATABASE_URL`, the
 * restricted login role of owner decision OD-9 (SELECT on the `fp_agent_findings` view, SELECT and INSERT on `finding_ai_advisories`,
 * SELECT on `tenant_llm_settings`, nothing else). In production the worker REFUSES to start without it; in development, when it is
 * unset, the shared pool is used (still only through the five-method repository) and a warning is logged. The shared pool is also what
 * the runtime uses for message idempotency and the ownership check, which are not the agent's reads.
 */
const WORKER_NAME = "findings-agent";

/**
 * @param {{ NODE_ENV?: string, FINDINGS_AGENT_ENABLED?: string, FINDINGS_AGENT_DATABASE_URL?: string }} [env]
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
async function start(env = process.env) {
  if (env.FINDINGS_AGENT_ENABLED !== "true") {
    console.log(
      "The findings agent worker is disabled (FINDINGS_AGENT_ENABLED is not true); nothing started.",
    );
    return { stop: async () => {} };
  }
  if (env.NODE_ENV === "production" && !env.FINDINGS_AGENT_DATABASE_URL) {
    console.error(
      "Invalid environment configuration:\n  - FINDINGS_AGENT_DATABASE_URL: required in production (the restricted qm_fp_agent login role)",
    );
    process.exit(1);
  }
  /** Resources the handler owns; closed by the stop hook. */
  const owned = [];
  /** Checks that must pass before the consumer starts (the Redis client is lazy: it must be connected, like every other worker's). */
  const startupChecks = [];
  const build = ({ db, config, logger }) => {
    const restricted = config.findings.agentDatabaseUrl
      ? createDbClient({ datasourceUrl: config.findings.agentDatabaseUrl })
      : null;
    if (restricted) owned.push(() => restricted.$disconnect());
    else
      logger.warn(
        "FINDINGS_AGENT_DATABASE_URL is not set: the advisory agent uses the shared database pool (development only; production refuses to start)",
      );
    const repository = createFindingsAgentRepository({ db: restricted ?? db });
    const llm = createFindingsAgentRuntime({ repository, config, logger });

    let rateLimiter;
    if (config.redisUrl) {
      const redis = createRedisClient({
        url: config.redisUrl,
        name: "qmentisai-worker-findings-agent",
        logger,
      });
      owned.push(() => closeRedis(redis));
      startupChecks.push(() => pingRedis(redis));
      rateLimiter = createRedisTenantRateLimiter({ limiter: createRateLimiter({ redis }) });
    } else {
      logger.warn("REDIS_URL is not set: the advisory rate limit is per process (development)");
    }

    // The completed hint goes STRAIGHT to the broker (SPEC 0.5 "Found while building A0", item 1): the agent's database role has no
    // write grant for the transactional table that carries events, by design. A failed hint is only a missed refresh.
    const connection = createRabbitConnection({ url: config.rabbitmqUrl, logger });
    const publisher = createPublisher({ connection, logger, retryPolicy: config.retryPolicy });
    owned.push(
      () => publisher.close(),
      () => connection.close(),
    );
    const publishCompleted = (hint) =>
      publisher.publish({
        queue: QUEUE_NAMES.REALTIME,
        envelope: buildAdvisoryCompletedEnvelope(hint),
      });
    return createFindingsAgentHandler({ repository, llm, config, rateLimiter, publishCompleted });
  };

  const worker = await runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.FINDINGS_AGENT,
    buildHandler: build,
    verifyOwnership: true,
    beforeStart: async () => {
      for (const check of startupChecks) await check();
    },
  });
  // A signal makes the runtime stop its consumers and exit the process (which ends these resources); a programmatic stop closes them
  // AFTER the in-flight jobs finish.
  return {
    stop: async () => {
      await worker.stop();
      for (const close of owned.reverse()) await close().catch(() => {});
    },
  };
}

await start();
