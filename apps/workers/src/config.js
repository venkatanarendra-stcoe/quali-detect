import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  // Redis is the idempotency store only when no database is configured; with DATABASE_URL the durable processed_messages table is used.
  REDIS_URL: z.string().url().optional(),
  RABBITMQ_URL: z.string().url(),
  DATABASE_URL: z.string().url().optional(),
  WORKER_PREFETCH: z.coerce.number().int().min(1).max(100).default(5),
  WORKER_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).default(5),
  WORKER_RETRY_BASE_DELAY_MS: z.coerce.number().int().min(1).default(1000),
  WORKER_RETRY_MAX_DELAY_MS: z.coerce.number().int().min(1).default(60000),
  WORKER_IDEMPOTENCY_TTL_SECONDS: z.coerce.number().int().min(60).default(86400),
  WORKER_SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().min(1000).default(30000),
  WORKER_CLAIM_TTL_SECONDS: z.coerce.number().int().min(10).default(900),
  // Scheduler: session purge. Expired/revoked sessions are kept this long (investigation window) before deletion.
  SCHEDULER_SESSION_PURGE_INTERVAL_SECONDS: z.coerce.number().int().min(10).default(3600),
  SCHEDULER_SESSION_RETENTION_SECONDS: z.coerce.number().int().min(0).default(86400),
  OUTBOX_BATCH_SIZE: z.coerce.number().int().min(1).max(500).default(20),
  OUTBOX_POLL_INTERVAL_MS: z.coerce.number().int().min(50).default(1000),
  OUTBOX_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10000).default(100),
  OUTBOX_RETRY_BASE_DELAY_MS: z.coerce.number().int().min(1).default(1000),
  OUTBOX_RETRY_MAX_DELAY_MS: z.coerce.number().int().min(1).default(60000),
});

/** Raised when the environment is invalid. Lists variable names and problems, never values. */
export class ConfigError extends Error {
  /** @param {Array<{ variable: string, message: string }>} problems */
  constructor(problems) {
    super(
      `Invalid environment configuration:\n${problems.map((p) => `  - ${p.variable}: ${p.message}`).join("\n")}`,
    );
    this.name = "ConfigError";
    this.problems = problems;
  }
}

/**
 * Validates the worker environment (fail fast). Pure: pass the environment explicitly.
 * @param {Record<string, string | undefined>} [env]
 */
export function loadWorkerConfig(env = process.env) {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    throw new ConfigError(
      result.error.issues.map((issue) => ({
        variable: issue.path.join(".") || "(env)",
        // Never echo the offending value (it could be a secret).
        message:
          issue.code === "invalid_enum_value"
            ? `must be one of: ${issue.options.join(", ")}`
            : issue.message,
      })),
    );
  }
  const e = result.data;
  if (e.WORKER_RETRY_MAX_DELAY_MS < e.WORKER_RETRY_BASE_DELAY_MS) {
    throw new ConfigError([
      { variable: "WORKER_RETRY_MAX_DELAY_MS", message: "must be >= WORKER_RETRY_BASE_DELAY_MS" },
    ]);
  }
  if (!e.DATABASE_URL && !e.REDIS_URL) {
    throw new ConfigError([
      { variable: "DATABASE_URL", message: "required (or REDIS_URL) for the idempotency store" },
    ]);
  }
  return Object.freeze({
    environment: e.NODE_ENV,
    logLevel: e.LOG_LEVEL,
    redisUrl: e.REDIS_URL,
    rabbitmqUrl: e.RABBITMQ_URL,
    databaseUrl: e.DATABASE_URL,
    prefetch: e.WORKER_PREFETCH,
    retryPolicy: Object.freeze({
      maxAttempts: e.WORKER_MAX_ATTEMPTS,
      baseDelayMs: e.WORKER_RETRY_BASE_DELAY_MS,
      maxDelayMs: e.WORKER_RETRY_MAX_DELAY_MS,
    }),
    idempotencyTtlSeconds: e.WORKER_IDEMPOTENCY_TTL_SECONDS,
    shutdownTimeoutMs: e.WORKER_SHUTDOWN_TIMEOUT_MS,
    claimTtlSeconds: e.WORKER_CLAIM_TTL_SECONDS,
    scheduler: Object.freeze({
      sessionPurgeIntervalSeconds: e.SCHEDULER_SESSION_PURGE_INTERVAL_SECONDS,
      sessionRetentionSeconds: e.SCHEDULER_SESSION_RETENTION_SECONDS,
    }),
    outbox: Object.freeze({
      batchSize: e.OUTBOX_BATCH_SIZE,
      pollIntervalMs: e.OUTBOX_POLL_INTERVAL_MS,
      maxAttempts: e.OUTBOX_MAX_ATTEMPTS,
      baseDelayMs: e.OUTBOX_RETRY_BASE_DELAY_MS,
      maxDelayMs: e.OUTBOX_RETRY_MAX_DELAY_MS,
    }),
  });
}
