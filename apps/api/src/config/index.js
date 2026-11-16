import { randomBytes } from "node:crypto";
import { z } from "zod";
import { SecretConfigError, parseMasterKey, readGitHubAppConfig } from "@qmentisai/infra";
import { PACKAGE_INFO } from "./package-info.js";

const booleanFlag = z.enum(["true", "false"]).transform((value) => value === "true");
const DEV_ORIGINS = ["http://localhost:5173", "http://localhost:5174"];

/** Environment variables accepted by the API. Unknown variables are ignored; invalid or missing required ones fail startup. */
const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_HOST: z.string().min(1).default("0.0.0.0"),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  REQUEST_BODY_LIMIT_BYTES: z.coerce.number().int().min(1024).max(52428800).default(1048576),
  OPENAPI_ENABLED: booleanFlag.optional(),
  // Express "trust proxy": "false" (default), a number of trusted proxy hops, or a list of addresses/subnets such as
  // "loopback, 10.0.0.0/8". "true" is refused: it would trust any client-supplied X-Forwarded-For.
  TRUST_PROXY: z.string().optional(),
  // Global per-IP request limit applied before authentication (login throttling is separate and stricter).
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).max(3600000).default(60000),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(1000000).default(600),
  // Per-route profiles (Redis-backed, stricter than the global limit). "auth": public sign-in endpoints, per IP.
  // "write": authenticated create/side-effect endpoints, per tenant + user. "webhook": provider webhooks (per IP), ready for Phase 5.
  RATE_LIMIT_AUTH_WINDOW_MS: z.coerce.number().int().min(1000).max(3600000).default(900000),
  RATE_LIMIT_AUTH_MAX: z.coerce.number().int().min(1).max(100000).default(30),
  RATE_LIMIT_WRITE_WINDOW_MS: z.coerce.number().int().min(1000).max(3600000).default(60000),
  RATE_LIMIT_WRITE_MAX: z.coerce.number().int().min(1).max(100000).default(120),
  RATE_LIMIT_WEBHOOK_WINDOW_MS: z.coerce.number().int().min(1000).max(3600000).default(60000),
  RATE_LIMIT_WEBHOOK_MAX: z.coerce.number().int().min(1).max(1000000).default(600),
  // Idempotency-Key: how long a stored response can be replayed.
  IDEMPOTENCY_TTL_SECONDS: z.coerce.number().int().min(60).max(604800).default(86400),
  // Progressive sign-in / MFA throttling (ADR-010). Defaults keep 6-digit MFA brute force impractical; see the ADR for the math.
  // How long after deactivation a Super Admin can still restore a tenant (AUTHORIZATION Q25). The length is an OPEN
  // decision (OPEN_DECISIONS.md): 30 days is a provisional placeholder, not an approved retention period.
  TENANT_DEACTIVATION_RETENTION_SECONDS: z.coerce
    .number()
    .int()
    .min(1)
    .max(31536000)
    .default(2592000),
  // Lifetime of the single-use GitHub linking state (SPEC §18.6: 10 minutes). Shortened by the security suite to test expiry.
  SCM_LINK_STATE_TTL_SECONDS: z.coerce.number().int().min(1).max(3600).default(600),
  // Pipelines and triggers (docs/modules/pipelines-triggers/SPEC.md §5.5 to §5.8, §7.3): platform limits applied when a
  // configuration is validated. Placeholders now, entitlements later (Q12).
  PIPELINES_MAX_PER_REPOSITORY: z.coerce.number().int().min(1).max(200).default(20),
  PIPELINE_TIMEOUT_DEFAULT_SECONDS: z.coerce.number().int().min(60).max(86400).default(1800),
  PIPELINE_TIMEOUT_MAX_SECONDS: z.coerce.number().int().min(60).max(86400).default(7200),
  PIPELINE_SCAN_TASK_TIMEOUT_DEFAULT_SECONDS: z.coerce
    .number()
    .int()
    .min(30)
    .max(86400)
    .default(900),
  PIPELINE_MAX_QUEUED_PER_PIPELINE: z.coerce.number().int().min(0).max(1000).default(20),
  PIPELINE_SCHEDULE_MIN_INTERVAL_SECONDS: z.coerce
    .number()
    .int()
    .min(60)
    .max(2592000)
    .default(3600),
  PIPELINE_MAX_SCHEDULES_PER_PIPELINE: z.coerce.number().int().min(0).max(20).default(3),
  PIPELINE_SCHEDULE_JITTER_SECONDS: z.coerce.number().int().min(0).max(3600).default(300),
  // Executions (docs/modules/executions/SPEC.md part D): the grace period of a graceful cancel (PT §5.8, ER-14), how long the
  // holder waits for aborted attempts after an immediate cancel, and how many retries may follow one original (EQ-2d).
  PIPELINE_CANCEL_GRACE_SECONDS: z.coerce.number().int().min(0).max(3600).default(60),
  EXECUTION_ABORT_GRACE_SECONDS: z.coerce.number().int().min(0).max(600).default(10),
  EXECUTION_RETRY_CHAIN_MAX: z.coerce.number().int().min(1).max(20).default(5),
  // Realtime (docs/modules/executions/SPEC.md §9.4 and §17.ad): Socket.IO hints, OFF unless enabled. Single instance only (no Redis
  // adapter): the `realtime` queue consumer and the sockets live in this process.
  REALTIME_ENABLED: booleanFlag.optional(),
  REALTIME_MAX_ROOMS_PER_SOCKET: z.coerce.number().int().min(1).max(100).default(20),
  REALTIME_MAX_DENIED_JOINS: z.coerce.number().int().min(1).max(100).default(5),
  REALTIME_DENIED_WINDOW_SECONDS: z.coerce.number().int().min(1).max(3600).default(60),
  REALTIME_REAUTH_SECONDS: z.coerce.number().int().min(1).max(3600).default(60),
  REALTIME_MAX_CONNECTIONS_PER_IP: z.coerce.number().int().min(1).max(10000).default(20),
  REALTIME_MAX_CONNECTIONS_PER_SESSION: z.coerce.number().int().min(1).max(100).default(5),
  REALTIME_CONNECT_RATE_PER_MINUTE: z.coerce.number().int().min(1).max(100000).default(60),
  REALTIME_JOIN_RATE_PER_MINUTE: z.coerce.number().int().min(1).max(10000).default(60),
  REALTIME_EVENTS_PER_MINUTE: z.coerce.number().int().min(1).max(100000).default(240),
  REALTIME_MAX_PAYLOAD_BYTES: z.coerce.number().int().min(256).max(65536).default(2048),
  // Secret storage (ADR-009). Off unless a feature needs it. The "env" key provider (master key from the environment) is
  // for DEVELOPMENT only and is refused in production; the KMS and Vault adapters are not implemented yet.
  SECRETS_ENABLED: booleanFlag.optional(),
  SECRET_KEY_PROVIDER: z.enum(["env", "kms", "vault"]).default("env"),
  SECRET_MASTER_KEY: z.string().optional(),
  SECRET_MASTER_KEY_VERSION: z.coerce.number().int().min(1).max(1000000).default(1),
  // Signing keys of pagination cursors (HMAC; the raw value never signs, a subkey is derived with HKDF). Comma-separated, NEWEST
  // FIRST: the first signs, all verify (rotation: prepend the new secret, drop the old one once its cursors have expired).
  // Each secret needs 32+ characters. Required in production; in development and test an unset value generates a random
  // per-process secret (cursors then stop working when the API restarts, which only restarts a "Load more" walk).
  CURSOR_SIGNING_SECRET: z.string().optional(),
  AUTH_THROTTLE_LOGIN_FREE_ATTEMPTS: z.coerce.number().int().min(0).max(100).default(5),
  AUTH_THROTTLE_LOGIN_BASE_DELAY_SECONDS: z.coerce.number().int().min(1).max(3600).default(10),
  AUTH_THROTTLE_LOGIN_CAP_SECONDS: z.coerce.number().int().min(1).max(86400).default(900),
  AUTH_THROTTLE_MFA_FREE_ATTEMPTS: z.coerce.number().int().min(0).max(20).default(3),
  AUTH_THROTTLE_MFA_BASE_DELAY_SECONDS: z.coerce.number().int().min(1).max(3600).default(30),
  AUTH_THROTTLE_MFA_CAP_SECONDS: z.coerce.number().int().min(1).max(86400).default(3600),
  AUTH_THROTTLE_IP_FREE_MULTIPLIER: z.coerce.number().int().min(1).max(100).default(10),
  AUTH_THROTTLE_DECAY_SECONDS: z.coerce.number().int().min(60).max(604800).default(86400),
  // The identity module needs the database, so it is required.
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url().optional(),
  RABBITMQ_URL: z.string().url().optional(),
  // Sessions and cookies
  SESSION_TTL_SECONDS: z.coerce.number().int().min(60).max(2592000).default(28800),
  SESSION_IDLE_TIMEOUT_SECONDS: z.coerce.number().int().min(60).max(2592000).default(3600),
  COOKIE_SECURE: booleanFlag.optional(),
  // Comma-separated browser origins allowed for CORS (with credentials) and for state-changing requests (CSRF).
  CORS_ALLOWED_ORIGINS: z.string().optional(),
  // Mock authentication (development only): seeded users sign in with a shared password from the environment.
  MOCK_AUTH_ENABLED: booleanFlag.optional(),
  MOCK_AUTH_PASSWORD: z.string().min(8).max(128).optional(),
  MOCK_PLATFORM_AUTH_PASSWORD: z.string().min(8).max(128).optional(),
  // Mock second factor for platform users (MFA is mandatory for the Root Console): a 6-digit code from the environment.
  MOCK_PLATFORM_MFA_CODE: z
    .string()
    .regex(/^\d{6}$/, "must be exactly 6 digits")
    .optional(),
});

/**
 * Parses TRUST_PROXY into the value accepted by Express `app.set("trust proxy", value)`.
 * @param {string | undefined} raw
 * @returns {false | number | string}
 */
function parseTrustProxy(raw) {
  const value = raw?.trim();
  if (!value || value === "false") return false;
  if (/^\d+$/.test(value)) return Number(value);
  if (value === "true") return false;
  return value;
}

/** Raised when the environment is invalid. The message lists variable names and problems, never values. */
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

const isOrigin = (value) => {
  try {
    return new URL(value).origin === value;
  } catch {
    return false;
  }
};

/** Cross-field rules that a per-variable schema cannot express. Returns problems (names and messages only). */
function crossChecks(e, allowedOrigins) {
  const problems = [];
  const production = e.NODE_ENV === "production";
  const mock = e.MOCK_AUTH_ENABLED ?? !production;
  if (e.SECRETS_ENABLED === true) {
    if (e.SECRET_KEY_PROVIDER !== "env") {
      problems.push({
        variable: "SECRET_KEY_PROVIDER",
        message: `the "${e.SECRET_KEY_PROVIDER}" key provider adapter is not implemented yet; secrets cannot be enabled with it`,
      });
    } else if (production) {
      problems.push({
        variable: "SECRET_KEY_PROVIDER",
        message:
          'the "env" key provider is development only; production needs a KMS or Vault adapter before secrets can be used',
      });
    } else {
      try {
        parseMasterKey(e.SECRET_MASTER_KEY);
      } catch (error) {
        if (!(error instanceof SecretConfigError)) throw error;
        problems.push({ variable: "SECRET_MASTER_KEY", message: error.message });
      }
    }
  }
  if (production && !e.CURSOR_SIGNING_SECRET?.trim())
    problems.push({ variable: "CURSOR_SIGNING_SECRET", message: "required in production" });
  if (e.CURSOR_SIGNING_SECRET !== undefined && e.CURSOR_SIGNING_SECRET.trim() !== "") {
    const secrets = e.CURSOR_SIGNING_SECRET.split(",").map((value) => value.trim());
    if (secrets.length > 4 || secrets.some((value) => value.length < 32 || value.length > 256))
      problems.push({
        variable: "CURSOR_SIGNING_SECRET",
        message:
          "must be 1 to 4 comma-separated secrets (newest first) of 32 to 256 characters each",
      });
  }
  if (e.PIPELINE_TIMEOUT_DEFAULT_SECONDS > e.PIPELINE_TIMEOUT_MAX_SECONDS)
    problems.push({
      variable: "PIPELINE_TIMEOUT_DEFAULT_SECONDS",
      message: "must not exceed PIPELINE_TIMEOUT_MAX_SECONDS",
    });
  for (const origin of allowedOrigins) {
    // CORS with credentials: only exact origins (scheme://host[:port]); never "*" or a path.
    if (!/^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/.test(origin))
      problems.push({
        variable: "CORS_ALLOWED_ORIGINS",
        message:
          "every entry must be an exact origin such as https://app.example.com (no wildcard, path or trailing slash)",
      });
  }
  if (e.TRUST_PROXY?.trim() === "true")
    problems.push({
      variable: "TRUST_PROXY",
      message:
        'must not be "true" (it trusts any client-supplied X-Forwarded-For); use a hop count or addresses',
    });
  if (production && e.MOCK_AUTH_ENABLED === true)
    problems.push({
      variable: "MOCK_AUTH_ENABLED",
      message: "mock authentication must not be enabled in production",
    });
  if (mock && !production) {
    if (!e.MOCK_AUTH_PASSWORD)
      problems.push({
        variable: "MOCK_AUTH_PASSWORD",
        message: "required while mock authentication is enabled",
      });
    if (!e.MOCK_PLATFORM_AUTH_PASSWORD)
      problems.push({
        variable: "MOCK_PLATFORM_AUTH_PASSWORD",
        message: "required while mock authentication is enabled",
      });
    if (!e.MOCK_PLATFORM_MFA_CODE)
      problems.push({
        variable: "MOCK_PLATFORM_MFA_CODE",
        message: "required while mock authentication is enabled (platform MFA is mandatory)",
      });
  }
  const bad = allowedOrigins.filter((o) => !isOrigin(o));
  if (bad.length > 0)
    problems.push({
      variable: "CORS_ALLOWED_ORIGINS",
      message:
        "every entry must be an origin like https://app.example.com (no path, no trailing slash)",
    });
  if (production) {
    if (allowedOrigins.length === 0)
      problems.push({ variable: "CORS_ALLOWED_ORIGINS", message: "required in production" });
    if (!e.REDIS_URL)
      problems.push({
        variable: "REDIS_URL",
        message: "required in production (login rate limiting)",
      });
    if (e.COOKIE_SECURE === false)
      problems.push({ variable: "COOKIE_SECURE", message: "must not be false in production" });
  }
  if (e.SESSION_IDLE_TIMEOUT_SECONDS > e.SESSION_TTL_SECONDS)
    problems.push({
      variable: "SESSION_IDLE_TIMEOUT_SECONDS",
      message: "must not exceed SESSION_TTL_SECONDS",
    });
  return problems;
}

/**
 * Validates the environment and returns an immutable, typed-by-schema configuration object.
 * Pure: pass the environment explicitly. Throws `ConfigError` (fail fast) when invalid.
 * @param {Record<string, string | undefined>} [env]
 */
export function loadConfig(env = process.env) {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    throw new ConfigError(
      result.error.issues.map((issue) => ({
        variable: issue.path.join(".") || "(env)",
        // Messages never echo the offending value (it could be a secret): enum issues are rephrased without it.
        message:
          issue.code === "invalid_enum_value"
            ? `must be one of: ${issue.options.join(", ")}`
            : issue.message,
      })),
    );
  }
  const e = result.data;
  const production = e.NODE_ENV === "production";
  const allowedOrigins =
    e.CORS_ALLOWED_ORIGINS === undefined
      ? production
        ? []
        : DEV_ORIGINS
      : e.CORS_ALLOWED_ORIGINS.split(",")
          .map((o) => o.trim())
          .filter(Boolean);
  const problems = crossChecks(e, allowedOrigins);
  // GitHub App settings are validated by the shared reader (also used by the workers); secrets are not read here.
  const github = readGitHubAppConfig(env, { production });
  problems.push(...github.problems);
  if (problems.length > 0) throw new ConfigError(problems);
  const mockEnabled = e.MOCK_AUTH_ENABLED ?? !production;
  return Object.freeze({
    app: Object.freeze({ ...PACKAGE_INFO, environment: e.NODE_ENV }),
    http: Object.freeze({
      host: e.API_HOST,
      port: e.API_PORT,
      bodyLimitBytes: e.REQUEST_BODY_LIMIT_BYTES,
      trustProxy: parseTrustProxy(e.TRUST_PROXY),
      rateLimit: Object.freeze({ windowMs: e.RATE_LIMIT_WINDOW_MS, max: e.RATE_LIMIT_MAX }),
      routeLimits: Object.freeze({
        auth: Object.freeze({ windowMs: e.RATE_LIMIT_AUTH_WINDOW_MS, max: e.RATE_LIMIT_AUTH_MAX }),
        write: Object.freeze({
          windowMs: e.RATE_LIMIT_WRITE_WINDOW_MS,
          max: e.RATE_LIMIT_WRITE_MAX,
        }),
        webhook: Object.freeze({
          windowMs: e.RATE_LIMIT_WEBHOOK_WINDOW_MS,
          max: e.RATE_LIMIT_WEBHOOK_MAX,
        }),
      }),
      idempotencyTtlSeconds: e.IDEMPOTENCY_TTL_SECONDS,
    }),
    github: github.enabled
      ? Object.freeze({ enabled: true, ...github.config })
      : Object.freeze({ enabled: false }),
    secrets: Object.freeze({
      enabled: e.SECRETS_ENABLED ?? false,
      provider: e.SECRET_KEY_PROVIDER,
      // Never log or return: validated above, kept only to build the key provider.
      masterKey: e.SECRETS_ENABLED === true ? e.SECRET_MASTER_KEY : undefined,
      masterKeyVersion: e.SECRET_MASTER_KEY_VERSION,
    }),
    scm: Object.freeze({ linkStateTtlSeconds: e.SCM_LINK_STATE_TTL_SECONDS }),
    pipelines: Object.freeze({
      maxPerRepository: e.PIPELINES_MAX_PER_REPOSITORY,
      limits: Object.freeze({
        timeoutDefaultSeconds: e.PIPELINE_TIMEOUT_DEFAULT_SECONDS,
        timeoutMaxSeconds: e.PIPELINE_TIMEOUT_MAX_SECONDS,
        scanTaskTimeoutDefaultSeconds: e.PIPELINE_SCAN_TASK_TIMEOUT_DEFAULT_SECONDS,
        maxQueuedPerPipeline: e.PIPELINE_MAX_QUEUED_PER_PIPELINE,
        scheduleMinIntervalSeconds: e.PIPELINE_SCHEDULE_MIN_INTERVAL_SECONDS,
        maxSchedulesPerPipeline: e.PIPELINE_MAX_SCHEDULES_PER_PIPELINE,
        scheduleJitterSeconds: e.PIPELINE_SCHEDULE_JITTER_SECONDS,
        pipelinesMaxPerRepository: e.PIPELINES_MAX_PER_REPOSITORY,
      }),
    }),
    executions: Object.freeze({
      cancelGraceSeconds: e.PIPELINE_CANCEL_GRACE_SECONDS,
      abortGraceSeconds: e.EXECUTION_ABORT_GRACE_SECONDS,
      retryChainMax: e.EXECUTION_RETRY_CHAIN_MAX,
    }),
    realtime: Object.freeze({
      enabled: e.REALTIME_ENABLED ?? false,
      maxRoomsPerSocket: e.REALTIME_MAX_ROOMS_PER_SOCKET,
      maxDeniedJoins: e.REALTIME_MAX_DENIED_JOINS,
      deniedWindowSeconds: e.REALTIME_DENIED_WINDOW_SECONDS,
      reauthSeconds: e.REALTIME_REAUTH_SECONDS,
      maxConnectionsPerIp: e.REALTIME_MAX_CONNECTIONS_PER_IP,
      maxConnectionsPerSession: e.REALTIME_MAX_CONNECTIONS_PER_SESSION,
      connectRatePerMinute: e.REALTIME_CONNECT_RATE_PER_MINUTE,
      joinRatePerMinute: e.REALTIME_JOIN_RATE_PER_MINUTE,
      eventsPerMinute: e.REALTIME_EVENTS_PER_MINUTE,
      maxPayloadBytes: e.REALTIME_MAX_PAYLOAD_BYTES,
    }),
    // Secrets: never log or return. Unset outside production = random per-process secret (see the schema comment).
    cursor: Object.freeze({
      signingSecrets: Object.freeze(
        e.CURSOR_SIGNING_SECRET?.trim()
          ? e.CURSOR_SIGNING_SECRET.split(",").map((value) => value.trim())
          : [randomBytes(32).toString("hex")],
      ),
      signingSecretConfigured: Boolean(e.CURSOR_SIGNING_SECRET?.trim()),
    }),
    tenants: Object.freeze({
      deactivationRetentionSeconds: e.TENANT_DEACTIVATION_RETENTION_SECONDS,
    }),
    log: Object.freeze({ level: e.LOG_LEVEL }),
    openapi: Object.freeze({ enabled: e.OPENAPI_ENABLED ?? !production }),
    // Connection strings may contain credentials: keep them out of logs and responses.
    infra: Object.freeze({
      databaseUrl: e.DATABASE_URL,
      redisUrl: e.REDIS_URL,
      rabbitmqUrl: e.RABBITMQ_URL,
    }),
    auth: Object.freeze({
      throttle: Object.freeze({
        login: Object.freeze({
          freeAttempts: e.AUTH_THROTTLE_LOGIN_FREE_ATTEMPTS,
          baseDelaySeconds: e.AUTH_THROTTLE_LOGIN_BASE_DELAY_SECONDS,
          capSeconds: e.AUTH_THROTTLE_LOGIN_CAP_SECONDS,
        }),
        mfa: Object.freeze({
          freeAttempts: e.AUTH_THROTTLE_MFA_FREE_ATTEMPTS,
          baseDelaySeconds: e.AUTH_THROTTLE_MFA_BASE_DELAY_SECONDS,
          capSeconds: e.AUTH_THROTTLE_MFA_CAP_SECONDS,
        }),
        ipFreeMultiplier: e.AUTH_THROTTLE_IP_FREE_MULTIPLIER,
        decaySeconds: e.AUTH_THROTTLE_DECAY_SECONDS,
      }),
      sessionTtlSeconds: e.SESSION_TTL_SECONDS,
      idleTimeoutSeconds: e.SESSION_IDLE_TIMEOUT_SECONDS,
      cookieSecure: e.COOKIE_SECURE ?? production,
      allowedOrigins: Object.freeze(allowedOrigins),
      // Passwords of the mock provider: never log or return them.
      mock: Object.freeze({
        enabled: mockEnabled,
        tenantPassword: e.MOCK_AUTH_PASSWORD,
        platformPassword: e.MOCK_PLATFORM_AUTH_PASSWORD,
        platformMfaCode: e.MOCK_PLATFORM_MFA_CODE,
      }),
    }),
  });
}

/**
 * Safe startup summary of the configuration (no connection strings, passwords or secrets).
 * @param {ReturnType<typeof loadConfig>} config
 */
export function describeConfig(config) {
  return {
    environment: config.app.environment,
    host: config.http.host,
    port: config.http.port,
    logLevel: config.log.level,
    openapiEnabled: config.openapi.enabled,
    redisConfigured: Boolean(config.infra.redisUrl),
    rabbitmqConfigured: Boolean(config.infra.rabbitmqUrl),
    sessionTtlSeconds: config.auth.sessionTtlSeconds,
    idleTimeoutSeconds: config.auth.idleTimeoutSeconds,
    cookieSecure: config.auth.cookieSecure,
    corsOrigins: config.auth.allowedOrigins.length,
    mockAuthEnabled: config.auth.mock.enabled,
    secretsEnabled: config.secrets.enabled,
    cursorSigning: config.cursor.signingSecretConfigured ? "configured" : "ephemeral",
    githubEnabled: config.github.enabled,
    realtimeEnabled: config.realtime.enabled,
  };
}
