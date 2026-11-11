import { z } from "zod";
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
  if (problems.length > 0) throw new ConfigError(problems);
  const mockEnabled = e.MOCK_AUTH_ENABLED ?? !production;
  return Object.freeze({
    app: Object.freeze({ ...PACKAGE_INFO, environment: e.NODE_ENV }),
    http: Object.freeze({
      host: e.API_HOST,
      port: e.API_PORT,
      bodyLimitBytes: e.REQUEST_BODY_LIMIT_BYTES,
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
  };
}
