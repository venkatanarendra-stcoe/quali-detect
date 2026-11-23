import path from "node:path";
import { readGitHubAppConfig, readLLMConfig, sandboxConfigProblems } from "@qmentisai/infra";
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
  // Pause between webhook redeliveries requested by the reconciler (GitHub asks for spacing between mutating requests).
  SCM_REDELIVER_PAUSE_MS: z.coerce.number().int().min(0).max(60000).default(1000),
  // Pipeline trigger router: bounds the fan-out of one event (same name and default as the API, SPEC pipelines-triggers R-7).
  PIPELINES_MAX_PER_REPOSITORY: z.coerce.number().int().min(1).max(200).default(20),
  // Pipeline schedules (SPEC pipelines-triggers §6.4, §5.6): configurable placeholders, platform settings now, entitlements later.
  PIPELINE_SCHEDULE_TICK_SECONDS: z.coerce.number().int().min(5).max(3600).default(60),
  PIPELINE_SCHEDULE_BATCH: z.coerce.number().int().min(1).max(1000).default(100),
  PIPELINE_SCHEDULE_MAX_PER_TENANT_PER_TICK: z.coerce.number().int().min(1).max(1000).default(10),
  PIPELINE_SCHEDULE_MAX_LATENESS_SECONDS: z.coerce.number().int().min(0).max(604800).default(21600),
  PIPELINE_SCHEDULE_ON_TIME_GRACE_SECONDS: z.coerce.number().int().min(0).max(86400).default(120),
  // Same name and default as the API: the window of the per-slot jitter `hash(triggerId + slot) mod window` (both sides must agree).
  PIPELINE_SCHEDULE_JITTER_SECONDS: z.coerce.number().int().min(0).max(3600).default(300),
  // Execution orchestrator (docs/modules/executions/SPEC.md part C). OFF BY DEFAULT (EXEC-026, EQ-7a): with the flag off the
  // `pipeline` queue keeps its no-op handler and nothing claims a queued execution. All values are platform settings.
  EXECUTION_ORCHESTRATOR_ENABLED: z.enum(["true", "false"]).default("false"),
  // TEST-ONLY delay hook (execution/test-delay.js): refused at startup when NODE_ENV=production. Unset/0 = off.
  EXECUTION_TEST_DELAY_MS: z.coerce.number().int().min(0).max(600000).default(0),
  // Lease and heartbeat (ER-27): the database clock is the only clock; TTL must exceed 3 x heartbeat (checked below).
  EXECUTION_HEARTBEAT_SECONDS: z.coerce.number().int().min(1).max(300).default(10),
  EXECUTION_LEASE_TTL_SECONDS: z.coerce.number().int().min(4).max(3600).default(60),
  // One setting for ER-9 (`EXECUTION_QUEUE_MAX_AGE_SECONDS`, accepted as an alias) and ER-31/ER-32.
  EXECUTION_STALE_QUEUE_THRESHOLD_SECONDS: z.coerce.number().int().min(60).max(31536000).optional(),
  EXECUTION_QUEUE_MAX_AGE_SECONDS: z.coerce.number().int().min(60).max(31536000).optional(),
  EXECUTION_SWEEP_INTERVAL_SECONDS: z.coerce.number().int().min(1).max(3600).default(15),
  EXECUTION_SWEEP_MAX_PER_TENANT_PER_TICK: z.coerce.number().int().min(1).max(100).default(5),
  EXECUTION_SWEEP_BATCH_SIZE: z.coerce.number().int().min(1).max(500).default(50),
  EXECUTION_TASK_PARALLELISM: z.coerce.number().int().min(1).max(4).default(2),
  EXECUTION_TASK_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(5).default(2),
  EXECUTION_MAX_RECLAIMS: z.coerce.number().int().min(0).max(10).default(2),
  EXECUTION_PREPARE_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).default(3),
  EXECUTION_PREPARE_RETRY_DELAY_MS: z.coerce.number().int().min(0).max(60000).default(1000),
  // Archive hand-off: the fetch step stores the archive under this ABSOLUTE root (tenant and execution in every path, mode 0700).
  ARTIFACT_STORE_ROOT: z.string().optional(),
  EXECUTION_ARCHIVE_MAX_BYTES: z.coerce.number().int().min(1024).default(209715200),
  EXECUTION_ARCHIVE_MAX_ENTRIES: z.coerce.number().int().min(1).default(100000),
  EXECUTION_ARCHIVE_MAX_FILE_BYTES: z.coerce.number().int().min(1024).default(52428800),
  EXECUTION_ARCHIVE_MAX_EXPANDED_BYTES: z.coerce.number().int().min(1024).default(1073741824),
  EXECUTION_ARCHIVE_MAX_RATIO: z.coerce.number().int().min(2).max(10000).default(200),
  EXECUTION_ARCHIVE_MAX_DEPTH: z.coerce.number().int().min(1).max(256).default(64),
  EXECUTION_MAX_RESULT_ITEMS_PER_TASK: z.coerce.number().int().min(1).max(1000000).default(50000),
  // Execution logs (SPEC §7.4, §17.ac): capped Postgres tables. The caps stay below the database ceilings (CHECK constraints:
  // 100000 lines / 8 MiB per execution, 50000 lines / 4 MiB per task); over a cap one marker line is written and the rest dropped.
  EXECUTION_LOG_MAX_LINES: z.coerce.number().int().min(10).max(100000).default(20000),
  EXECUTION_LOG_MAX_BYTES: z.coerce.number().int().min(4096).max(8388608).default(2097152),
  EXECUTION_LOG_MAX_LINES_PER_TASK: z.coerce.number().int().min(10).max(50000).default(10000),
  EXECUTION_LOG_MAX_BYTES_PER_TASK: z.coerce.number().int().min(4096).max(4194304).default(1048576),
  // Retention (ER-17, Confirmed PT Q18): logs and raw outputs 90 days, execution metadata 13 months. The PURGE is OFF by default
  // (Open decision: the job); metadata deletion has its own, second switch.
  EXECUTION_LOG_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(90),
  EXECUTION_ARTIFACT_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(90),
  EXECUTION_METADATA_RETENTION_MONTHS: z.coerce.number().int().min(1).max(600).default(13),
  EXECUTION_RETENTION_PURGE_ENABLED: z.enum(["true", "false"]).default("false"),
  EXECUTION_RETENTION_PURGE_METADATA: z.enum(["true", "false"]).default("false"),
  EXECUTION_RETENTION_PURGE_INTERVAL_SECONDS: z.coerce
    .number()
    .int()
    .min(60)
    .max(86400)
    .default(3600),
  EXECUTION_RETENTION_PURGE_BATCH_SIZE: z.coerce.number().int().min(1).max(5000).default(500),
  // Scan decisioning (docs/modules/scan-decisioning/SPEC.md 5.2, 5.3, 17.c). NOT WIRED YET: the orchestrator does not call the
  // decision until part E. The diff bounds stay at or below the documented GitHub limits (compare 300, pull-request files 3000).
  // the only Secrets rule (owner decision 2026-11-18; `strict` was removed): any other value stops the worker at start
  SCAN_DECISION_SECRETS_RULE: z.literal("any_change").default("any_change"),
  SCAN_DECISION_MAX_CHANGED_FILES: z.coerce.number().int().min(1).max(3000).default(3000),
  SCAN_DECISION_MAX_PAGES: z.coerce.number().int().min(1).max(30).default(30),
  SCAN_DECISION_SAMPLE_PATHS: z.coerce.number().int().min(0).max(100).default(20),
  // Decision agent (SPEC 5.4, 17.d; AP-5: 20 s and 3 turns). The timeout must stay below EXECUTION_LEASE_TTL_SECONDS (checked below).
  SCAN_DECISION_AGENT_TIMEOUT_SECONDS: z.coerce.number().int().min(1).max(300).default(20),
  SCAN_DECISION_MAX_TURNS: z.coerce.number().int().min(1).max(5).default(3),
  SCAN_DECISION_CONTEXT_PATHS: z.coerce.number().int().min(0).max(500).default(100),
  // Scan engines (docs/modules/scan-engines/SPEC.md part A, ADR-014). OFF BY DEFAULT (D-12). Part K core reads it in the pipeline and
  // scan workers: while it is "true" the ensemble SBOM engine replaces the built-in one and the decision stores the changed paths.
  // The sandbox settings below only describe the container runtime CLI; no secret is involved.
  SCAN_ENGINES_ENSEMBLE_ENABLED: z.enum(["true", "false"]).default("false"),
  // Findings (docs/modules/findings/SPEC.md IN-1, 9.2, owner decisions of 2026-11-23): BOTH flags default OFF and nothing is written, queued or
  // handled while they are "false". FINDINGS_AGENT_DATABASE_URL is the connection string of the restricted `qm_fp_agent` login role (read
  // view + advisory insert only; a secret: never logged). It is REQUIRED in production while FINDINGS_AGENT_ENABLED=true.
  FINDINGS_INGESTION_ENABLED: z.enum(["true", "false"]).default("false"),
  FINDINGS_AGENT_ENABLED: z.enum(["true", "false"]).default("false"),
  FINDINGS_AGENT_DATABASE_URL: z.string().url().optional(),
  FINDINGS_FIX_CONFIRMATIONS: z.coerce.number().int().min(1).max(5).default(1),
  FINDINGS_AGENT_MAX_CONCURRENT_CALLS: z.coerce.number().int().min(1).max(32).default(2),
  FINDINGS_AGENT_TENANT_DAILY_CAP: z.coerce.number().int().min(1).max(100000).default(500),
  // The Docker-compatible CLI (execFile, never a shell). Nothing assumes a rootful runtime; rootless operation and uid mapping are
  // UNVERIFIED (SPEC D-20, ENG-L18). The Docker socket is never mounted into a container.
  SANDBOX_RUNTIME_BIN: z.enum(["docker", "podman"]).default("podman"),
  SANDBOX_USER: z.string().default("65534:65534"),
  SANDBOX_USERNS_MODE: z.enum(["keep-id", "auto", "nomap"]).optional(),
  SANDBOX_UIDMAP: z.string().optional(),
  SANDBOX_GIDMAP: z.string().optional(),
  SANDBOX_SECCOMP_PROFILE: z.string().optional(),
  SANDBOX_STDOUT_MAX_BYTES: z.coerce.number().int().min(1024).max(2147483648).default(134217728),
  SANDBOX_CLI_TIMEOUT_MS: z.coerce.number().int().min(1000).max(600000).default(30000),
  // Part K core. Both paths are required (and checked) only while SCAN_ENGINES_ENSEMBLE_ENABLED=true. The archive root is where the scan
  // worker extracts trees (it must not be a system or home path); the rules directory holds the platform tool configuration
  // (syft.yaml, trivy.yaml; copy the platform rules of the SBOM ensemble there).
  SANDBOX_ARCHIVE_ROOT: z.string().optional(),
  SANDBOX_RULES_DIR: z.string().optional(),
  SCAN_ENGINE_TOOL_PARALLELISM: z.coerce.number().int().min(1).max(8).default(2),
  SCAN_RUNNER_MAX_CONTAINERS: z.coerce.number().int().min(1).max(64).default(4),
  SCAN_RUNNER_MAX_CONTAINERS_PER_TENANT: z.coerce.number().int().min(1).max(64).default(2),
  SCAN_UNTRUSTED_CAPACITY_SHARE: z.coerce.number().int().min(1).max(100).default(50),
  SCAN_RUNNER_WAIT_SECONDS: z.coerce.number().int().min(1).max(900).default(120),
  SCAN_RUNNER_JANITOR_SECONDS: z.coerce.number().int().min(10).max(3600).default(60),
  // Vulnerability DB mirror (docs/modules/scan-engines/SPEC.md 5.12, part F). OFF BY DEFAULT: the refresh job is neither scheduled nor
  // handled unless SCAN_DB_REFRESH_ENABLED=true. The roots are required (and checked) only while it is on. No URL, host or credential
  // is configured here: the downloader (the only component with network egress) is wired outside this schema.
  SCAN_DB_REFRESH_ENABLED: z.enum(["true", "false"]).default("false"),
  SCAN_DB_REFRESH_INTERVAL_SECONDS: z.coerce.number().int().min(300).max(604800).default(21600),
  SCAN_DB_REFRESH_TOOLS: z.string().max(100).default("trivy,osv-scanner"),
  SCAN_DB_MIRROR_ROOT: z.string().optional(),
  SCAN_DB_CACHE_ROOT: z.string().optional(),
  SCAN_DB_MAX_BYTES: z.coerce.number().int().min(1048576).max(68719476736).default(4294967296),
  SCAN_DB_MIN_SIZE_PERCENT: z.coerce.number().int().min(1).max(100).default(50),
  SCAN_DB_MAX_UPSTREAM_AGE_DAYS: z.coerce.number().int().min(1).max(365).default(30),
  SCAN_DB_KEEP_RETIRED: z.coerce.number().int().min(0).max(20).default(3),
  SCAN_DB_CANDIDATE_ABANDON_SECONDS: z.coerce.number().int().min(60).max(604800).default(3600),
  SCAN_DB_LOCK_TTL_SECONDS: z.coerce.number().int().min(60).max(86400).default(3600),
  // Staleness tiers of the active snapshot (SE-38; 3 and 14 days are the SPEC numbers, 30 is the added `expired` tier). Staleness never
  // fails a scan: every tier above fresh makes the tool run partial and the result incomplete.
  SCAN_DB_STALE_AGING_DAYS: z.coerce.number().int().min(1).max(365).default(3),
  SCAN_DB_STALE_STALE_DAYS: z.coerce.number().int().min(1).max(365).default(14),
  SCAN_DB_STALE_EXPIRED_DAYS: z.coerce.number().int().min(1).max(730).default(30),
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
export function loadWorkerConfig(env = process.env, { workerName } = {}) {
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
  // TEST-ONLY hook (execution/test-delay.js): a production process must not start with it, checked before anything else.
  if (e.NODE_ENV === "production" && e.EXECUTION_TEST_DELAY_MS > 0) {
    throw new ConfigError([
      {
        variable: "EXECUTION_TEST_DELAY_MS",
        message: "is a test-only hook and is refused when NODE_ENV=production",
      },
    ]);
  }
  // ER-5: the scan worker neither requires nor accepts GitHub App or SecretStore settings, so the process holds no credential
  // handle at all (the variables may exist in a shared environment; this process never reads them).
  const github =
    workerName === "scan"
      ? { enabled: false, problems: [], config: null }
      : readGitHubAppConfig(env, { production: e.NODE_ENV === "production" });
  if (github.problems.length > 0) throw new ConfigError(github.problems);
  // The optional LLM assistant (ADR-013): only the pipeline worker runs the decision agent, so the scan worker reads nothing of it
  // (ER-5: it holds no credential handle). Problems name the variable and the rule, never a value.
  const llm =
    workerName === "scan"
      ? { problems: [], config: null }
      : readLLMConfig(env, { production: e.NODE_ENV === "production" });
  if (llm.problems.length > 0) throw new ConfigError(llm.problems);
  const executionProblems = [];
  if (e.SCAN_DECISION_AGENT_TIMEOUT_SECONDS >= e.EXECUTION_LEASE_TTL_SECONDS)
    executionProblems.push({
      variable: "SCAN_DECISION_AGENT_TIMEOUT_SECONDS",
      message: "must be less than EXECUTION_LEASE_TTL_SECONDS (the agent runs under the lease)",
    });
  if (e.EXECUTION_LEASE_TTL_SECONDS <= 3 * e.EXECUTION_HEARTBEAT_SECONDS)
    executionProblems.push({
      variable: "EXECUTION_LEASE_TTL_SECONDS",
      message: "must be greater than 3 x EXECUTION_HEARTBEAT_SECONDS",
    });
  if (
    e.EXECUTION_STALE_QUEUE_THRESHOLD_SECONDS !== undefined &&
    e.EXECUTION_QUEUE_MAX_AGE_SECONDS !== undefined &&
    e.EXECUTION_STALE_QUEUE_THRESHOLD_SECONDS !== e.EXECUTION_QUEUE_MAX_AGE_SECONDS
  )
    executionProblems.push({
      variable: "EXECUTION_QUEUE_MAX_AGE_SECONDS",
      message:
        "is the same setting as EXECUTION_STALE_QUEUE_THRESHOLD_SECONDS; set one or make them equal",
    });
  const orchestratorEnabled = e.EXECUTION_ORCHESTRATOR_ENABLED === "true";
  if (orchestratorEnabled) {
    if (!e.DATABASE_URL)
      executionProblems.push({
        variable: "DATABASE_URL",
        message: "required while EXECUTION_ORCHESTRATOR_ENABLED=true",
      });
    if (!e.ARTIFACT_STORE_ROOT || !path.isAbsolute(e.ARTIFACT_STORE_ROOT))
      executionProblems.push({
        variable: "ARTIFACT_STORE_ROOT",
        message: "an absolute path is required while EXECUTION_ORCHESTRATOR_ENABLED=true",
      });
    if (workerName === "pipeline" && !github.enabled)
      executionProblems.push({
        variable: "GITHUB_APP_ENABLED",
        message:
          "the pipeline worker fetches code through the GitHub App while EXECUTION_ORCHESTRATOR_ENABLED=true",
      });
  }
  if (e.EXECUTION_LOG_MAX_LINES_PER_TASK > e.EXECUTION_LOG_MAX_LINES)
    executionProblems.push({
      variable: "EXECUTION_LOG_MAX_LINES_PER_TASK",
      message: "must not exceed EXECUTION_LOG_MAX_LINES",
    });
  if (e.EXECUTION_LOG_MAX_BYTES_PER_TASK > e.EXECUTION_LOG_MAX_BYTES)
    executionProblems.push({
      variable: "EXECUTION_LOG_MAX_BYTES_PER_TASK",
      message: "must not exceed EXECUTION_LOG_MAX_BYTES",
    });
  if (e.EXECUTION_METADATA_RETENTION_MONTHS * 28 < e.EXECUTION_LOG_RETENTION_DAYS)
    executionProblems.push({
      variable: "EXECUTION_METADATA_RETENTION_MONTHS",
      message: "must keep execution metadata at least as long as the logs",
    });
  // SPEC 9.3.4 layer 1: in production the advisory agent refuses to start without the restricted database role.
  if (
    e.FINDINGS_AGENT_ENABLED === "true" &&
    e.NODE_ENV === "production" &&
    !e.FINDINGS_AGENT_DATABASE_URL
  )
    executionProblems.push({
      variable: "FINDINGS_AGENT_DATABASE_URL",
      message:
        "required in production while FINDINGS_AGENT_ENABLED=true (the restricted qm_fp_agent login role)",
    });
  const sandbox = {
    runtimeBin: e.SANDBOX_RUNTIME_BIN,
    containerUser: e.SANDBOX_USER,
    usernsMode: e.SANDBOX_USERNS_MODE ?? null,
    uidMap: e.SANDBOX_UIDMAP ? e.SANDBOX_UIDMAP.split(",") : [],
    gidMap: e.SANDBOX_GIDMAP ? e.SANDBOX_GIDMAP.split(",") : [],
    seccompProfile: e.SANDBOX_SECCOMP_PROFILE ?? null,
    ceilings: { stdoutBytes: e.SANDBOX_STDOUT_MAX_BYTES },
    cliTimeoutMs: e.SANDBOX_CLI_TIMEOUT_MS,
  };
  // fail fast on an invalid sandbox setting (names the variable's concept, never the value); mount roots are supplied at wiring (part K)
  for (const problem of sandboxConfigProblems(sandbox))
    executionProblems.push({ variable: `SANDBOX_* (${problem.field})`, message: problem.message });
  if (e.SCAN_ENGINES_ENSEMBLE_ENABLED === "true") {
    // fail fast: the mount roots must be explicit, safe, absolute and outside the forbidden host paths
    const withRoots = {
      ...sandbox,
      mountRoots: {
        archive: e.SANDBOX_ARCHIVE_ROOT ? [e.SANDBOX_ARCHIVE_ROOT] : [],
        db: [],
        rules: e.SANDBOX_RULES_DIR ? [e.SANDBOX_RULES_DIR] : [],
      },
    };
    for (const [variable, value] of [
      ["SANDBOX_ARCHIVE_ROOT", e.SANDBOX_ARCHIVE_ROOT],
      ["SANDBOX_RULES_DIR", e.SANDBOX_RULES_DIR],
    ])
      if (!value || !path.isAbsolute(value))
        executionProblems.push({
          variable,
          message: "an absolute path is required while SCAN_ENGINES_ENSEMBLE_ENABLED=true",
        });
    for (const problem of sandboxConfigProblems(withRoots))
      if (problem.field.startsWith("mountRoots"))
        executionProblems.push({
          variable: `SANDBOX_ARCHIVE_ROOT / SANDBOX_RULES_DIR (${problem.field})`,
          message: problem.message,
        });
    if (e.SCAN_RUNNER_MAX_CONTAINERS_PER_TENANT > e.SCAN_RUNNER_MAX_CONTAINERS)
      executionProblems.push({
        variable: "SCAN_RUNNER_MAX_CONTAINERS_PER_TENANT",
        message: "must not exceed SCAN_RUNNER_MAX_CONTAINERS",
      });
  }
  // Vulnerability DB mirror (part F): thresholds always checked; roots and tools only matter while the refresh is on.
  const scanDbTools = e.SCAN_DB_REFRESH_TOOLS.split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  if (!(
    e.SCAN_DB_STALE_AGING_DAYS < e.SCAN_DB_STALE_STALE_DAYS &&
    e.SCAN_DB_STALE_STALE_DAYS < e.SCAN_DB_STALE_EXPIRED_DAYS
  ))
    executionProblems.push({
      variable: "SCAN_DB_STALE_AGING_DAYS / SCAN_DB_STALE_STALE_DAYS / SCAN_DB_STALE_EXPIRED_DAYS",
      message: "must be strictly increasing",
    });
  if (e.SCAN_DB_REFRESH_ENABLED === "true") {
    if (!e.DATABASE_URL)
      executionProblems.push({
        variable: "DATABASE_URL",
        message: "required while SCAN_DB_REFRESH_ENABLED=true",
      });
    for (const [variable, value] of [
      ["SCAN_DB_MIRROR_ROOT", e.SCAN_DB_MIRROR_ROOT],
      ["SCAN_DB_CACHE_ROOT", e.SCAN_DB_CACHE_ROOT],
    ])
      if (!value || !path.isAbsolute(value))
        executionProblems.push({
          variable,
          message: "an absolute path is required while SCAN_DB_REFRESH_ENABLED=true",
        });
    // the promotion canary reads its platform fixture and configuration from the platform rules directory (SPEC 17.u)
    if (!e.SANDBOX_RULES_DIR || !path.isAbsolute(e.SANDBOX_RULES_DIR))
      executionProblems.push({
        variable: "SANDBOX_RULES_DIR",
        message:
          "an absolute path is required while SCAN_DB_REFRESH_ENABLED=true (the canary scan reads canary.cdx.json from it)",
      });
    if (e.SCAN_DB_MIRROR_ROOT && e.SCAN_DB_MIRROR_ROOT === e.SCAN_DB_CACHE_ROOT)
      executionProblems.push({
        variable: "SCAN_DB_CACHE_ROOT",
        message: "must differ from SCAN_DB_MIRROR_ROOT",
      });
    for (const t of scanDbTools)
      if (!["trivy", "osv-scanner"].includes(t))
        executionProblems.push({
          variable: "SCAN_DB_REFRESH_TOOLS",
          message:
            t === "grype"
              ? "grype has no mirror in v1 (SPEC D-21)"
              : "must list only trivy and osv-scanner",
        });
    if (scanDbTools.length === 0)
      executionProblems.push({
        variable: "SCAN_DB_REFRESH_TOOLS",
        message: "must list at least one tool",
      });
  }
  if (executionProblems.length > 0) throw new ConfigError(executionProblems);
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
    scm: github.enabled
      ? Object.freeze({
          enabled: true,
          ...github.config,
          redeliverPauseMs: e.SCM_REDELIVER_PAUSE_MS,
        })
      : Object.freeze({ enabled: false }),
    scheduler: Object.freeze({
      sessionPurgeIntervalSeconds: e.SCHEDULER_SESSION_PURGE_INTERVAL_SECONDS,
      sessionRetentionSeconds: e.SCHEDULER_SESSION_RETENTION_SECONDS,
      scheduleTickSeconds: e.PIPELINE_SCHEDULE_TICK_SECONDS,
    }),
    pipelines: Object.freeze({
      maxPerRepository: e.PIPELINES_MAX_PER_REPOSITORY,
      schedule: Object.freeze({
        batch: e.PIPELINE_SCHEDULE_BATCH,
        maxPerTenantPerTick: e.PIPELINE_SCHEDULE_MAX_PER_TENANT_PER_TICK,
        maxLatenessSeconds: e.PIPELINE_SCHEDULE_MAX_LATENESS_SECONDS,
        onTimeGraceSeconds: e.PIPELINE_SCHEDULE_ON_TIME_GRACE_SECONDS,
        jitterSeconds: e.PIPELINE_SCHEDULE_JITTER_SECONDS,
      }),
    }),
    scanDb: Object.freeze({
      refreshEnabled: e.SCAN_DB_REFRESH_ENABLED === "true",
      intervalSeconds: e.SCAN_DB_REFRESH_INTERVAL_SECONDS,
      tools: Object.freeze([...new Set(scanDbTools)]),
      mirrorRoot: e.SCAN_DB_MIRROR_ROOT ?? null,
      cacheRoot: e.SCAN_DB_CACHE_ROOT ?? null,
      maxBytes: e.SCAN_DB_MAX_BYTES,
      minSizePercent: e.SCAN_DB_MIN_SIZE_PERCENT,
      maxUpstreamAgeDays: e.SCAN_DB_MAX_UPSTREAM_AGE_DAYS,
      keepRetired: e.SCAN_DB_KEEP_RETIRED,
      candidateAbandonSeconds: e.SCAN_DB_CANDIDATE_ABANDON_SECONDS,
      lockTtlSeconds: e.SCAN_DB_LOCK_TTL_SECONDS,
      stalenessDays: Object.freeze({
        aging: e.SCAN_DB_STALE_AGING_DAYS,
        stale: e.SCAN_DB_STALE_STALE_DAYS,
        expired: e.SCAN_DB_STALE_EXPIRED_DAYS,
      }),
    }),
    execution: Object.freeze({
      enabled: orchestratorEnabled,
      heartbeatSeconds: e.EXECUTION_HEARTBEAT_SECONDS,
      leaseTtlSeconds: e.EXECUTION_LEASE_TTL_SECONDS,
      staleThresholdSeconds:
        e.EXECUTION_STALE_QUEUE_THRESHOLD_SECONDS ?? e.EXECUTION_QUEUE_MAX_AGE_SECONDS ?? 86400,
      sweepIntervalSeconds: e.EXECUTION_SWEEP_INTERVAL_SECONDS,
      maxPerTenantPerTick: e.EXECUTION_SWEEP_MAX_PER_TENANT_PER_TICK,
      sweepBatchSize: e.EXECUTION_SWEEP_BATCH_SIZE,
      taskParallelism: e.EXECUTION_TASK_PARALLELISM,
      taskMaxAttempts: e.EXECUTION_TASK_MAX_ATTEMPTS,
      maxReclaims: e.EXECUTION_MAX_RECLAIMS,
      prepareMaxAttempts: e.EXECUTION_PREPARE_MAX_ATTEMPTS,
      prepareRetryDelayMs: e.EXECUTION_PREPARE_RETRY_DELAY_MS,
      artifactStoreRoot: e.ARTIFACT_STORE_ROOT ?? null,
      maxResultItemsPerTask: e.EXECUTION_MAX_RESULT_ITEMS_PER_TASK,
      logs: Object.freeze({
        maxLinesPerExecution: e.EXECUTION_LOG_MAX_LINES,
        maxBytesPerExecution: e.EXECUTION_LOG_MAX_BYTES,
        maxLinesPerTask: e.EXECUTION_LOG_MAX_LINES_PER_TASK,
        maxBytesPerTask: e.EXECUTION_LOG_MAX_BYTES_PER_TASK,
      }),
      retention: Object.freeze({
        purgeEnabled: e.EXECUTION_RETENTION_PURGE_ENABLED === "true",
        purgeMetadata: e.EXECUTION_RETENTION_PURGE_METADATA === "true",
        purgeIntervalSeconds: e.EXECUTION_RETENTION_PURGE_INTERVAL_SECONDS,
        batchSize: e.EXECUTION_RETENTION_PURGE_BATCH_SIZE,
        logRetentionDays: e.EXECUTION_LOG_RETENTION_DAYS,
        artifactRetentionDays: e.EXECUTION_ARTIFACT_RETENTION_DAYS,
        metadataRetentionMonths: e.EXECUTION_METADATA_RETENTION_MONTHS,
      }),
      archiveLimits: Object.freeze({
        maxBytes: e.EXECUTION_ARCHIVE_MAX_BYTES,
        maxEntries: e.EXECUTION_ARCHIVE_MAX_ENTRIES,
        maxFileBytes: e.EXECUTION_ARCHIVE_MAX_FILE_BYTES,
        maxTotalBytes: e.EXECUTION_ARCHIVE_MAX_EXPANDED_BYTES,
        maxRatio: e.EXECUTION_ARCHIVE_MAX_RATIO,
        maxDepth: e.EXECUTION_ARCHIVE_MAX_DEPTH,
      }),
    }),
    scanEngines: Object.freeze({
      // rollout flag (D-12); read by the registry wiring, the scan worker and the orchestrator (part K core)
      ensembleEnabled: e.SCAN_ENGINES_ENSEMBLE_ENABLED === "true",
      sandbox: Object.freeze(sandbox),
      production: e.NODE_ENV === "production",
      archiveRoot: e.SANDBOX_ARCHIVE_ROOT ?? null,
      rulesDir: e.SANDBOX_RULES_DIR ?? null,
      toolParallelism: e.SCAN_ENGINE_TOOL_PARALLELISM,
      maxContainers: e.SCAN_RUNNER_MAX_CONTAINERS,
      maxContainersPerTenant: e.SCAN_RUNNER_MAX_CONTAINERS_PER_TENANT,
      untrustedCapacityShare: e.SCAN_UNTRUSTED_CAPACITY_SHARE,
      waitSeconds: e.SCAN_RUNNER_WAIT_SECONDS,
      janitorSeconds: e.SCAN_RUNNER_JANITOR_SECONDS,
    }),
    findings: Object.freeze({
      ingestionEnabled: e.FINDINGS_INGESTION_ENABLED === "true",
      agentEnabled: e.FINDINGS_AGENT_ENABLED === "true",
      /** The restricted-role connection string; null in development when unset (SPEC 9.3.4: the agent then uses the normal pool through the code layer and warns). */
      agentDatabaseUrl: e.FINDINGS_AGENT_DATABASE_URL ?? null,
      fixConfirmations: e.FINDINGS_FIX_CONFIRMATIONS,
      agentMaxConcurrentCalls: e.FINDINGS_AGENT_MAX_CONCURRENT_CALLS,
      agentTenantDailyCap: e.FINDINGS_AGENT_TENANT_DAILY_CAP,
    }),
    scanDecision: Object.freeze({
      secretsRule: e.SCAN_DECISION_SECRETS_RULE,
      maxChangedFiles: e.SCAN_DECISION_MAX_CHANGED_FILES,
      maxPages: e.SCAN_DECISION_MAX_PAGES,
      samplePaths: e.SCAN_DECISION_SAMPLE_PATHS,
      agentTimeoutSeconds: e.SCAN_DECISION_AGENT_TIMEOUT_SECONDS,
      maxTurns: e.SCAN_DECISION_MAX_TURNS,
      contextPaths: e.SCAN_DECISION_CONTEXT_PATHS,
    }),
    llm: llm.config,
    outbox: Object.freeze({
      batchSize: e.OUTBOX_BATCH_SIZE,
      pollIntervalMs: e.OUTBOX_POLL_INTERVAL_MS,
      maxAttempts: e.OUTBOX_MAX_ATTEMPTS,
      baseDelayMs: e.OUTBOX_RETRY_BASE_DELAY_MS,
      maxDelayMs: e.OUTBOX_RETRY_MAX_DELAY_MS,
    }),
  });
}
