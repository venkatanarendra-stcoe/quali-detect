/**
 * Pure constants of the Pipelines + Triggers module (docs/modules/pipelines-triggers/SPEC.md). No Node, database or
 * framework imports: the API, the workers and the browser share this file.
 */

/** Trigger types a pipeline can carry (SPEC §5.3 to §5.6). DAST and Asset Discovery are never pipeline-triggered (PIPE-007). */
export const PIPELINE_TRIGGER_TYPES = Object.freeze(["push", "pull_request", "schedule", "manual"]);

/** Scan types a pipeline configuration can enable (SPEC §5.7). Deliberately no `dast` and no `assetDiscovery`. */
export const PIPELINE_SCAN_TYPES = Object.freeze(["sca", "sbom", "sast", "secrets"]);

/** Severity vocabulary of thresholds, lowest first. */
export const PIPELINE_SEVERITIES = Object.freeze(["info", "low", "medium", "high", "critical"]);

/** Fork policies. `run_with_credentials` does not exist and is not representable (SPEC §5.4.1). */
export const FORK_POLICIES = Object.freeze(["skip", "run_without_credentials"]);

/** Pull request actions a trigger may select (SPEC §5.4). */
export const PULL_REQUEST_ACTIONS = Object.freeze([
  "opened",
  "synchronize",
  "reopened",
  "ready_for_review",
]);

/** Version of the configuration schema this build writes (SPEC §5.7). */
export const PIPELINE_CONFIG_SCHEMA_VERSION = 1;

/** The token that resolves to the repository's default branch at match time (SPEC §5.3, Q29). */
export const DEFAULT_BRANCH_TOKEN = "$default_branch";

/** Derived effective states of a pipeline (SPEC §5.2). The stored `enabled` flag is never flipped (C5). */
export const PIPELINE_EFFECTIVE_STATES = Object.freeze([
  "running_normally",
  "disabled",
  "repository_disabled",
  "repository_unavailable",
  "repository_disconnected",
  "workspace_archived",
  "tenant_unavailable",
  "deleted",
]);

/** Reasons recorded as trigger decision rows for policy skips (SPEC §7.8). */
export const TRIGGER_DECISION_REASONS = Object.freeze([
  "fork_policy_skip",
  "draft_policy_skip",
  "repository_inactive",
  "repository_disabled",
  "workspace_archived",
  "pipeline_disabled",
  "trigger_disabled",
]);

/** What a trigger decision row is keyed by (SPEC §7.8): an SCM delivery, a nominal schedule slot, or a manual run. */
export const TRIGGER_DECISION_SOURCES = Object.freeze(["scm_event", "schedule_slot", "manual"]);

/**
 * Platform limits applied at validation (SPEC §5.5, §5.6, §5.8, §7.3). Every value is a placeholder default that the API
 * reads from platform settings (environment) and may later come from entitlements; none is a product constant.
 */
export const DEFAULT_PIPELINE_LIMITS = Object.freeze({
  timeoutDefaultSeconds: 1800,
  timeoutMaxSeconds: 7200,
  timeoutMinSeconds: 60,
  scanTaskTimeoutDefaultSeconds: 900,
  scanTaskTimeoutMinSeconds: 30,
  maxQueuedPerPipeline: 20,
  scheduleMinIntervalSeconds: 3600,
  maxSchedulesPerPipeline: 3,
  scheduleJitterSeconds: 300,
  pipelinesMaxPerRepository: 20,
  maxPatternsPerList: 20,
  maxPatternLength: 200,
  maxExclusionPaths: 50,
  maxActiveLimit: 10,
});

/**
 * Platform-owned engine catalog (SPEC §5.7.1): one placeholder engine per scan type in v1. A repository can never add an
 * engine, a rule pack path, a command or a plugin; `engine.id` and `engine.profile` only SELECT from this constant.
 * Real engines and versions are added by the engine modules.
 * @type {Readonly<Record<string, Readonly<Record<string, Readonly<{ name: string, profiles: readonly string[] }>>>>>}
 */
export const ENGINE_CATALOG = Object.freeze({
  sca: Object.freeze({
    default: Object.freeze({
      name: "Default SCA engine (placeholder)",
      profiles: Object.freeze(["standard"]),
    }),
  }),
  sbom: Object.freeze({
    default: Object.freeze({
      name: "Default SBOM engine (placeholder)",
      profiles: Object.freeze(["standard"]),
    }),
  }),
  sast: Object.freeze({
    default: Object.freeze({
      name: "Default SAST engine (placeholder)",
      profiles: Object.freeze(["standard"]),
    }),
  }),
  secrets: Object.freeze({
    default: Object.freeze({
      name: "Default secrets engine (placeholder)",
      profiles: Object.freeze(["standard"]),
    }),
  }),
});
