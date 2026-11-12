import { z } from "zod";
import {
  DEFAULT_PIPELINE_LIMITS,
  DEFAULT_BRANCH_TOKEN,
  ENGINE_CATALOG,
  FORK_POLICIES,
  PIPELINE_CONFIG_SCHEMA_VERSION,
  PIPELINE_SCAN_TYPES,
  PIPELINE_SEVERITIES,
  PULL_REQUEST_ACTIONS,
} from "./constants.js";
import { isKnownTimeZone } from "./cron.js";
import { validateSchedule } from "./schedule.js";
import { isValidRefName, patternProblem } from "./glob.js";

/**
 * `pipelineConfigV1` (SPEC §5.7, §5.7.1, §7.3): the strict, versioned pipeline configuration.
 *
 * R-8 / PIPE-023: scans never execute repository code. By construction this schema has NO field that can carry a command
 * line, script, shell snippet, container image, environment, working directory, package-manager invocation, install step,
 * build step, hook or plugin reference. Every object is `.strict()`: an unknown key at any level is rejected, never ignored
 * or stored. The only free-text values are bounded and validated: trigger keys, glob patterns (matched against names, never
 * evaluated), cron expression, IANA time zone, ref names and engine catalog ids/profiles (which only SELECT from the
 * platform-owned `ENGINE_CATALOG`). Adding any field that can carry executable content is an ADR-level change.
 */

const TRIGGER_KEY = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const PROFILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Builds the schema with the platform limits applied (timeouts, schedule minimum interval, pattern counts).
 * @param {Partial<typeof DEFAULT_PIPELINE_LIMITS>} [overrides]
 * @param {{ now?: () => Date }} [options] clock used by the schedule interval check
 */
export function createPipelineConfigSchema(overrides = {}, { now = () => new Date() } = {}) {
  const limits = { ...DEFAULT_PIPELINE_LIMITS, ...overrides };

  const pattern = z.string().superRefine((value, ctx) => {
    const problem = patternProblem(value, limits.maxPatternLength);
    if (problem) ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
  });
  const patternList = (max = limits.maxPatternsPerList) => z.array(pattern).max(max).default([]);
  const includeExclude = (defaultInclude = []) =>
    z
      .object({ include: patternList().default(defaultInclude), exclude: patternList() })
      .strict()
      .default({});
  const refName = z.string().superRefine((value, ctx) => {
    if (value !== DEFAULT_BRANCH_TOKEN && !isValidRefName(value))
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "This is not a valid branch or tag name.",
      });
  });
  const key = z
    .string()
    .regex(
      TRIGGER_KEY,
      "Use 1-64 characters: a-z, 0-9, hyphen or underscore, starting with a letter or digit.",
    );
  const enabled = z.boolean().default(true);

  const pushTrigger = z
    .object({
      key,
      type: z.literal("push"),
      enabled,
      branches: includeExclude([DEFAULT_BRANCH_TOKEN]),
      tags: z
        .object({
          enabled: z.boolean().default(false),
          include: patternList(),
          exclude: patternList(),
        })
        .strict()
        .default({}),
      onBranchCreated: z.enum(["run", "skip"]).default("run"),
      onForcePush: z.enum(["run", "skip"]).default("run"),
    })
    .strict();
  const pullRequestTrigger = z
    .object({
      key,
      type: z.literal("pull_request"),
      enabled,
      actions: z
        .array(z.enum(PULL_REQUEST_ACTIONS))
        .min(1)
        .max(PULL_REQUEST_ACTIONS.length)
        .refine((list) => new Set(list).size === list.length, "Each action may appear once.")
        .default([...PULL_REQUEST_ACTIONS]),
      targetBranches: includeExclude([DEFAULT_BRANCH_TOKEN]),
      drafts: z.enum(["skip", "run"]).default("skip"),
      forkPolicy: z.enum(FORK_POLICIES).default("skip"),
    })
    .strict();
  const scheduleTrigger = z
    .object({
      key,
      type: z.literal("schedule"),
      enabled,
      cron: z.string().min(1).max(100),
      timezone: z
        .string()
        .max(64)
        .default("UTC")
        .refine((tz) => isKnownTimeZone(tz), "This is not a known IANA time zone."),
      ref: refName.default(DEFAULT_BRANCH_TOKEN),
      scanKind: z.enum(["full", "incremental"]).default("full"),
      missedPolicy: z.enum(["skip", "run_once"]).default("run_once"),
    })
    .strict();
  const manualTrigger = z.object({ key, type: z.literal("manual"), enabled }).strict();

  const triggers = z
    .array(
      z.discriminatedUnion("type", [
        pushTrigger,
        pullRequestTrigger,
        scheduleTrigger,
        manualTrigger,
      ]),
    )
    .max(3 + limits.maxSchedulesPerPipeline)
    .default([])
    .superRefine((list, ctx) => {
      const keys = new Set();
      const counts = { push: 0, pull_request: 0, schedule: 0, manual: 0 };
      list.forEach((trigger, index) => {
        if (keys.has(trigger.key))
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [index, "key"],
            message: "Trigger keys must be unique.",
          });
        keys.add(trigger.key);
        counts[trigger.type] += 1;
        if (trigger.type === "schedule") {
          // an unknown time zone is reported by the field itself; here the expression is validated and measured for real
          // (time zone and daylight saving aware, SPEC §5.6); a minimum interval of 0 or less checks the syntax only
          if (isKnownTimeZone(trigger.timezone)) {
            const result = validateSchedule({
              expression: trigger.cron,
              timeZone: trigger.timezone,
              minIntervalSeconds: limits.scheduleMinIntervalSeconds,
              now: now(),
            });
            if (!result.ok)
              ctx.addIssue({
                code: z.ZodIssueCode.custom,
                path: [index, "cron"],
                message: result.message,
              });
          }
        }
      });
      for (const type of ["push", "pull_request", "manual"])
        if (counts[type] > 1)
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `At most one ${type} trigger is allowed.`,
          });
      if (counts.schedule > limits.maxSchedulesPerPipeline)
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `At most ${limits.maxSchedulesPerPipeline} schedule triggers are allowed.`,
        });
    });

  const scan = (type) =>
    z
      .object({
        enabled: z.boolean().default(false),
        engine: z
          .object({
            id: z.string().min(1).max(64).default("default"),
            profile: z.string().regex(PROFILE_NAME).optional(),
          })
          .strict()
          .default({}),
        severityThreshold: z.enum(PIPELINE_SEVERITIES).default("low"),
      })
      .strict()
      .superRefine((value, ctx) => {
        const entry = ENGINE_CATALOG[type]?.[value.engine.id];
        if (!entry)
          return ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["engine", "id"],
            message: "This engine is not in the platform catalog.",
          });
        if (value.engine.profile !== undefined && !entry.profiles.includes(value.engine.profile))
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["engine", "profile"],
            message: "This profile is not offered by the engine.",
          });
      });
  const scans = z
    .object(Object.fromEntries(PIPELINE_SCAN_TYPES.map((type) => [type, scan(type).default({})])))
    .strict()
    .default({});

  const execution = z
    .object({
      timeoutSeconds: z
        .number()
        .int()
        .min(limits.timeoutMinSeconds)
        .max(limits.timeoutMaxSeconds)
        .default(limits.timeoutDefaultSeconds),
      scanTaskTimeoutSeconds: z
        .number()
        .int()
        .min(limits.scanTaskTimeoutMinSeconds)
        .max(limits.timeoutMaxSeconds)
        .default(limits.scanTaskTimeoutDefaultSeconds),
      concurrency: z
        .object({
          policy: z.enum(["queue", "supersede", "skip"]).default("supersede"),
          maxQueued: z.number().int().min(0).max(limits.maxQueuedPerPipeline).default(5),
          maxActive: z.number().int().min(1).max(limits.maxActiveLimit).default(1),
        })
        .strict()
        .default({}),
      cancellation: z.enum(["graceful", "immediate"]).default("graceful"),
    })
    .strict()
    .superRefine((value, ctx) => {
      if (value.scanTaskTimeoutSeconds > value.timeoutSeconds)
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["scanTaskTimeoutSeconds"],
          message: "The scan task timeout cannot exceed the execution timeout.",
        });
    })
    .default({});

  return z
    .object({
      schemaVersion: z.literal(PIPELINE_CONFIG_SCHEMA_VERSION),
      triggers,
      scans,
      scanMode: z
        .object({
          default: z.enum(["incremental", "full"]).default("incremental"),
          fullEvery: z.enum(["weekly", "monthly"]).nullable().default(null),
        })
        .strict()
        .default({}),
      failOn: z
        .object({
          severity: z.enum(["none", "low", "medium", "high", "critical"]).default("high"),
          scope: z.enum(["new", "all"]).default("new"),
          onEngineError: z.enum(["fail", "ignore"]).default("fail"),
        })
        .strict()
        .default({}),
      exclusions: z
        .object({ paths: z.array(pattern).max(limits.maxExclusionPaths).default([]) })
        .strict()
        .default({}),
      execution,
      notifications: z.object({}).strict().default({}),
    })
    .strict();
}

/** The configuration schema with the default platform limits. */
export const pipelineConfigV1 = /* @__PURE__ */ createPipelineConfigSchema();

/**
 * Canonical JSON: sorted keys, no whitespace, `undefined` members dropped. The `config_hash` of a version is SHA-256 over
 * the canonical JSON of `{ schemaVersion, config }` (SPEC §5.7); hashing is done by the caller (this file has no Node imports).
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (Array.isArray(value))
    return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(",")}}`;
  return JSON.stringify(value) ?? "null";
}

/** The pull request trigger's fork policy; `skip` when the configuration has none. @param {any} config */
export const forkPolicyOf = (config) =>
  config?.triggers?.find((t) => t.type === "pull_request")?.forkPolicy ?? "skip";

/** Schedule triggers of a configuration. @param {any} config */
export const scheduleTriggersOf = (config) =>
  (config?.triggers ?? []).filter((t) => t.type === "schedule");

/**
 * R-4: a pipeline can be enabled only with at least one scan type enabled and at least one enabled trigger.
 * @param {any} config
 * @returns {{ ok: boolean, missing: Array<"scan" | "trigger"> }}
 */
export function checkEnableable(config) {
  const missing = [];
  if (!PIPELINE_SCAN_TYPES.some((type) => config?.scans?.[type]?.enabled)) missing.push("scan");
  if (!(config?.triggers ?? []).some((t) => t.enabled)) missing.push("trigger");
  return { ok: missing.length === 0, missing };
}

const MAX_SUMMARY_PATHS = 100;

function flatten(value, prefix, out) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value);
    if (keys.length === 0 && prefix) out.set(prefix, "{}");
    for (const k of keys) flatten(value[k], prefix ? `${prefix}.${k}` : k, out);
  } else out.set(prefix, canonicalJson(value));
}

/**
 * Diff summary of two configurations for the audit entry and the version list: PATHS only (added, removed, changed), never
 * a value (SPEC §7.2). Triggers are compared by their `key` (`triggers.<key>.<field>`).
 * @param {any} previous null for the first version
 * @param {any} next
 * @returns {{ added: string[], removed: string[], changed: string[], truncated: boolean }}
 */
export function summarizeConfigChange(previous, next) {
  const collect = (config) => {
    const flat = new Map();
    const rest = { ...(config ?? {}) };
    const triggers = rest.triggers ?? [];
    delete rest.triggers;
    flatten(rest, "", flat);
    const byKey = new Map();
    for (const trigger of triggers) {
      const sub = new Map();
      flatten(trigger, `triggers.${trigger.key}`, sub);
      byKey.set(trigger.key, sub);
    }
    return { flat, byKey };
  };
  const a = collect(previous);
  const b = collect(next);
  const added = [];
  const removed = [];
  const changed = [];
  for (const [path, value] of b.flat) {
    if (!a.flat.has(path)) added.push(path);
    else if (a.flat.get(path) !== value) changed.push(path);
  }
  for (const path of a.flat.keys()) if (!b.flat.has(path)) removed.push(path);
  for (const [triggerKey, sub] of b.byKey) {
    const old = a.byKey.get(triggerKey);
    if (!old) added.push(`triggers.${triggerKey}`);
    else {
      for (const [path, value] of sub) {
        if (!old.has(path)) added.push(path);
        else if (old.get(path) !== value) changed.push(path);
      }
      for (const path of old.keys()) if (!sub.has(path)) removed.push(path);
    }
  }
  for (const triggerKey of a.byKey.keys())
    if (!b.byKey.has(triggerKey)) removed.push(`triggers.${triggerKey}`);
  const cap = (list) => list.sort().slice(0, MAX_SUMMARY_PATHS);
  const truncated = [added, removed, changed].some((l) => l.length > MAX_SUMMARY_PATHS);
  return { added: cap(added), removed: cap(removed), changed: cap(changed), truncated };
}

/**
 * The scan-relevant part of a configuration (`scans`, `exclusions`, `scanMode`): when its hash differs from the previous
 * request's, the next request is a full scan with reason `config_changed` (SPEC §5.7).
 * @param {any} config
 */
export const scanRelevantPart = (config) => ({
  scans: config?.scans,
  exclusions: config?.exclusions,
  scanMode: config?.scanMode,
});
