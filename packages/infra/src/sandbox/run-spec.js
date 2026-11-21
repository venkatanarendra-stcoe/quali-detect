import { findCredentials } from "../credential-guard.js";
import { isSafeAbsolutePath, isUnderForbiddenRoot } from "./config.js";
import { SANDBOX_ERROR_CODES, SandboxError } from "./errors.js";
import {
  ENV_ALLOWLIST,
  ENV_VALUE_PATTERN,
  ID_PATTERN,
  IMAGE_DIGEST_PATTERN,
  NETWORK_PURPOSES,
  TOOL_ID_PATTERN,
} from "./policy.js";

/**
 * The run specification (SPEC 6.2). It has NO field that can weaken the sandbox: there is no network-mode, mount-mode, capability,
 * user, device, privilege, entrypoint or extra-mount field, and unknown keys are refused. The runner derives all of those from the
 * policy constants and the runtime configuration. The only exception to the sealed network is `networkPurpose` (the DB refresh job,
 * SE-34), which maps to a dedicated named network that exists only in the runtime configuration.
 *
 * Part B turns `imageKey` into `image` through the lock file; Part A takes the digest reference itself and refuses anything else.
 *
 * @typedef {{
 *   toolId: string,
 *   image: string,
 *   argv: string[],
 *   paths?: string[],   // repository-relative; the runner passes them as `/src/<path>` after `--`
 *   mounts: { archive?: string, db?: string, rules?: string },
 *   env?: Record<string, string>,
 *   stdin?: string,
 *   limits: { cpus: number, memoryMiB: number, pids: number, wallClockSeconds: number, stdoutBytes: number, tmpfsMiB: number, nofile?: number },
 *   labels: { tenantId: string, executionId: string, taskId: string, attempt: number, deadlineEpoch: number },
 *   networkPurpose?: "db_refresh"
 * }} RunSpec
 */

const RUN_SPEC_KEYS = new Set([
  "toolId",
  "image",
  "argv",
  "paths",
  "mounts",
  "env",
  "stdin",
  "limits",
  "labels",
  "networkPurpose",
]);
const LIMIT_KEYS = [
  "cpus",
  "memoryMiB",
  "pids",
  "wallClockSeconds",
  "stdoutBytes",
  "tmpfsMiB",
  "nofile",
];
const LABEL_FIELDS = ["tenantId", "executionId", "taskId", "attempt", "deadlineEpoch"];
/* eslint-disable no-control-regex */
const CONTROL =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/;
/* eslint-enable no-control-regex */
const MAX_ARGV = 256;
const MAX_ARG_LENGTH = 1024;
const MAX_PATHS = 2000;
const MAX_PATH_LENGTH = 1024;
const MAX_STDIN_BYTES = 1048576;

/** @param {unknown} v */
const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Whether `p` can be handed to a tool as a repository path: relative, no `..`, no control or bidirectional characters, no
 * backslash, bounded. A leading `-` is allowed ONLY because paths are always passed after `--`.
 * @param {unknown} p
 */
export function isValidRepoPath(p) {
  if (typeof p !== "string" || p.length === 0 || p.length > MAX_PATH_LENGTH) return false;
  if (p === "--" || CONTROL.test(p) || p.includes("\\") || p.startsWith("/")) return false;
  return !p.split("/").some((seg) => seg === ".." || seg === "" || seg === ".");
}

/**
 * Splits repository-derived paths into the valid ones and a count of the dropped ones (SPEC 14.1 ENG-S03). Never throws on content.
 * @param {unknown[]} paths
 * @returns {{ paths: string[], dropped: number }}
 */
export function sanitizeRepoPaths(paths) {
  const valid = [];
  let dropped = 0;
  for (const p of Array.isArray(paths) ? paths : []) {
    if (isValidRepoPath(p) && valid.length < MAX_PATHS) valid.push(p);
    else dropped += 1;
  }
  return { paths: valid, dropped };
}

/**
 * Container name of a run: `qm-<task8>-<tool>-<attempt>` (unique per attempt, SPEC 6.4).
 * @param {RunSpec} spec a validated spec
 */
export function containerNameOf(spec) {
  const task8 = spec.labels.taskId.replace(/[^A-Za-z0-9]/g, "").slice(0, 8) || "task";
  return `qm-${task8}-${spec.toolId}-${spec.labels.attempt}`;
}

/**
 * Validates a RunSpec against the runtime configuration. Pure. Returns a deep-frozen copy.
 * @param {unknown} raw
 * @param {Readonly<import("./config.js").SandboxConfig>} config
 * @returns {Readonly<RunSpec>}
 * @throws {SandboxError} `invalid_spec` (shape) or `policy_violation` (a forbidden property); names rules, never values
 */
export function validateRunSpec(raw, config) {
  const invalid = (rule) => {
    throw new SandboxError(SANDBOX_ERROR_CODES.invalidSpec, `RunSpec rejected: ${rule}`, [rule]);
  };
  const forbid = (rule) => {
    throw new SandboxError(SANDBOX_ERROR_CODES.policyViolation, `RunSpec rejected: ${rule}`, [
      rule,
    ]);
  };
  if (!isPlainObject(raw)) invalid("spec must be an object");
  const spec = /** @type {Record<string, any>} */ (raw);
  for (const key of Object.keys(spec))
    if (!RUN_SPEC_KEYS.has(key)) forbid(`unknown key ${JSON.stringify(key).slice(0, 40)}`);
  if (typeof spec.toolId !== "string" || !TOOL_ID_PATTERN.test(spec.toolId)) invalid("toolId");
  if (typeof spec.image !== "string" || !IMAGE_DIGEST_PATTERN.test(spec.image))
    forbid("image must be a repository@sha256:<64 hex> digest reference (no tag)");
  if (!Array.isArray(spec.argv) || spec.argv.length > MAX_ARGV) invalid("argv must be an array");
  for (const a of spec.argv)
    if (typeof a !== "string" || a.length > MAX_ARG_LENGTH || CONTROL.test(a) || a === "--")
      invalid("argv entries must be bounded strings without control characters (and not --)");
  if (spec.paths !== undefined) {
    if (
      !Array.isArray(spec.paths) ||
      spec.paths.length > MAX_PATHS ||
      !spec.paths.every(isValidRepoPath)
    )
      invalid("paths must be valid relative repository paths");
  }
  // mounts: only the three known kinds, each a safe absolute path inside the configured root of that kind
  if (!isPlainObject(spec.mounts)) invalid("mounts must be an object");
  for (const key of Object.keys(spec.mounts))
    if (!["archive", "db", "rules"].includes(key))
      forbid("mounts may only name archive, db or rules");
  for (const kind of ["archive", "db", "rules"]) {
    const src = spec.mounts[kind];
    if (src === undefined) continue;
    if (typeof src !== "string" || !isSafeAbsolutePath(src))
      forbid(`mounts.${kind} must be a safe absolute path`);
    if (src.split("/").some((seg) => /\.sock$/i.test(seg)))
      forbid(`mounts.${kind} must not be a runtime socket`);
    if (isUnderForbiddenRoot(src, /** @type {string[]} */ (config.forbiddenMountRoots)))
      forbid(`mounts.${kind} is inside a forbidden host path`);
    const roots = config.mountRoots[kind];
    if (!roots.some((r) => src === r || src.startsWith(`${r}/`)))
      forbid(`mounts.${kind} is outside the configured ${kind} roots`);
  }
  const hasMount = spec.mounts.archive || spec.mounts.db || spec.mounts.rules;
  if (!hasMount && !spec.networkPurpose)
    invalid("a run needs at least one mount or a network purpose");
  // environment: names from the allowlist, static safe values, nothing credential-shaped
  const env = spec.env ?? {};
  if (!isPlainObject(env)) invalid("env must be an object");
  for (const [name, value] of Object.entries(env)) {
    if (!ENV_ALLOWLIST.includes(name)) forbid("env name outside the allowlist");
    if (typeof value !== "string" || !ENV_VALUE_PATTERN.test(value))
      forbid("env value must be a short static string");
    if (name === "HOME" && value !== "/tmp") forbid("env HOME must be /tmp");
  }
  if (
    findCredentials(
      { spec: { argv: spec.argv, paths: spec.paths, env, stdin: spec.stdin } },
      "spec",
    ).length > 0
  )
    forbid("spec carries a credential");
  if (
    spec.stdin !== undefined &&
    (typeof spec.stdin !== "string" || Buffer.byteLength(spec.stdin) > MAX_STDIN_BYTES)
  )
    invalid("stdin must be a string of at most 1 MiB");
  // limits: required, bounded by the configured ceilings
  if (!isPlainObject(spec.limits)) invalid("limits must be an object");
  for (const key of Object.keys(spec.limits))
    if (!LIMIT_KEYS.includes(key)) forbid("unknown limit key");
  const c = config.ceilings;
  const within = (value, max) =>
    typeof value === "number" && Number.isFinite(value) && value > 0 && value <= max;
  if (!within(spec.limits.cpus, c.cpus)) invalid("limits.cpus");
  if (!Number.isInteger(spec.limits.memoryMiB) || !within(spec.limits.memoryMiB, c.memoryMiB))
    invalid("limits.memoryMiB");
  if (!Number.isInteger(spec.limits.pids) || !within(spec.limits.pids, c.pids))
    invalid("limits.pids");
  if (
    !Number.isInteger(spec.limits.wallClockSeconds) ||
    !within(spec.limits.wallClockSeconds, c.wallClockSeconds)
  )
    invalid("limits.wallClockSeconds");
  if (!Number.isInteger(spec.limits.stdoutBytes) || !within(spec.limits.stdoutBytes, c.stdoutBytes))
    invalid("limits.stdoutBytes");
  if (!Number.isInteger(spec.limits.tmpfsMiB) || !within(spec.limits.tmpfsMiB, c.tmpfsMiB))
    invalid("limits.tmpfsMiB");
  if (
    spec.limits.nofile !== undefined &&
    (!Number.isInteger(spec.limits.nofile) || !within(spec.limits.nofile, 65536))
  )
    invalid("limits.nofile");
  // labels: ids for the janitor and the audit trail
  if (!isPlainObject(spec.labels)) invalid("labels must be an object");
  for (const key of Object.keys(spec.labels))
    if (!LABEL_FIELDS.includes(key)) forbid("unknown label field");
  for (const key of ["tenantId", "executionId", "taskId"])
    if (typeof spec.labels[key] !== "string" || !ID_PATTERN.test(spec.labels[key]))
      invalid(`labels.${key}`);
  if (
    !Number.isInteger(spec.labels.attempt) ||
    spec.labels.attempt < 1 ||
    spec.labels.attempt > 1000
  )
    invalid("labels.attempt");
  if (!Number.isInteger(spec.labels.deadlineEpoch) || spec.labels.deadlineEpoch < 1)
    invalid("labels.deadlineEpoch");
  // network: sealed unless an explicit allowlisted purpose with a configured network (never together with the archive)
  if (spec.networkPurpose !== undefined) {
    if (!NETWORK_PURPOSES.includes(spec.networkPurpose)) forbid("unknown network purpose");
    if (!config.egressNetworks[spec.networkPurpose])
      forbid("network purpose has no configured network");
    if (spec.mounts.archive) forbid("a run with network access must not mount repository content");
  }
  return deepFreeze(structuredClone(spec));
}

/** @param {any} v */
function deepFreeze(v) {
  if (v && typeof v === "object") {
    for (const item of Object.values(v)) deepFreeze(item);
    Object.freeze(v);
  }
  return v;
}
