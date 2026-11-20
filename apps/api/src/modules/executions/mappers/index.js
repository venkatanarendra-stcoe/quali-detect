import {
  COVERAGE_GAP_NAMES,
  COVERAGE_STATE_DTO,
  ENSEMBLE_TOOL_IDS,
  KIND_OF_SCAN_TYPE,
  SCAN_TASK_ORDER,
  SEVERITIES,
  TOOL_DISPLAY_NAMES,
  TOOL_REASONS,
  TOOL_SCOPE_WORDS,
  TOOL_STATUSES,
  UNKNOWN_WORD,
} from "@qmentisai/shared";
import { FAILED_TASK_STATUSES } from "../constants/index.js";

/**
 * The answer of a cancel or a retry (SPEC executions §8.1, §8.2): the execution as the caller may see it. Never a Prisma
 * model: no tenant id, no lease, no archive, no idempotency key. The full detail DTO belongs to the read APIs (part G).
 * @param {any} e execution row
 */
export const toExecutionActionDto = (e) => ({
  id: e.id,
  workspaceId: e.workspaceId,
  pipelineId: e.pipelineId,
  status: e.status,
  statusReason: e.statusReason ?? null,
  triggerType: e.triggerType,
  refType: e.refType,
  refName: e.refName,
  pullRequestNumber: e.pullRequestNumber ?? null,
  commitSha: e.commitSha ?? null,
  scanKind: e.scanKind,
  scanKindReason: e.scanKindReason,
  trust: e.trust,
  requestedAt: e.requestedAt,
  retryOfExecutionId: e.retryOfExecutionId ?? null,
  cancelRequested: Boolean(e.cancelRequestedAt),
  cancelRequestedAt: e.cancelRequestedAt ?? null,
  cancelMode: e.cancelMode ?? null,
});

const iso = (value) => (value ? new Date(value).toISOString() : null);
const durationOf = (e) =>
  e.startedAt && e.finishedAt ? Math.max(0, new Date(e.finishedAt) - new Date(e.startedAt)) : null;

/**
 * The task counters of a list row. `failed` counts `failed` and `timed_out`; `running` counts `running`.
 * @param {Array<{ status: string, count: number }>} counts
 */
export function toTaskSummary(counts) {
  const sum = (...statuses) =>
    counts.filter((c) => statuses.includes(c.status)).reduce((n, c) => n + c.count, 0);
  return {
    total: counts.reduce((n, c) => n + c.count, 0),
    succeeded: sum("succeeded"),
    failed: sum(...FAILED_TASK_STATUSES),
    running: sum("running"),
  };
}

/**
 * List row (SPEC §8.2). The pipeline and repository NAMES are present only when the caller may see them (`pipeline.view`,
 * `repository.view` in the execution's workspace); ids are not secrets. No tenant id, lease, archive, key or author data.
 * @param {any} e execution row (list columns)
 * @param {{ pipelineName?: string | null, repositoryName?: string | null, taskCounts?: Array<{ status: string, count: number }> }} labels
 */
export const toExecutionListDto = (e, labels = {}) => ({
  id: e.id,
  workspaceId: e.workspaceId,
  pipeline: {
    id: e.pipelineId,
    ...(labels.pipelineName ? { name: labels.pipelineName } : {}),
  },
  repository: labels.repositoryName
    ? { id: e.repositoryId, fullName: labels.repositoryName }
    : null,
  status: e.status,
  statusReason: e.statusReason ?? null,
  triggerType: e.triggerType,
  triggerKey: e.triggerKey,
  refType: e.refType,
  refName: e.refName,
  pullRequestNumber: e.pullRequestNumber ?? null,
  commitSha: e.commitSha ?? null,
  scanKind: e.scanKind,
  scanKindReason: e.scanKindReason,
  trust: e.trust,
  requestedAt: iso(e.requestedAt),
  startedAt: iso(e.startedAt),
  finishedAt: iso(e.finishedAt),
  durationMs: durationOf(e),
  taskSummary: toTaskSummary(labels.taskCounts ?? []),
  cancelRequested: Boolean(e.cancelRequestedAt),
  retryOfExecutionId: e.retryOfExecutionId ?? null,
});

const countOf = (value) => (Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0);

const HEX_DIGEST = /^(?:sha256:)?([0-9a-f]{64})$/;
/** `sha256:` plus the first 8 hex characters of a full hash; `null` for anything else. The full value never leaves the server. */
const shortHash = (value) => {
  const m = typeof value === "string" ? HEX_DIGEST.exec(value) : null;
  return m ? `sha256:${m[1].slice(0, 8)}` : null;
};
const TERMINAL_TASK = new Set(["succeeded", "failed", "timed_out", "cancelled"]);
const wordOf = (value, allowed) => (allowed.includes(value) ? value : UNKNOWN_WORD);

/**
 * One tool run as the tenant may see it (SPEC scan-engines 8, SCREENS 3). A FIELD ALLOW-LIST: the display name comes from the
 * platform catalog, status and reason are fixed words (an unknown value becomes `unknown`), the image is the short form, the counts
 * are integers. No run id, no chain or tenant id, no config or rule-pack hash, no exit code, no limits, no command line, no stderr
 * and no tool-originated text. A tool id outside the catalog yields `null` (the row is dropped).
 * @param {any} r a `scan_tool_runs` row (allow-listed select)
 * @param {string} scanType
 */
export const toToolRunDto = (r, scanType) => {
  if (!ENSEMBLE_TOOL_IDS.includes(r.toolId)) return null;
  const counts = r.severityCounts && typeof r.severityCounts === "object" ? r.severityCounts : {};
  const scope = r.scope && typeof r.scope === "object" ? r.scope.kind : null;
  const hasDb = Boolean(r.dbSnapshotSha256 || r.dbBuiltAt);
  return {
    toolId: r.toolId,
    displayName: TOOL_DISPLAY_NAMES[r.toolId],
    version:
      r.toolVersion && r.toolVersion !== "unknown" ? String(r.toolVersion).slice(0, 64) : null,
    imageShort: shortHash(r.imageDigest),
    builtIn: r.toolId === "sbom-lite",
    status: wordOf(r.status, TOOL_STATUSES),
    reason: r.reason ? wordOf(r.reason, TOOL_REASONS) : null,
    durationMs: countOf(r.durationMs),
    counts: Object.fromEntries(SEVERITIES.map((s) => [s, countOf(counts[s])])),
    findingsMapped: countOf(r.findingsMapped),
    resultKind: KIND_OF_SCAN_TYPE[scanType] ?? "component",
    db: hasDb ? { builtAt: iso(r.dbBuiltAt), versionShort: shortHash(r.dbSnapshotSha256) } : null,
    scope: TOOL_SCOPE_WORDS.includes(scope) ? scope : null,
  };
};

/**
 * The tools and the coverage statement of one task: only the LATEST attempt's tool runs and only for a finished task (a running
 * retry shows none), in catalog order. The coverage is the stored statement of the result of THE SAME attempt (a result of an older
 * attempt would misdescribe the newer tools); a gap word outside the platform list is `other`. An empty object (the fields are
 * omitted, no placeholder) for a legacy task: no tool runs.
 * @param {any} t task row
 * @param {any[]} runs the tool runs of this task (any attempt)
 */
const toolsOf = (t, runs) => {
  if (!TERMINAL_TASK.has(t.status) || !runs.length) return {};
  const latest = Math.max(...runs.map((r) => r.attempt));
  const order = (id) => ENSEMBLE_TOOL_IDS.indexOf(id);
  const tools = runs
    .filter((r) => r.attempt === latest)
    .sort((a, b) => order(a.toolId) - order(b.toolId))
    .map((r) => toToolRunDto(r, t.scanType))
    .filter(Boolean);
  if (!tools.length) return {};
  const result = t.results?.[0] ?? null;
  const stored = result?.attempt === latest && result.coverage ? result.coverage : null;
  const state = stored ? COVERAGE_STATE_DTO[stored.state] : null;
  const gaps = Array.isArray(stored?.coverageGaps) ? stored.coverageGaps : [];
  return {
    tools,
    ...(state
      ? {
          coverage: {
            state,
            toolsDegraded: countOf(stored.toolsDegraded),
            toolsTotal: tools.filter((x) => x.status !== "skipped").length,
            gaps: [
              ...new Set(gaps.map((g) => (COVERAGE_GAP_NAMES.includes(g) ? g : "other"))),
            ].slice(0, 10),
          },
        }
      : {}),
  };
};

/**
 * One scan task of the detail DTO. The result summary has counts and flags only (no items, no locator). `tools` and `coverage` exist
 * only for a task an ensemble engine ran (docs/modules/scan-engines/SPEC.md 8).
 * @param {any} t task row with its (at most one) result
 * @param {any[]} [toolRuns] the tool runs of this task
 */
export const toTaskDto = (t, toolRuns = []) => {
  const result = t.results?.[0] ?? null;
  return {
    id: t.id,
    scanType: t.scanType,
    status: t.status,
    statusReason: t.statusReason ?? null,
    attempt: t.attempt,
    maxAttempts: t.maxAttempts,
    engine: { id: t.engineId, profile: t.engineProfile },
    startedAt: iso(t.startedAt),
    finishedAt: iso(t.finishedAt),
    resultSummary: result
      ? {
          itemCount: result.itemCount,
          severityCounts: result.severityCounts ?? {},
          truncated: result.truncated,
          completeness: result.completeness,
        }
      : null,
    ...toolsOf(t, toolRuns),
  };
};
const countRecord = (value) =>
  Object.fromEntries(
    Object.entries(value && typeof value === "object" ? value : {})
      .filter(([, n]) => Number.isFinite(n))
      .map(([key, n]) => [key, countOf(n)]),
  );
const textOrNull = (value) => (typeof value === "string" && value ? value : null);

/**
 * The scan decision of an execution (docs/modules/scan-decisioning/SPEC.md 8): what changed, what each scan type got (`required` by the
 * deterministic floor with its stable rule ids, `added` by the assistant with its reason, `not_selected` with a stable reason code, or
 * `not_enabled`), the assistant status with provider and model, and the time. A FIELD ALLOWLIST over the stored row: no tenant id, no
 * workspace/repository/pipeline id, no record id, no schema version and no other internal column. The reason TEXTS of the required
 * rules are not in the API (the UI maps the stable ids); the agent summary and reasons are model-written untrusted text (render as text).
 * @param {any} d the stored decision (or null)
 * @param {Array<{ id: string, scanType: string }>} tasks the tasks of the execution
 */
export const toDecisionDto = (d, tasks) => {
  if (!d) return null;
  const floor = new Map((d.floor ?? []).map((f) => [f.scanType, f.ruleIds ?? []]));
  const added = new Map((d.agentAdditions ?? []).map((a) => [a.scanType, a.reason]));
  const notSelected = new Map((d.notSelected ?? []).map((n) => [n.scanType, n.reason]));
  const taskIds = new Map(tasks.map((t) => [t.scanType, t.id]));
  const summary = d.changeSummary && typeof d.changeSummary === "object" ? d.changeSummary : {};
  const usage = d.agentUsage && typeof d.agentUsage === "object" ? d.agentUsage : null;
  return {
    scanKind: d.scanKind,
    diff: {
      source: d.diffSource,
      status: d.diffStatus,
      changedTotal: d.changedTotal,
      summary: {
        byClass: countRecord(summary.byClass),
        byStatus: countRecord(summary.byStatus),
        additions: countOf(summary.additions),
        deletions: countOf(summary.deletions),
        samples: Object.fromEntries(
          Object.entries(
            summary.samples && typeof summary.samples === "object" ? summary.samples : {},
          ).map(([key, paths]) => [
            key,
            Array.isArray(paths) ? paths.filter((x) => typeof x === "string") : [],
          ]),
        ),
      },
    },
    secretsRule: d.secretsRule,
    scanTypes: SCAN_TASK_ORDER.map((scanType) => {
      const taskId = taskIds.get(scanType) ?? null;
      if (floor.has(scanType))
        return {
          scanType,
          state: "required",
          ruleIds: [...floor.get(scanType)],
          reason: null,
          taskId,
        };
      if (added.has(scanType))
        return { scanType, state: "added", ruleIds: [], reason: added.get(scanType), taskId };
      if (notSelected.has(scanType))
        return {
          scanType,
          state: "not_selected",
          ruleIds: [],
          reason: notSelected.get(scanType),
          taskId,
        };
      return { scanType, state: "not_enabled", ruleIds: [], reason: null, taskId };
    }),
    agent: {
      status: d.agentStatus,
      provider: textOrNull(d.agentProvider),
      model: textOrNull(d.agentModel),
      summary: textOrNull(d.agentSummary),
      usage: usage
        ? {
            inputTokens: countOf(usage.inputTokens),
            outputTokens: countOf(usage.outputTokens),
            latencyMs: countOf(usage.latencyMs),
          }
        : null,
    },
    decidedAt: iso(d.decidedAt),
  };
};

/**
 * Detail DTO: the list row plus the snapshot summary (version and a SHORT hash, never the configuration body), the requester's
 * display name (manual and retry only), the deadline, the cancel state, the tasks, `resolutionEligible` and `rev`.
 * @param {any} e execution row (list and detail columns)
 * @param {{ pipelineName?: string | null, repositoryName?: string | null, requestedByName?: string | null, tasks: any[], toolRuns?: any[], resolutionEligible: boolean, decision?: any }} parts
 */
export const toExecutionDetailDto = (e, parts) => {
  const runsOf = (taskId) => (parts.toolRuns ?? []).filter((r) => r.scanTaskId === taskId);
  const tasks = parts.tasks.map((t) => toTaskDto(t, runsOf(t.id)));
  const counts = Object.entries(
    tasks.reduce((acc, t) => ({ ...acc, [t.status]: (acc[t.status] ?? 0) + 1 }), {}),
  ).map(([status, count]) => ({ status, count }));
  return {
    ...toExecutionListDto(e, { ...parts, taskCounts: counts }),
    configVersion: e.configVersion,
    configHash: String(e.configHash).slice(0, 12),
    requestedBy:
      e.requestedByUserId && parts.requestedByName
        ? { id: e.requestedByUserId, displayName: parts.requestedByName }
        : null,
    baseRef: e.baseRef ?? null,
    deadlineAt: iso(e.deadlineAt),
    cancelRequestedAt: iso(e.cancelRequestedAt),
    cancelMode: e.cancelMode ?? null,
    tasks,
    resolutionEligible: parts.resolutionEligible,
    decision: toDecisionDto(parts.decision ?? null, parts.tasks),
    rev: e.statusRev,
  };
};

/** One history row. Only enums, reason codes and the actor KIND: no user id, no details blob, no correlation id. @param {any} ev */
export const toEventDto = (ev) => ({
  seq: ev.seq,
  at: iso(ev.at),
  type: ev.type,
  fromStatus: ev.fromStatus ?? null,
  toStatus: ev.toStatus ?? null,
  reason: ev.reason ?? null,
  actorType: ev.actorType,
});

/** One log line (already redacted at write time). @param {any} line */
export const toLogLineDto = (line) => ({
  seq: line.seq,
  at: iso(line.at),
  level: line.level,
  source: line.source,
  taskId: line.taskId ?? null,
  message: line.message,
});
