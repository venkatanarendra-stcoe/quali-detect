import { SCAN_TASK_ORDER } from "@qmentisai/shared";
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

/**
 * One scan task of the detail DTO. The result summary has counts and flags only (no items, no locator).
 * @param {any} t task row with its (at most one) result
 */
export const toTaskDto = (t) => {
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
  };
};

const countOf = (value) => (Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0);
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
 * @param {{ pipelineName?: string | null, repositoryName?: string | null, requestedByName?: string | null, tasks: any[], resolutionEligible: boolean, decision?: any }} parts
 */
export const toExecutionDetailDto = (e, parts) => {
  const tasks = parts.tasks.map(toTaskDto);
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
