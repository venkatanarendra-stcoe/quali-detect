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

/**
 * Detail DTO: the list row plus the snapshot summary (version and a SHORT hash, never the configuration body), the requester's
 * display name (manual and retry only), the deadline, the cancel state, the tasks, `resolutionEligible` and `rev`.
 * @param {any} e execution row (list and detail columns)
 * @param {{ pipelineName?: string | null, repositoryName?: string | null, requestedByName?: string | null, tasks: any[], resolutionEligible: boolean }} parts
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
