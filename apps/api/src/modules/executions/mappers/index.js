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
