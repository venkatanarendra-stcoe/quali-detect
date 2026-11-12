import { computeEffectiveState } from "@qmentisai/shared";

/** Effective state of a loaded pipeline row (it includes its repository and workspace). @param {any} p @param {string | null} [tenantStatus] */
export const effectiveStateOf = (p, tenantStatus = null) =>
  computeEffectiveState({
    tenantStatus,
    workspaceStatus: p.workspace.status,
    repositoryStatus: p.repository.status,
    repositoryEnabled: p.repository.enabled,
    pipelineEnabled: p.enabled,
    pipelineDeletedAt: p.deletedAt,
  });

/**
 * Pipeline DTO. Never a Prisma model: no tenant id, no stored config (versions are read through their own routes), no
 * provider ids. The repository name is shown only to callers who can see the repository.
 * @param {any} p pipeline row with repository, workspace, currentConfig, triggers
 * @param {{ tenantStatus?: string | null, canSeeRepository?: boolean, lastRequest?: any, counters?: { skippedByPolicyLast24h: number } }} [context]
 */
export function toPipelineDto(
  p,
  { tenantStatus = null, canSeeRepository = true, lastRequest = null, counters } = {},
) {
  return {
    id: p.id,
    workspaceId: p.workspaceId,
    repositoryId: p.repositoryId,
    name: p.name,
    description: p.description,
    enabled: p.enabled,
    effectiveState: effectiveStateOf(p, tenantStatus),
    repository: {
      id: p.repositoryId,
      name: canSeeRepository ? (p.repository.displayName ?? p.repository.fullName) : null,
    },
    currentVersion: p.currentConfig
      ? {
          version: p.currentConfig.version,
          configHash: p.currentConfig.configHash,
          createdAt: p.currentConfig.createdAt,
        }
      : null,
    triggers: p.triggers.map((t) => ({
      key: t.triggerKey,
      type: t.type,
      enabled: t.enabled,
      nextRunAt: t.nextFireAt,
    })),
    lastRequest: lastRequest
      ? {
          id: lastRequest.id,
          status: lastRequest.status,
          statusReason: lastRequest.statusReason ?? null,
          requestedAt: lastRequest.requestedAt,
        }
      : null,
    ...(counters ? { counters } : {}),
    createdAt: p.createdAt,
    updatedAt: p.updatedAt,
    deletedAt: p.deletedAt,
  };
}

/** Version summary (list item). @param {any} v @param {Map<string, string>} names */
export const toVersionSummaryDto = (v, names) => ({
  version: v.version,
  schemaVersion: v.schemaVersion,
  configHash: v.configHash,
  changeNote: v.changeNote,
  changeSummary: v.changeSummary ?? {},
  createdBy: v.createdByUserId
    ? { id: v.createdByUserId, name: names.get(v.createdByUserId) ?? null }
    : null,
  createdAt: v.createdAt,
});

/** One version with its full configuration (contains no secret by construction). @param {any} v @param {Map<string, string>} names */
export const toVersionDto = (v, names) => ({ ...toVersionSummaryDto(v, names), config: v.config });

/** Minimal execution row. @param {any} e */
export const toExecutionDto = (e) => ({
  id: e.id,
  status: e.status,
  statusReason: e.statusReason ?? null,
  triggerType: e.triggerType,
  refType: e.refType,
  refName: e.refName,
  pullRequestNumber: e.pullRequestNumber ?? null,
  commitSha: e.commitSha ?? null,
  scanKind: e.scanKind,
  trust: e.trust,
  requestedAt: e.requestedAt,
});

/**
 * Trigger decision row (policy skip) with its source type and the key that matches it: `scmDeliveryId` (scm_event),
 * `scheduleSlot` (schedule_slot, the nominal UTC slot) or `manualKey` (manual: only the caller-chosen idempotency value,
 * never the `manual:<userId>:` prefix of the stored key). The other two key fields are null.
 * @param {any} d
 */
export const toDecisionDto = (d) => ({
  id: d.id,
  decidedAt: d.decidedAt,
  decision: d.decision,
  reason: d.reason,
  sourceType: d.sourceType,
  scmDeliveryId: d.sourceType === "scm_event" ? (d.scmDeliveryId ?? null) : null,
  scheduleSlot: d.sourceType === "schedule_slot" ? (d.scheduleSlot ?? null) : null,
  manualKey:
    d.sourceType === "manual" && d.manualKey ? d.manualKey.split(":").slice(2).join(":") : null,
  triggerType: d.triggerType,
  triggerKey: d.triggerKey,
  refType: d.refType,
  refName: d.refName,
  pullRequestNumber: d.pullRequestNumber ?? null,
});
