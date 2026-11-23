import { toSlaSettingsDto } from "../mappers/board.js";

/**
 * The tenant's SLA targets (Part C, docs/modules/findings/SPEC.md 5.9 SL-1, 8.1, 8.2). The tenant comes from the session only: there is
 * no workspace or tenant id in the request. Reading is `tenant_settings.view`, changing `tenant_settings.manage` (both checked by the
 * route). The write replaces the targets (a severity left out goes back to the shared default), is validated by `putSlaBodySchema`
 * (1 to 87,600 hours, no `info`, no duplicate), and is audited in the SAME transaction as `tenant.findings_sla_changed` with the
 * previous and new hours of each severity that changed. Writing what is already stored changes nothing and writes no audit entry. A
 * change does not recompute running clocks: a finding keeps the due date its clock started with until it is reopened or its severity
 * changes (SL-1: not retroactive).
 * @param {{ repository: ReturnType<typeof import("../repositories/remediation.js").createFindingsRemediationRepository> }} deps
 */
export function createFindingsSlaService({ repository }) {
  return Object.freeze({
    /** `GET /settings/findings-sla`. @param {{ tenantId: string }} actor */
    async get(actor) {
      return toSlaSettingsDto(
        await repository.assignments.readSlaTargets({ tenantId: actor.tenantId }),
      );
    },

    /**
     * `PUT /settings/findings-sla`.
     * @param {{ tenantId: string, userId: string, requestId?: string, ip?: string }} actor
     * @param {{ targets: Array<{ severity: string, hours: number }> }} body validated `putSlaBodySchema` output
     */
    async put(actor, body) {
      return repository.transaction(async (tx) => {
        const { changes } = await repository.assignments.writeSlaTargets(
          tx,
          { tenantId: actor.tenantId },
          body.targets,
          actor.userId,
        );
        if (changes.length > 0) await repository.auditSlaChange(tx, actor, changes);
        return toSlaSettingsDto(
          await repository.assignments.readSlaTargets({ tenantId: actor.tenantId }, tx),
        );
      });
    },
  });
}
