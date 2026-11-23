import { toListItemDto } from "./index.js";

/**
 * DTO mappers of the remediation board and the SLA settings (Part C, docs/modules/findings/SPEC.md 8.1, SCREENS T-36). Never a Prisma
 * model: every field is named here. `canRemediate` is computed on the SERVER for THE CALLER so the UI never guesses; the PR link and
 * the ticket key of the latest submitted fix are the owner-approved additive card fields of 2026-11-24 (null when none).
 */

/** The statuses whose card the caller may move with a remediation action (start work, submit a fix). */
const MOVABLE = Object.freeze(["assigned", "in_remediation"]);

/**
 * `canRemediate` of one card for the caller (RM-1, SCREENS T-36): `finding.remediate`, the finding is assigned or in progress on a live
 * pipeline, and it is the caller's own unless they also hold `finding.assign`.
 * @param {{ status: string, pipelineDeleted: boolean, assigneeUserId: string | null }} card
 * @param {{ callerUserId: string, can: (key: string) => boolean }} context
 */
export function canRemediateCard(card, { callerUserId, can }) {
  if (!MOVABLE.includes(card.status) || card.pipelineDeleted) return false;
  if (!can("finding.remediate")) return false;
  return card.assigneeUserId === callerUserId || can("finding.assign");
}

/**
 * One board card: the list item plus `canRemediate`, `pullRequestUrl` and `ticketKey`.
 * @param {{ finding: any, pipeline: any, repository: any, claimedBy: any, assignee: any, advisoryHint: any, remediation?: { pullRequestUrl: string | null, ticketKey: string | null } | null }} entry
 * @param {Date} now
 * @param {{ callerUserId: string, can: (key: string) => boolean }} context
 */
export function toBoardCardDto(entry, now, context) {
  const item = toListItemDto(entry, now);
  return {
    ...item,
    canRemediate: canRemediateCard(
      {
        status: item.status,
        pipelineDeleted: item.pipeline.deleted,
        assigneeUserId: entry.finding.assigneeUserId ?? null,
      },
      context,
    ),
    pullRequestUrl: entry.remediation?.pullRequestUrl ?? null,
    ticketKey: entry.remediation?.ticketKey ?? null,
  };
}

/** `GET /settings/findings-sla` (`slaSettingsDtoSchema`): one row per severity. @param {Array<{ severity: string, hours: number | null, isDefault: boolean }>} targets */
export const toSlaSettingsDto = (targets) => ({
  targets: targets.map((t) => ({
    severity: t.severity,
    hours: t.hours,
    isDefault: t.isDefault,
  })),
});
