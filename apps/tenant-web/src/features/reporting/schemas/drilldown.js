import { GROUP_STATUSES } from "../constants/index.js";

/**
 * Drill-down links into the Findings list. They use EXACTLY the URL parameters `readFindingFilters` accepts
 * (`apps/tenant-web/src/features/findings/schemas/filters.js`): `view` (a saved view), `severity`, `status`, `sla`, `pipeline`,
 * `repository`, `assignee`. A tile count and the list it opens agree because both come from the open statuses (`all_open`) or the
 * same status list. A filter the list does not accept (an age bucket, "new in 24 hours", "fixed in the period") has NO link.
 */

const list = (value) => (Array.isArray(value) ? value.join(",") : value);

/**
 * @param {string} workspaceId
 * @param {{ view?: string, severity?: string | string[], status?: string | string[], sla?: string, pipeline?: string,
 *   repository?: string, assignee?: string }} [filters]
 */
export function findingsUrl(workspaceId, filters = {}) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    const text = list(value);
    if (text) query.set(key, text);
  }
  const suffix = query.toString();
  return `/workspaces/${workspaceId}/findings${suffix ? `?${suffix}` : ""}`;
}

/** Open findings, optionally of some severities (the `all_open` saved view). */
export const openFindingsUrl = (workspaceId, severity) =>
  findingsUrl(workspaceId, { view: "all_open", severity });

/** Open findings of one SLA state; `breached` uses the `breached_sla` saved view like the Findings SLA card. */
export const slaFindingsUrl = (workspaceId, slaFilter, severity) =>
  slaFilter === "breached"
    ? findingsUrl(workspaceId, { view: "breached_sla", severity })
    : findingsUrl(workspaceId, { view: "all_open", sla: slaFilter, severity });

/** The statuses of one lifecycle group. */
export const groupFindingsUrl = (workspaceId, groupId) =>
  findingsUrl(workspaceId, { status: GROUP_STATUSES[groupId] });

export const findingUrl = (workspaceId, findingId) =>
  `/workspaces/${workspaceId}/findings/${findingId}`;
