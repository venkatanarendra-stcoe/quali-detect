/**
 * The reporting settings DTO: the zone, when it was last changed, who changed it (display name only, resolved inside the tenant) and
 * whether a rebuild requested by a change has not finished. Never the row, an id or an e-mail.
 * @param {{ reportingTimezone: string, updatedAt: Date } | null} row @param {string | null} changedByName @param {boolean} recomputing
 */
export function toReportingSettingsDto(row, changedByName, recomputing) {
  return {
    reportingTimezone: row?.reportingTimezone ?? "UTC",
    updatedAt: row?.updatedAt?.toISOString() ?? null,
    updatedBy: typeof changedByName === "string" ? { displayName: changedByName } : null,
    recomputing: row ? recomputing === true : false,
  };
}
