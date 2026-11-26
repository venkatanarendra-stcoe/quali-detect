import { z } from "zod";
import { isValidTimeZone } from "./period.js";

/**
 * Tenant reporting time zone setting (docs/modules/reporting-dashboards/SPEC.md 8.4, 17.1 D-5, AS_BUILT_TZ.md). Contract of
 * `GET /reporting/settings` and `PUT /reporting/settings`; the zone decides which tenant-local day every report, rollup and chart uses.
 */

/** Longest accepted zone name (the validator of the tenant setting already refuses longer ones). */
export const REPORTING_TIMEZONE_MAX_LENGTH = 64;

/** The one name that is not in the runtime's region list. */
export const REPORTING_DEFAULT_TIMEZONE = "UTC";

/** @type {Set<string> | null} */
let canonical = null;

/**
 * The canonical zone names the runtime offers: `Intl.supportedValuesOf("timeZone")` plus `UTC`. The tenant app offers exactly this list
 * from the browser; the API refuses every other spelling (aliases such as `US/Pacific` or `Asia/Kolkata` when the runtime lists the legacy
 * name, `Etc/*`, wrong case, offsets) with a 400, so a stored zone is always one stable name.
 * @returns {ReadonlySet<string>}
 */
export function canonicalTimeZoneSet() {
  if (!canonical) {
    let list = [];
    try {
      list = Intl.supportedValuesOf("timeZone");
    } catch {
      list = [];
    }
    canonical = new Set([REPORTING_DEFAULT_TIMEZONE, ...list]);
  }
  return canonical;
}

/**
 * Whether `value` may be stored as the tenant reporting zone: a canonical name the runtime lists AND a zone the runtime can format with.
 * @param {unknown} value @returns {boolean}
 */
export const isCanonicalReportingTimeZone = (value) =>
  typeof value === "string" &&
  value.length <= REPORTING_TIMEZONE_MAX_LENGTH &&
  canonicalTimeZoneSet().has(value) &&
  isValidTimeZone(value);

/** PUT body. Strict: an unknown key (including `tenantId`) is a 400. */
export const updateReportingSettingsBodySchema = z
  .object({
    reportingTimezone: z
      .string()
      .min(1)
      .max(REPORTING_TIMEZONE_MAX_LENGTH)
      .refine(
        isCanonicalReportingTimeZone,
        "Choose a time zone from the list (an IANA name such as Europe/Berlin, or UTC).",
      ),
  })
  .strict();

/** The settings DTO (never the row, never an id or an e-mail: the display name of who last changed it, or null). */
export const reportingSettingsDtoSchema = z
  .object({
    reportingTimezone: z.string().min(1).max(REPORTING_TIMEZONE_MAX_LENGTH),
    updatedAt: z.string().datetime({ offset: true }).nullable(),
    updatedBy: z
      .object({ displayName: z.string().max(200) })
      .strict()
      .nullable(),
    recomputing: z.boolean(),
  })
  .strict();
