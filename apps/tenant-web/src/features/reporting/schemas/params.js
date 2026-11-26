import {
  FINDING_SEVERITIES,
  REPORT_MAX_PERIOD_DAYS,
  REPORT_PERIOD_PRESETS,
  diffDays,
  isDayString,
  localDayOf,
  isValidTimeZone,
} from "@qmentisai/shared";
import { DEFAULT_PERIOD } from "../constants/index.js";

/**
 * URL state of the reporting screens (SCREENS 1): `period` (7, 30, 90), `from` and `to` (custom), `sev`, `view`, `asOf`. Every
 * value is read defensively: an unknown value is dropped, never sent to the API (which answers 400 for it).
 */

/** The tenant-local "today" in a zone (UTC when the zone is unknown). @param {string} [timeZone] @param {Date} [now] */
export function todayIn(timeZone, now = new Date()) {
  return localDayOf(now, timeZone && isValidTimeZone(timeZone) ? timeZone : "UTC");
}

/**
 * Validates a custom range typed by the person. Returns the inline message, or "" when it is acceptable. `to` may be today
 * (partial day) but not later; at most 400 days (SCREENS 1).
 * @param {string} from @param {string} to @param {string} today
 */
export function customRangeError(from, to, today) {
  if (!isDayString(from) || !isDayString(to)) return "Enter both days.";
  if (from > to) return "From must not be after To.";
  if (to > today) return "To cannot be in the future.";
  if (diffDays(from, to) + 1 > REPORT_MAX_PERIOD_DAYS)
    return `The range is longer than ${REPORT_MAX_PERIOD_DAYS} days. Choose a shorter range.`;
  return "";
}

/**
 * Reads the period of the URL. A custom range that fails validation falls back to the default preset and is reported in
 * `invalid`, so the screen can show the reason and never calls the API with it.
 * @param {URLSearchParams} params @param {string} today the tenant-local day
 */
export function readPeriod(params, today) {
  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";
  if (from || to) {
    const message = customRangeError(from, to, today);
    if (!message) return { kind: "custom", from, to, query: { from, to }, invalid: "" };
    return {
      kind: "preset",
      period: DEFAULT_PERIOD,
      query: { period: String(DEFAULT_PERIOD) },
      invalid: message,
      from,
      to,
    };
  }
  const asked = Number(params.get("period"));
  const period = REPORT_PERIOD_PRESETS.includes(asked) ? asked : DEFAULT_PERIOD;
  return { kind: "preset", period, query: { period: String(period) }, invalid: "" };
}

/** @param {URLSearchParams} params */
export function readSeverities(params) {
  const wanted = (params.get("sev") ?? "").split(",").map((v) => v.trim());
  return FINDING_SEVERITIES.filter((s) => wanted.includes(s));
}

/** `chart` (default) or `table` (T-21). @param {URLSearchParams} params */
export const readView = (params) => (params.get("view") === "table" ? "table" : "chart");

/** A past day (`asOf`) or "" for live. @param {URLSearchParams} params @param {string} today */
export function readAsOf(params, today) {
  const value = params.get("asOf") ?? "";
  return isDayString(value) && value < today ? value : "";
}
