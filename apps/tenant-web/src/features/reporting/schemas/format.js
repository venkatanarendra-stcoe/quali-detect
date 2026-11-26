import { isValidTimeZone } from "@qmentisai/shared";

/** Number formatting and the "data as of" words of the reporting screens. */

const NUMBER = new Intl.NumberFormat(undefined);
export const formatCount = (n) => (n === null || n === undefined ? "—" : NUMBER.format(n));

/** "9.4 d" or "—". @param {number | null | undefined} days */
export const formatDays = (days) =>
  days === null || days === undefined ? "—" : `${NUMBER.format(Math.round(days * 10) / 10)} d`;

/** "92%" from a 0..1 rate. @param {number | null | undefined} rate */
export const formatPercent = (rate) =>
  rate === null || rate === undefined ? "—" : `${NUMBER.format(Math.round(rate * 1000) / 10)}%`;

const safeZone = (zone) => (zone && isValidTimeZone(zone) ? zone : "UTC");

/** "14:02" in the tenant zone. @param {string} iso @param {string} [timeZone] */
export function clockIn(iso, timeZone) {
  return new Date(iso).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    timeZone: safeZone(timeZone),
  });
}

/** "14 Mar 2026, 14:02 (Europe/Berlin)". @param {string} iso @param {string} [timeZone] */
export function exactIn(iso, timeZone) {
  const zone = safeZone(timeZone);
  return `${new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: zone,
  })} (${zone})`;
}

/**
 * The footer of a card (SCREENS 1): "Live · updated 14:02" or "Daily rollup · as of 13:00 (Europe/Berlin)".
 * @param {{ asOf: string, source: string, timeZone: string }} meta
 */
export function footerText(meta) {
  if (meta.source === "live") return `Live · updated ${clockIn(meta.asOf, meta.timeZone)}`;
  return `Daily rollup · as of ${clockIn(meta.asOf, meta.timeZone)} (${meta.timeZone})`;
}

/** "14 Mar" from a day string, never a Date in the viewer's zone (a day is a calendar label). @param {string} day */
export function dayLabel(day) {
  const [y, m, d] = day.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    timeZone: "UTC",
  });
}
/** "Mon 14 Mar 2026" from a day string. @param {string} day */
export function dayLong(day) {
  const [y, m, d] = day.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString(undefined, {
    weekday: "short",
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  });
}

/** Words for a change: "down 14", "up 1", "no change" (an arrow icon is added by the caller, never colour alone). @param {number} delta */
export function changeWords(delta) {
  if (delta === 0) return "no change";
  return `${delta < 0 ? "down" : "up"} ${NUMBER.format(Math.abs(delta))}`;
}

/** Whole-byte size in words. @param {number | null | undefined} bytes */
export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
