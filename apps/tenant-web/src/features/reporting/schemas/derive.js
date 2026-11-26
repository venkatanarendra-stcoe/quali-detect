import { LIFECYCLE_GROUP_IDS } from "@qmentisai/shared";
import { GROUP_LABELS, SEVERITY_LABELS, SEVERITY_ORDER } from "../constants/index.js";
import { dayLabel, formatCount, formatDays } from "./format.js";

/** Pure derivations over the DTOs: the one-sentence chart summaries, the empty-state decisions and the changes since the period start. */

export const sumOf = (obj) => Object.values(obj ?? {}).reduce((a, b) => a + b, 0);

/** The points of a trends DTO whose FLOW series are known (a number, never a gap). @param {any} trends */
export const dataPoints = (trends) =>
  trends.points.filter((p) => p.new !== null && p.new !== undefined);

/** The points whose STATE series (open by severity, backlog, awaiting verification) exist: forward-only, from `stateSeriesFrom`. @param {any} trends */
export const statePoints = (trends) => trends.points.filter((p) => p.openBySeverity);

/**
 * Change from the first to the last day with a known value, or null when there are fewer than two days. A null (gap) is skipped,
 * never read as 0.
 * @param {any} trends @param {(point: any) => number | null | undefined} pick
 */
export function changeOver(trends, pick) {
  const points = trends.points.filter((p) => pick(p) !== undefined && pick(p) !== null);
  if (points.length < 2) return null;
  return pick(points[points.length - 1]) - pick(points[0]);
}

/** Total of one flow field over the days that have it. */
export const flowTotal = (trends, key) => dataPoints(trends).reduce((a, p) => a + (p[key] ?? 0), 0);

/** `"empty"` when the workspace never had a finding (a null count is "not available", never none), else null. @param {any} posture */
export const postureEmpty = (posture) =>
  posture.byStatus && sumOf(posture.byStatus) === 0 ? "empty" : null;

/**
 * The state charts (open by severity, burn-down, awaiting verification): `"empty"` before any exact day exists, `"period"` when the
 * period ends before `stateSeriesFrom` or holds no known day, else null. @param {any} trends
 */
export function trendsEmpty(trends) {
  // findings may well exist: the per-day open series is forward-only and has simply not started recording yet
  if (trends.stateSeriesFrom === null) return "notrecorded";
  return statePoints(trends).length === 0 ? "period" : null;
}

/** The flow charts (new, fixed, closed, reopened): `"empty"` without a rollup day, `"period"` when nothing happened in the period. @param {any} trends */
export function flowEmpty(trends) {
  if (trends.dataFrom === null) return "empty";
  return dataPoints(trends).some(
    (p) => (p.new ?? 0) + (p.fixed ?? 0) + (p.closedWithoutFix ?? 0) + (p.reopened ?? 0) > 0,
  )
    ? null
    : "period";
}

/**
 * The visible note of a forward-only chart, once per chart: "Severity trend starts on 17 Nov: earlier days were not recorded".
 * Null when the whole period is covered. @param {any} trends @param {string} [what]
 */
export function forwardOnlyNote(trends, what = "Severity trend") {
  if (!trends.stateSeriesFrom || trends.period.from >= trends.stateSeriesFrom) return null;
  return `${what} starts on ${dayLabel(trends.stateSeriesFrom)}: earlier days were not recorded.`;
}

const plural = (n, one, many = `${one}s`) => `${formatCount(n)} ${n === 1 ? one : many}`;

export function postureSummary(posture) {
  if (!posture.bySeverity || posture.open === null)
    return "These counts are not available for this view.";
  const parts = SEVERITY_ORDER.map(
    (s) => `${formatCount(posture.bySeverity[s])} ${SEVERITY_LABELS[s].toLowerCase()}`,
  );
  return `${plural(posture.open, "open finding")}: ${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}.`;
}

export function lifecycleSummary(posture) {
  if (!posture.byGroup || posture.open === null)
    return "These counts are not available for this view.";
  const open = LIFECYCLE_GROUP_IDS.slice(0, 4).map(
    (g) => `${formatCount(posture.byGroup[g])} ${GROUP_LABELS[g].toLowerCase()}`,
  );
  return `Of ${plural(posture.open, "open finding")}, ${open.slice(0, -1).join(", ")} and ${open.at(-1)}. Closed: ${formatCount(posture.byGroup.accepted_or_suppressed)} accepted or suppressed, ${formatCount(posture.byGroup.false_positive)} false positive, ${formatCount(posture.byGroup.fixed)} fixed.`;
}

export function flowSummary(trends, days) {
  const fresh = flowTotal(trends, "new");
  const fixed = flowTotal(trends, "fixed");
  const closed = flowTotal(trends, "closedWithoutFix");
  const reopened = flowTotal(trends, "reopened");
  return `In ${days} days ${plural(fresh, "new finding")} were found, ${formatCount(fixed)} were fixed, ${formatCount(closed)} were closed without a fix and ${formatCount(reopened)} were reopened.`;
}

export function openChangeSummary(trends, days) {
  const points = statePoints(trends);
  if (points.length < 2) return "Not enough days of data to describe a change yet.";
  const first = points[0];
  const last = points[points.length - 1];
  const total = (p) => sumOf(p.openBySeverity);
  const a = total(first);
  const b = total(last);
  const critical = last.openBySeverity.critical - first.openBySeverity.critical;
  const verb = b < a ? "fell" : b > a ? "rose" : "stayed";
  const crit =
    critical === 0
      ? "critical did not change"
      : `critical ${critical < 0 ? "fell" : "rose"} by ${formatCount(Math.abs(critical))}`;
  return b === a
    ? `Open findings stayed at ${formatCount(b)} over ${days} days; ${crit}.`
    : `Open findings ${verb} from ${formatCount(a)} to ${formatCount(b)} over ${days} days; ${crit}.`;
}

export function slaSummary(sla) {
  const t = sla.open.total;
  const all = t.onTrack + t.dueSoon + t.breached;
  return `${formatCount(t.breached)} of ${plural(all, "open finding")} with an SLA ${t.breached === 1 ? "is" : "are"} breached; ${formatCount(t.dueSoon)} ${t.dueSoon === 1 ? "is" : "are"} due soon.`;
}

export function executionSummary(scan, days) {
  const total = scan.perDay.reduce((a, d) => a + d.total, 0);
  const rate = scan.successRate.rate;
  return `${plural(total, "execution")} in ${days} days${rate === null ? "." : `; ${formatCount(Math.round(rate * 1000) / 10)}% of the ones with a result succeeded.`}`;
}

export function remediationSummary(rem) {
  const o = rem.timeToRemediate.overall;
  if (o.count === 0) return "No findings were fixed in this period.";
  return `${plural(o.count, "finding")} fixed; the median time to remediate is ${formatDays(o.medianDays)}, 9 in 10 took ${formatDays(o.p90Days)} or less.`;
}
