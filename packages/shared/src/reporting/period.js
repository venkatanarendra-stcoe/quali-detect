import {
  REPORT_DEFAULT_TIME_ZONE,
  REPORT_MAX_PERIOD_DAYS,
  REPORT_PERIOD_PRESETS,
} from "./constants.js";

/**
 * Period and time-zone arithmetic of the Reporting module (SPEC 17 D-5): ONE tenant reporting time zone (IANA), rollups keyed by the
 * tenant-LOCAL calendar day, ranges half-open `[from 00:00, to + 1 day 00:00)` in that zone, so a day is 23, 24 or 25 hours when the
 * zone changes its offset. Pure functions over `Intl.DateTimeFormat` (no `Date` local-time methods, no process time zone); day strings are
 * `YYYY-MM-DD` calendar days; instants are `Date` objects.
 */

/** A period that cannot be used; `code` is the stable `REPORT_*` error code the API answers. */
export class ReportPeriodError extends Error {
  /** @param {"REPORT_PERIOD_INVALID" | "REPORT_PERIOD_TOO_LONG"} code @param {string} message */
  constructor(code, message) {
    super(message);
    this.name = "ReportPeriodError";
    this.code = code;
  }
}

const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const ZONE_RE = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+){0,2}$/;
const formatters = new Map();

/** @param {string} timeZone */
function formatter(timeZone) {
  let f = formatters.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", {
      timeZone,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    formatters.set(timeZone, f);
  }
  return f;
}

/**
 * Whether `timeZone` is an IANA zone name the runtime knows (the validation of the tenant setting, SPEC 8.4). Offset forms (`+01:00`),
 * empty and over-long strings are refused.
 * @param {unknown} timeZone @returns {boolean}
 */
export function isValidTimeZone(timeZone) {
  if (typeof timeZone !== "string" || timeZone.length === 0 || timeZone.length > 64) return false;
  if (!ZONE_RE.test(timeZone)) return false;
  try {
    formatter(timeZone);
    return true;
  } catch {
    return false;
  }
}

/** @param {string} timeZone */
function assertZone(timeZone) {
  if (!isValidTimeZone(timeZone))
    throw new ReportPeriodError("REPORT_PERIOD_INVALID", "time zone is not valid");
}

const pad = (n, w = 2) => String(n).padStart(w, "0");
const dayString = (y, m, d) => `${pad(y, 4)}-${pad(m)}-${pad(d)}`;

/**
 * Whether `day` is a real calendar day `YYYY-MM-DD`.
 * @param {unknown} day @returns {boolean}
 */
export function isDayString(day) {
  if (typeof day !== "string") return false;
  const m = DAY_RE.exec(day);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const t = new Date(Date.UTC(y, mo - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d;
}

/** @param {string} day */
function parseDay(day) {
  if (!isDayString(day)) throw new ReportPeriodError("REPORT_PERIOD_INVALID", "not a calendar day");
  const m = /** @type {RegExpExecArray} */ (DAY_RE.exec(day));
  return { y: Number(m[1]), m: Number(m[2]), d: Number(m[3]) };
}

/**
 * The tenant-local calendar day of an instant (the rollup bucket).
 * @param {Date} instant @param {string} timeZone @returns {string}
 */
export function localDayOf(instant, timeZone) {
  assertZone(timeZone);
  if (!(instant instanceof Date) || Number.isNaN(instant.getTime()))
    throw new ReportPeriodError("REPORT_PERIOD_INVALID", "not an instant");
  /** @type {Record<string, number>} */
  const w = {};
  for (const p of formatter(timeZone).formatToParts(instant))
    if (p.type !== "literal") w[p.type] = Number(p.value);
  return dayString(w.year, w.month, w.day);
}

/**
 * Calendar arithmetic on a day string (zone independent).
 * @param {string} day @param {number} n whole days, may be negative @returns {string}
 */
export function addDays(day, n) {
  const { y, m, d } = parseDay(day);
  const t = new Date(Date.UTC(y, m - 1, d + n));
  return dayString(t.getUTCFullYear(), t.getUTCMonth() + 1, t.getUTCDate());
}

/**
 * Whole calendar days from `from` to `to` (0 when equal; negative when `to` is earlier).
 * @param {string} from @param {string} to @returns {number}
 */
export function diffDays(from, to) {
  const a = parseDay(from);
  const b = parseDay(to);
  return Math.round((Date.UTC(b.y, b.m - 1, b.d) - Date.UTC(a.y, a.m - 1, a.d)) / 86400000);
}

/**
 * The first instant of the tenant-local day: the earliest instant whose local calendar day is `day`. Exact on DST days (a zone whose
 * clock skips local midnight starts the day at the first existing instant). Pure; a binary search over the monotone local day.
 * @param {string} day @param {string} timeZone @returns {Date}
 */
export function dayStartInstant(day, timeZone) {
  assertZone(timeZone);
  const { y, m, d } = parseDay(day);
  const before = (t) => localDayOf(new Date(t), timeZone) < day;
  // The local day starts within +-15 hours of UTC midnight (every offset is within +-14h).
  const mid = Date.UTC(y, m - 1, d);
  let lo = mid - 15 * 3600000; // before(lo) is true
  let hi = mid + 15 * 3600000; // before(hi) is false
  while (hi - lo > 1) {
    const t = lo + Math.floor((hi - lo) / 2);
    if (before(t)) lo = t;
    else hi = t;
  }
  return new Date(hi);
}

/**
 * The half-open instant range of a tenant-local day and its length in hours (23, 24 or 25 around a DST change).
 * @param {string} day @param {string} timeZone
 * @returns {{ day: string, start: Date, endExclusive: Date, hours: number }}
 */
export function dayRange(day, timeZone) {
  const start = dayStartInstant(day, timeZone);
  const endExclusive = dayStartInstant(addDays(day, 1), timeZone);
  return { day, start, endExclusive, hours: (endExclusive.getTime() - start.getTime()) / 3600000 };
}

/**
 * Every calendar day from `from` to `to` inclusive. Throws `REPORT_PERIOD_TOO_LONG` above the 400 day limit.
 * @param {string} from @param {string} to @returns {string[]}
 */
export function listDays(from, to) {
  const n = diffDays(from, to);
  if (n < 0) throw new ReportPeriodError("REPORT_PERIOD_INVALID", "from is after to");
  if (n + 1 > REPORT_MAX_PERIOD_DAYS)
    throw new ReportPeriodError("REPORT_PERIOD_TOO_LONG", "period is longer than the limit");
  return Array.from({ length: n + 1 }, (_, i) => addDays(from, i));
}

/**
 * The tenant-local days covered by the half-open instant range `[start, endExclusive)` (empty for an empty range).
 * @param {Date} start @param {Date} endExclusive @param {string} timeZone @returns {string[]}
 */
export function listLocalDays(start, endExclusive, timeZone) {
  if (!(endExclusive.getTime() > start.getTime())) return [];
  return listDays(
    localDayOf(start, timeZone),
    localDayOf(new Date(endExclusive.getTime() - 1), timeZone),
  );
}

/**
 * @typedef {object} ResolvedPeriod
 * @property {string} from first tenant-local day (inclusive)
 * @property {string} to last tenant-local day (inclusive; today for a preset)
 * @property {number} dayCount
 * @property {Date} start instant of `from` 00:00 local
 * @property {Date} endExclusive instant of (`to` + 1 day) 00:00 local
 * @property {string} timeZone
 * @property {number | null} preset 7, 30 or 90, else null (custom)
 */

/**
 * Resolves a period request in the tenant time zone (SPEC 17 D-5): a preset N is the N tenant-local days ending TODAY inclusive
 * (today is partial); a custom period is `from` to `to` inclusive, `to` not after today, at most 400 days. Ranges are half-open
 * `[from 00:00, to + 1 day 00:00)`.
 * @param {{ period?: number | string, from?: string, to?: string }} request `period` 7, 30 or 90 (a string like "30" is accepted), or `from` and `to`
 * @param {{ now: Date, timeZone?: string }} context
 * @returns {ResolvedPeriod}
 * @throws {ReportPeriodError}
 */
export function resolvePeriod(request, { now, timeZone = REPORT_DEFAULT_TIME_ZONE }) {
  assertZone(timeZone);
  const today = localDayOf(now, timeZone);
  const hasRange = request.from !== undefined || request.to !== undefined;
  const preset = request.period === undefined ? undefined : Number(request.period);
  if (hasRange && preset !== undefined)
    throw new ReportPeriodError("REPORT_PERIOD_INVALID", "give a preset or from and to, not both");
  let from;
  let to;
  let usedPreset = null;
  if (hasRange) {
    if (
      request.from === undefined ||
      request.to === undefined ||
      !isDayString(request.from) ||
      !isDayString(request.to)
    )
      throw new ReportPeriodError(
        "REPORT_PERIOD_INVALID",
        "from and to must both be YYYY-MM-DD days",
      );
    from = request.from;
    to = request.to;
    if (from > to) throw new ReportPeriodError("REPORT_PERIOD_INVALID", "from is after to");
    if (to > today) throw new ReportPeriodError("REPORT_PERIOD_INVALID", "to is in the future");
  } else {
    const n = preset ?? 30;
    if (!REPORT_PERIOD_PRESETS.includes(n))
      throw new ReportPeriodError("REPORT_PERIOD_INVALID", "preset must be 7, 30 or 90");
    usedPreset = n;
    to = today;
    from = addDays(today, -(n - 1));
  }
  const dayCount = diffDays(from, to) + 1;
  if (dayCount > REPORT_MAX_PERIOD_DAYS)
    throw new ReportPeriodError("REPORT_PERIOD_TOO_LONG", "period is longer than the limit");
  return {
    from,
    to,
    dayCount,
    start: dayStartInstant(from, timeZone),
    endExclusive: dayStartInstant(addDays(to, 1), timeZone),
    timeZone,
    preset: usedPreset,
  };
}

/**
 * The instant at which a tenant-local day closes for rollup purposes (SPEC 7.2 `T = end of the tenant-local day`): the last millisecond
 * before the next local midnight, so "latest history row with `created_at <= T`" is exact.
 * @param {string} day @param {string} timeZone @returns {Date}
 */
export function dayCloseInstant(day, timeZone) {
  return new Date(dayStartInstant(addDays(day, 1), timeZone).getTime() - 1);
}
