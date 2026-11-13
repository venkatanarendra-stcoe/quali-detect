/**
 * Schedule evaluation for pipeline schedule triggers (docs/modules/pipelines-triggers/SPEC.md §5.6, §6.4, implementation
 * part E): the next and previous fire instant of a 5-field cron expression in an IANA time zone, the real minimum interval,
 * the slot key and the missed-run plan. Pure (no database, no clock unless passed in); shared by the API (validation,
 * `next_fire_at`) and the scheduler worker.
 *
 * Division of labor. `cron.js` is the grammar gate (what the platform accepts). The `croner` library matches the expression
 * against WALL-CLOCK time: it is asked in the "UTC" zone, on the naive local wall clock, where there is no daylight saving and
 * the answer is exact. This module then maps each nominal local time to a UTC instant with the runtime's time-zone database
 * (`Intl`), with the rules of SPEC §5.6 (croner's own time-zone mode shifts a nonexistent local time by the length of the
 * gap, 02:30 -> 03:30, which is not the rule the owner approved):
 * - a local time that does not exist (spring forward) fires ONCE at the end of the gap (the first valid instant after it);
 *   the exception is a wildcard or step hour field (`*`, `*\/n`, `0-23/3`): there the nominal times inside the gap are
 *   skipped, because a fire at the gap end would shorten the interval of an hourly schedule below the platform minimum;
 * - a local time that occurs twice (fall back) fires once, at its FIRST occurrence (named hours, and step hours N > 1 such as
 *   `0 *\/2`); only a wildcard hour (`*`, `*\/1`) fires at EVERY real occurrence (once per real hour: `30 * * * *` fires 25
 *   times on a fall-back day), so an hourly schedule keeps its hour (owner decision 2026-11-13 follow-up);
 * - the slot is the UTC instant of that fire, never changed by jitter.
 */
import { Cron } from "croner";
import { isKnownTimeZone, parseCron } from "./cron.js";

const HOUR_MS = 3600000;
const DAY_MS = 86400000;
/** How far ahead an expression is searched for fires (8 years: a 29 February schedule fires within it). */
export const SCHEDULE_HORIZON_DAYS = 366 * 8;
/** Occurrences measured for the minimum interval (SPEC §5.6). */
const MEASURED_OCCURRENCES = 50;
/** Cap of fires measured in one daylight-saving window (a schedule that dense is refused by the first measurement anyway). */
const WINDOW_FIRE_CAP = 400;

const formatters = new Map();
/** @param {string} timeZone */
function formatterOf(timeZone) {
  let f = formatters.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", {
      timeZone,
      hourCycle: "h23",
      year: "numeric",
      month: "numeric",
      day: "numeric",
      hour: "numeric",
      minute: "numeric",
      second: "numeric",
    });
    formatters.set(timeZone, f);
  }
  return f;
}

/**
 * Offset of a zone from UTC at an instant, in milliseconds (local wall clock minus UTC).
 * @param {string} timeZone @param {number} ms
 */
export function zoneOffsetMs(timeZone, ms) {
  const v = {};
  for (const part of formatterOf(timeZone).formatToParts(new Date(ms)))
    if (part.type !== "literal") v[part.type] = Number(part.value);
  const wall = Date.UTC(v.year, v.month - 1, v.day, v.hour % 24, v.minute, v.second);
  return wall - Math.floor(ms / 1000) * 1000;
}

/**
 * Maps a nominal local wall-clock time (as the UTC milliseconds of the NAIVE time) to the instant it fires at.
 * @param {string} timeZone @param {number} wallMs
 * @returns {{ instant: number, instants: number[], kind: "normal" | "overlap" | "gap" }} `instant` is the first valid
 * instant (the gap end for a time that does not exist); `instants` are all valid ones (two for a repeated time)
 */
export function wallToInstant(timeZone, wallMs) {
  const before = zoneOffsetMs(timeZone, wallMs - DAY_MS);
  const after = zoneOffsetMs(timeZone, wallMs + DAY_MS);
  const valid = [...new Set([before, after])]
    .map((offset) => wallMs - offset)
    .filter((instant) => zoneOffsetMs(timeZone, instant) === wallMs - instant);
  if (valid.length > 0) {
    const instants = [...valid].sort((a, b) => a - b);
    return { instant: instants[0], instants, kind: instants.length > 1 ? "overlap" : "normal" };
  }
  // The local time does not exist: the end of the gap is the instant the offset changes.
  let lo = wallMs - DAY_MS;
  let hi = wallMs + DAY_MS;
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2);
    if (zoneOffsetMs(timeZone, mid) === before) lo = mid;
    else hi = mid;
  }
  return { instant: hi, instants: [hi], kind: "gap" };
}

/** @param {string} expression the whitespace-normalized expression */
const normalize = (expression) => expression.trim().split(/\s+/).join(" ");

/** The entries of the hour field. @param {string} expression */
const hourEntries = (expression) => normalize(expression).split(" ")[1].split(",");

/** Hour entries that cover the whole day with step 1: `*\/1`, `0-23\/1`. */
const FULL_RANGE_STEP_1 = new Set(["*/1", "0-23/1"]);

/**
 * Wildcard hour: some entry is `*` or a full-range step of 1 (`*\/1`, `0-23\/1`), i.e. every hour. Fires at EVERY real
 * occurrence of a repeated hour (25 on a fall-back day).
 */
const isWildcardHour = (expression) =>
  hourEntries(expression).some((entry) => entry === "*" || FULL_RANGE_STEP_1.has(entry));

/** Step hour: some entry has a step N > 1 (`*\/2`, `0-23/3`). Skips gap times (spring forward) but fires ONCE in a repeated hour. */
const isStepHour = (expression) =>
  hourEntries(expression).some((entry) => {
    const step = entry.split("/")[1];
    return step !== undefined && Number(step) > 1;
  });

const crons = new Map();
/** @param {string} expression */
function cronOf(expression) {
  const key = normalize(expression);
  let cron = crons.get(key);
  if (!cron) {
    if (crons.size > 500) crons.clear();
    cron = new Cron(key, { timezone: "UTC" });
    crons.set(key, cron);
  }
  return cron;
}

/**
 * The fire instants of a schedule strictly after `afterMs`, increasing, each once, within the horizon.
 * @param {string} expression @param {string} timeZone @param {number} afterMs @param {number} [horizonMs]
 * @returns {Generator<number>}
 */
function* fires(expression, timeZone, afterMs, horizonMs = SCHEDULE_HORIZON_DAYS * DAY_MS) {
  const cron = cronOf(expression);
  const wildcard = isWildcardHour(expression);
  const skipsGap = wildcard || isStepHour(expression);
  const limit = afterMs + horizonMs;
  // Start four hours earlier on the wall clock: a zone offset moves by at most two hours, so every fire after `afterMs` is seen.
  let wall = afterMs + zoneOffsetMs(timeZone, afterMs) - 4 * HOUR_MS;
  let last = afterMs;
  for (;;) {
    const next = cron.nextRun(new Date(wall));
    if (!next) return;
    wall = next.getTime();
    const { instants, kind } = wallToInstant(timeZone, wall);
    if (kind === "gap" && skipsGap) continue;
    // a repeated time fires at its first occurrence only (named hours and step hours N > 1), except for a wildcard hour: it
    // fires at every real occurrence, i.e. once per REAL hour (a fall-back day has 25)
    for (const instant of kind === "overlap" && !wildcard ? instants.slice(0, 1) : instants) {
      if (instant <= last) continue;
      if (instant > limit) return;
      last = instant;
      yield instant;
    }
  }
}

/**
 * The first fire instant strictly after `after`, or null (the schedule never fires within the horizon).
 * @param {string} expression 5-field cron @param {string} timeZone IANA name @param {Date | number} after
 * @returns {Date | null}
 */
export function nextFireAfter(expression, timeZone, after) {
  const { value } = fires(expression, timeZone, new Date(after).getTime()).next();
  return value === undefined ? null : new Date(value);
}

/**
 * The last fire instant before `before` (or at it when `inclusive`), or null when none lies within the lookback.
 * @param {string} expression @param {string} timeZone @param {Date | number} before @param {{ inclusive?: boolean }} [options]
 * @returns {Date | null}
 */
export function previousFireBefore(expression, timeZone, before, { inclusive = false } = {}) {
  const target = new Date(before).getTime();
  for (const days of [2, 14, 70, 400, SCHEDULE_HORIZON_DAYS]) {
    let last = null;
    for (const t of fires(expression, timeZone, target - days * DAY_MS, days * DAY_MS + 1)) {
      if (t > target || (t === target && !inclusive)) break;
      last = t;
    }
    if (last !== null) return new Date(last);
  }
  return null;
}

/** The slot key: the nominal UTC instant as an ISO string (the `schedule_slot` column and the idempotency key). @param {Date} date */
export const slotKey = (date) => date.toISOString();

/** @param {Iterable<number>} instants @param {number} cap @returns {{ min: number | null, count: number }} */
function measure(instants, cap) {
  let previous = null;
  let min = null;
  let count = 0;
  for (const t of instants) {
    if (previous !== null && (min === null || t - previous < min)) min = t - previous;
    previous = t;
    count += 1;
    if (count >= cap) break;
  }
  return { min, count };
}

/**
 * The real minimum gap, in seconds, between two consecutive fires: over the next 50 occurrences and over every
 * daylight-saving transition of the zone within `horizonDays` (a window of two days either side of each), because a
 * transition can shorten a gap. Null when fewer than two fires were seen.
 * @param {string} expression @param {string} timeZone
 * @param {{ from?: Date, horizonDays?: number }} [options]
 * @returns {{ count: number, minGapSeconds: number | null }}
 */
export function minimumIntervalSeconds(
  expression,
  timeZone,
  { from = new Date(), horizonDays = 400 } = {},
) {
  const start = from.getTime();
  const first = measure(fires(expression, timeZone, start), MEASURED_OCCURRENCES);
  let min = first.min;
  let previousOffset = zoneOffsetMs(timeZone, start);
  for (let d = 1; d <= horizonDays; d += 1) {
    const at = start + d * DAY_MS;
    const offset = zoneOffsetMs(timeZone, at);
    if (offset !== previousOffset) {
      const window = measure(
        fires(expression, timeZone, at - 3 * DAY_MS, 6 * DAY_MS),
        WINDOW_FIRE_CAP,
      );
      if (window.min !== null && (min === null || window.min < min)) min = window.min;
    }
    previousOffset = offset;
  }
  return { count: first.count, minGapSeconds: min === null ? null : min / 1000 };
}

/**
 * Validates a schedule: grammar (5 fields; no seconds, `@reboot`, `L`, `W`, `#`), time zone, that it fires at all, and the
 * real minimum interval. Never throws.
 * @param {{ expression: string, timeZone: string, minIntervalSeconds?: number, now?: Date }} input
 * `minIntervalSeconds` 0 (or less) validates the syntax and the zone only, without evaluating fires (cheap re-validation).
 * @returns {{ ok: true, minGapSeconds: number | null, expression: string } | { ok: false, code: "invalid_expression" | "unknown_time_zone" | "never_fires" | "too_frequent", message: string }}
 */
export function validateSchedule({
  expression,
  timeZone,
  minIntervalSeconds = 0,
  now = new Date(),
}) {
  if (!isKnownTimeZone(timeZone))
    return { ok: false, code: "unknown_time_zone", message: "This is not a known IANA time zone." };
  let clean;
  try {
    parseCron(expression);
    clean = normalize(expression);
    cronOf(clean);
  } catch (error) {
    return {
      ok: false,
      code: "invalid_expression",
      message:
        error instanceof RangeError || error instanceof TypeError
          ? "This is not a supported cron expression."
          : error.message,
    };
  }
  if (!(minIntervalSeconds > 0)) return { ok: true, minGapSeconds: null, expression: clean };
  const { count, minGapSeconds } = minimumIntervalSeconds(clean, timeZone, { from: now });
  if (count === 0) return { ok: false, code: "never_fires", message: "This schedule never fires." };
  if (minGapSeconds !== null && minGapSeconds < minIntervalSeconds)
    return {
      ok: false,
      code: "too_frequent",
      message: `Runs must be at least ${minIntervalSeconds} seconds apart (the shortest gap of this schedule is ${minGapSeconds} seconds, counting daylight-saving changes).`,
    };
  return { ok: true, minGapSeconds, expression: clean };
}

/**
 * 32-bit FNV-1a with a murmur3 finalizer: pure (this module is also bundled into the browser, so no `node:crypto`), stable
 * across runtimes and well spread for jitter. Not a security hash. @param {string} text @returns {number} unsigned 32-bit
 */
function hash32(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

/**
 * Deterministic jitter of one slot (SPEC §5.6, owner decision 2026-11-13): `hash(triggerId + slot) mod window`, in whole
 * seconds. The same trigger and slot always give the same offset (so a retry, a second scheduler instance and the
 * `next_fire_at` computation of the API all agree); other slots and other triggers spread over the window. It is only
 * added to the FIRE time: the slot (the `schedule_slot` key, the idempotency key) is the nominal UTC instant, never moved.
 * @param {string} triggerId @param {Date | number} slot @param {number} windowSeconds `PIPELINE_SCHEDULE_JITTER_SECONDS`
 * @returns {number} an integer in `[0, windowSeconds)`, 0 when the window is 0
 */
export function jitterOffsetSeconds(triggerId, slot, windowSeconds) {
  if (!(windowSeconds > 0)) return 0;
  return hash32(`${triggerId}:${new Date(slot).toISOString()}`) % windowSeconds;
}

/** @param {string} triggerId @param {number} slotMs @param {number} windowSeconds */
const fireAtOf = (triggerId, slotMs, windowSeconds) =>
  slotMs + jitterOffsetSeconds(triggerId, slotMs, windowSeconds) * 1000;

/**
 * The next slot strictly after `after` and its planned fire time (slot + the jitter of THAT slot). The one function the API
 * (`next_fire_at` on create, edit and enable) and the scheduler handler (the advance) use.
 * @param {{ expression: string, timeZone: string, after: Date, triggerId: string, jitterWindowSeconds?: number }} input
 * @returns {{ slot: Date, fireAt: Date } | null}
 */
export function nextScheduledFire({
  expression,
  timeZone,
  after,
  triggerId,
  jitterWindowSeconds = 0,
}) {
  const slot = nextFireAfter(expression, timeZone, after);
  return slot
    ? { slot, fireAt: new Date(fireAtOf(triggerId, slot.getTime(), jitterWindowSeconds)) }
    : null;
}

/**
 * What to do with a due schedule trigger (SPEC §5.6 missed runs, §6.4). `nextFireAt` is the stored planned fire time of
 * the first pending slot (that slot plus ITS jitter; the slot is recovered from it). Of all pending slots only the LATEST
 * one whose fire time has come is considered:
 * - `run_once` fires it when it is not later than `maxLatenessSeconds`, otherwise it is recorded as one missed run;
 * - `skip` ("fire only when on time") fires it only when it is not later than `onTimeGraceSeconds`, otherwise it is a missed run.
 * The advance is the planned time of the first slot after the handled one, so a crash or a long pause never double-fires
 * and never replays old slots. Lateness is measured from the planned fire time (slot + jitter).
 * @param {{
 *   expression: string, timeZone: string, triggerId: string, jitterWindowSeconds?: number, nextFireAt: Date, now: Date,
 *   missedPolicy: "skip" | "run_once", maxLatenessSeconds: number, onTimeGraceSeconds: number,
 * }} input
 * @returns {{ action: "fire" | "missed" | "none", slot: Date | null, latenessSeconds: number, skippedEarlier: boolean, nextFireAt: Date | null }}
 */
export function planScheduledFire({
  expression,
  timeZone,
  triggerId,
  jitterWindowSeconds = 0,
  nextFireAt,
  now,
  missedPolicy,
  maxLatenessSeconds,
  onTimeGraceSeconds,
}) {
  const maxJitterMs = Math.max(0, jitterWindowSeconds - 1) * 1000;
  const nowMs = now.getTime();
  // the first pending slot: the one whose planned fire time is the stored time
  let firstPending = null;
  for (const t of fires(
    expression,
    timeZone,
    nextFireAt.getTime() - maxJitterMs - 1,
    maxJitterMs + 2,
  ))
    if (fireAtOf(triggerId, t, jitterWindowSeconds) === nextFireAt.getTime()) {
      firstPending = t;
      break;
    }
  // the latest slot whose planned fire time has come
  let latest = null;
  if (firstPending !== null) {
    let candidate = previousFireBefore(expression, timeZone, now, { inclusive: true });
    while (candidate && candidate.getTime() >= firstPending) {
      if (fireAtOf(triggerId, candidate.getTime(), jitterWindowSeconds) <= nowMs) {
        latest = candidate;
        break;
      }
      candidate = previousFireBefore(expression, timeZone, candidate);
    }
  }
  if (!latest) {
    // the stored time is not a slot of this schedule (edited by hand): create nothing, move on to the first slot not yet due
    let next = null;
    for (const t of fires(expression, timeZone, nowMs - maxJitterMs - 1)) {
      const fireAt = fireAtOf(triggerId, t, jitterWindowSeconds);
      if (fireAt > nowMs) {
        next = new Date(fireAt);
        break;
      }
    }
    return {
      action: "none",
      slot: null,
      latenessSeconds: 0,
      skippedEarlier: false,
      nextFireAt: next,
    };
  }
  const latenessSeconds = Math.max(
    0,
    (nowMs - fireAtOf(triggerId, latest.getTime(), jitterWindowSeconds)) / 1000,
  );
  const allowed = missedPolicy === "skip" ? onTimeGraceSeconds : maxLatenessSeconds;
  const next = nextScheduledFire({
    expression,
    timeZone,
    after: latest,
    triggerId,
    jitterWindowSeconds,
  });
  return {
    action: latenessSeconds <= allowed ? "fire" : "missed",
    slot: latest,
    latenessSeconds,
    skippedEarlier: latest.getTime() > firstPending,
    nextFireAt: next?.fireAt ?? null,
  };
}
