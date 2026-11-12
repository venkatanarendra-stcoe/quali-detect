/**
 * Restricted 5-field cron (SPEC §5.6): `minute hour day-of-month month day-of-week`, lists, ranges and steps, names
 * (`JAN`, `MON`); no seconds, no `@reboot`, no `L`, `W`, `#`, `?`. Day-of-week accepts 0 to 7 (0 and 7 are Sunday).
 * When both day-of-month and day-of-week are restricted a day matches when EITHER matches (classic cron).
 *
 * This module is the GRAMMAR GATE only (what the platform accepts). Evaluating a schedule (time zones, daylight saving, the
 * real fire instants and the real minimum interval) is `schedule.js`, which uses the `croner` library for the cron matching.
 * Steps need a wildcard or a range (for example `*` or `0-30` followed by `/15`); a bare number with a step (`5/20`) is
 * rejected because the evaluator does not accept it either.
 */

const MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
const DAYS = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

const FIELDS = [
  { name: "minute", min: 0, max: 59 },
  { name: "hour", min: 0, max: 23 },
  { name: "day-of-month", min: 1, max: 31 },
  { name: "month", min: 1, max: 12, names: MONTHS, offset: 1 },
  { name: "day-of-week", min: 0, max: 7, names: DAYS, offset: 0 },
];

/** @param {string} token @param {typeof FIELDS[number]} field */
function parseValue(token, field) {
  const upper = token.toUpperCase();
  if (field.names) {
    const index = field.names.indexOf(upper);
    if (index >= 0) return index + field.offset;
  }
  if (!/^\d{1,2}$/.test(token))
    throw new Error(`"${token}" is not valid in the ${field.name} field.`);
  const value = Number(token);
  if (value < field.min || value > field.max)
    throw new Error(`${field.name} must be between ${field.min} and ${field.max}.`);
  return value;
}

/** @param {string} source @param {typeof FIELDS[number]} field @returns {{ values: Set<number>, restricted: boolean }} */
function parseField(source, field) {
  const values = new Set();
  let restricted = true;
  for (const part of source.split(",")) {
    if (part === "") throw new Error(`The ${field.name} field has an empty list entry.`);
    const [range, stepText, ...extra] = part.split("/");
    if (extra.length > 0) throw new Error(`The ${field.name} field has an invalid step.`);
    let step = 1;
    if (stepText !== undefined) {
      if (!/^\d{1,3}$/.test(stepText) || Number(stepText) < 1)
        throw new Error(`The ${field.name} step must be a positive number.`);
      step = Number(stepText);
    }
    let from;
    let to;
    if (range === "*") {
      from = field.min;
      to = field.name === "day-of-week" ? 6 : field.max;
      if (stepText === undefined && source === "*") restricted = false;
    } else if (range.includes("-")) {
      const [a, b, ...rest] = range.split("-");
      if (rest.length > 0 || a === "" || b === "")
        throw new Error(`The ${field.name} range is invalid.`);
      from = parseValue(a, field);
      to = parseValue(b, field);
      if (from > to) throw new Error(`The ${field.name} range runs backwards.`);
    } else {
      if (stepText !== undefined)
        throw new Error(`The ${field.name} step needs "*" or a range, for example "*/15".`);
      from = parseValue(range, field);
      to = from;
    }
    for (let v = from; v <= to; v += step)
      values.add(field.name === "day-of-week" && v === 7 ? 0 : v);
  }
  return { values, restricted };
}

/**
 * Parses a 5-field cron expression.
 * @param {string} expression
 * @returns {{ minutes: number[], hours: number[], daysOfMonth: Set<number>, months: Set<number>, daysOfWeek: Set<number>, domRestricted: boolean, dowRestricted: boolean }}
 * @throws {Error} with a user-safe message
 */
export function parseCron(expression) {
  if (typeof expression !== "string") throw new Error("The cron expression must be text.");
  const parts = expression.trim().split(/\s+/);
  if (parts.length !== 5 || parts.some((p) => p === ""))
    throw new Error(
      "Use a standard 5-field cron expression: minute hour day-of-month month day-of-week.",
    );
  const [minute, hour, dom, month, dow] = parts.map((source, i) => parseField(source, FIELDS[i]));
  return {
    minutes: [...minute.values].sort((a, b) => a - b),
    hours: [...hour.values].sort((a, b) => a - b),
    daysOfMonth: dom.values,
    months: month.values,
    daysOfWeek: dow.values,
    domRestricted: dom.restricted,
    dowRestricted: dow.restricted,
  };
}

/** Whether `name` is an IANA-style time zone the runtime knows (validated against its time-zone database). @param {unknown} name */
export function isKnownTimeZone(name) {
  if (typeof name !== "string" || !/^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$/.test(name)) return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: name });
    return true;
  } catch {
    return false;
  }
}
