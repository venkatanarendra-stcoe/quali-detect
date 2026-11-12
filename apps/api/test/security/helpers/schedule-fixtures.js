/**
 * Deterministic schedule fixtures (SPEC pipelines-triggers §5.6, implementation part E): fixed instants, two time zones with
 * daylight saving (Europe/Berlin and America/New_York) and both transitions. They are table data for the security checks
 * PIP-043 (the pure evaluation) and PIP-044 (the same instants through the scheduler handler); there is no feature test suite
 * (ADR-008). Every instant is UTC. 2026 transitions: Berlin spring forward 29 March 01:00Z (02:00 -> 03:00 local), fall back
 * 25 October 01:00Z (03:00 -> 02:00); New York spring forward 8 March 07:00Z (02:00 -> 03:00), fall back 1 November 06:00Z
 * (02:00 -> 01:00).
 */
import {
  minimumIntervalSeconds,
  nextFireAfter,
  planScheduledFire,
  previousFireBefore,
  validateSchedule,
} from "@qmentisai/shared";

/** The next fires after a start instant: the nominal local time that does not exist fires once at the gap end, a repeated one once at its first occurrence. */
export const NEXT_FIRES = Object.freeze([
  {
    name: "Berlin spring gap: 02:30 does not exist on 29 March, fires once at the gap end (03:00 local = 01:00Z)",
    expression: "30 2 * * *",
    timeZone: "Europe/Berlin",
    after: "2026-03-27T12:00:00Z",
    expected: ["2026-03-28T01:30:00.000Z", "2026-03-29T01:00:00.000Z", "2026-03-30T00:30:00.000Z"],
  },
  {
    name: "Berlin fall overlap: 02:30 occurs twice on 25 October, fires once at the first occurrence (CEST)",
    expression: "30 2 * * *",
    timeZone: "Europe/Berlin",
    after: "2026-10-23T12:00:00Z",
    expected: ["2026-10-24T00:30:00.000Z", "2026-10-25T00:30:00.000Z", "2026-10-26T01:30:00.000Z"],
  },
  {
    name: "New York spring gap: 02:30 does not exist on 8 March, fires once at the gap end (03:00 local = 07:00Z)",
    expression: "30 2 * * *",
    timeZone: "America/New_York",
    after: "2026-03-06T12:00:00Z",
    expected: ["2026-03-07T07:30:00.000Z", "2026-03-08T07:00:00.000Z", "2026-03-09T06:30:00.000Z"],
  },
  {
    name: "New York fall overlap: 01:30 occurs twice on 1 November, fires once at the first occurrence (EDT)",
    expression: "30 1 * * *",
    timeZone: "America/New_York",
    after: "2026-10-30T12:00:00Z",
    expected: ["2026-10-31T05:30:00.000Z", "2026-11-01T05:30:00.000Z", "2026-11-02T06:30:00.000Z"],
  },
  {
    name: "several nominal times inside one gap collapse into ONE fire at the gap end",
    expression: "*/30 2 * * *",
    timeZone: "Europe/Berlin",
    after: "2026-03-28T12:00:00Z",
    expected: ["2026-03-29T01:00:00.000Z", "2026-03-30T00:00:00.000Z", "2026-03-30T00:30:00.000Z"],
  },
  {
    name: "an interval-style (hourly) schedule skips the gap instead of adding a fire that would shorten its interval",
    expression: "30 * * * *",
    timeZone: "Europe/Berlin",
    after: "2026-03-28T23:00:00Z",
    expected: [
      "2026-03-28T23:30:00.000Z",
      "2026-03-29T00:30:00.000Z",
      "2026-03-29T01:30:00.000Z",
      "2026-03-29T02:30:00.000Z",
    ],
  },
  {
    name: "fall back with a two-hourly schedule: the repeated 02:00 fires once",
    expression: "0 */2 * * *",
    timeZone: "Europe/Berlin",
    after: "2026-10-24T21:00:00Z",
    expected: [
      "2026-10-24T22:00:00.000Z",
      "2026-10-25T00:00:00.000Z",
      "2026-10-25T03:00:00.000Z",
      "2026-10-25T05:00:00.000Z",
    ],
  },
  {
    name: "UTC has no transitions (control)",
    expression: "0 2 * * *",
    timeZone: "UTC",
    after: "2026-03-28T12:00:00Z",
    expected: ["2026-03-29T02:00:00.000Z", "2026-03-30T02:00:00.000Z"],
  },
]);

/** The real minimum gap in seconds, counting the transitions of the 400 days after `from`. */
export const MIN_GAPS = Object.freeze([
  {
    expression: "0 * * * *",
    timeZone: "America/New_York",
    from: "2026-01-01T00:00:00Z",
    expected: 3600,
  },
  { expression: "0 2 * * *", timeZone: "UTC", from: "2026-01-01T00:00:00Z", expected: 86400 },
  {
    expression: "30 1,2 * * *",
    timeZone: "Europe/Berlin",
    from: "2026-01-01T00:00:00Z",
    expected: 1800,
  },
  {
    expression: "30 1 * * *",
    timeZone: "America/New_York",
    from: "2026-01-01T00:00:00Z",
    expected: 82800,
  },
  { expression: "*/45 * * * *", timeZone: "UTC", from: "2026-01-01T00:00:00Z", expected: 900 },
]);

/** Pure evaluation problems (empty when every fixture holds). @returns {string[]} */
export function runEvaluationFixtures() {
  const problems = [];
  for (const row of NEXT_FIRES) {
    const got = [];
    let at = new Date(row.after);
    for (let i = 0; i < row.expected.length; i += 1) {
      at = nextFireAfter(row.expression, row.timeZone, at);
      got.push(at?.toISOString() ?? null);
    }
    if (JSON.stringify(got) !== JSON.stringify(row.expected))
      problems.push(`${row.name}: got ${got.join(", ")}`);
  }
  for (const row of MIN_GAPS) {
    const { minGapSeconds } = minimumIntervalSeconds(row.expression, row.timeZone, {
      from: new Date(row.from),
    });
    if (minGapSeconds !== row.expected)
      problems.push(
        `minimum gap of "${row.expression}" in ${row.timeZone}: ${minGapSeconds}, expected ${row.expected}`,
      );
  }
  // previous fire: the gap-end fire is the one at or before 01:00Z on 29 March; strictly before it is the previous day's
  const gapEnd = new Date("2026-03-29T01:00:00Z");
  const inclusive = previousFireBefore("30 2 * * *", "Europe/Berlin", gapEnd, { inclusive: true });
  const exclusive = previousFireBefore("30 2 * * *", "Europe/Berlin", gapEnd);
  if (inclusive?.toISOString() !== "2026-03-29T01:00:00.000Z")
    problems.push(`previousFireBefore (inclusive) at the gap end: ${inclusive?.toISOString()}`);
  if (exclusive?.toISOString() !== "2026-03-28T01:30:00.000Z")
    problems.push(`previousFireBefore (exclusive) at the gap end: ${exclusive?.toISOString()}`);
  // the validation answers: forbidden syntax, time zone and the real interval
  const bad = [
    ["0 0 * * * *", "UTC", "invalid_expression"],
    ["@reboot", "UTC", "invalid_expression"],
    ["@daily", "UTC", "invalid_expression"],
    ["0 0 L * *", "UTC", "invalid_expression"],
    ["0 0 15W * *", "UTC", "invalid_expression"],
    ["0 0 * * 5#2", "UTC", "invalid_expression"],
    ["0 0 ? * *", "UTC", "invalid_expression"],
    ["5/20 * * * *", "UTC", "invalid_expression"],
    ["0 0 31 2 *", "UTC", "never_fires"],
    ["0 0 * * *", "Mars/Olympus", "unknown_time_zone"],
    ["*/30 * * * *", "UTC", "too_frequent"],
    ["30 1,2 * * *", "Europe/Berlin", "too_frequent"],
  ];
  for (const [expression, timeZone, code] of bad) {
    const result = validateSchedule({
      expression,
      timeZone,
      minIntervalSeconds: 3600,
      now: new Date("2026-01-01T00:00:00Z"),
    });
    if (result.ok || result.code !== code)
      problems.push(
        `"${expression}" in ${timeZone} should be ${code}, got ${result.ok ? "ok" : result.code}`,
      );
  }
  const good = [
    ["0 * * * *", "America/New_York"],
    ["30 * * * *", "Europe/Berlin"],
    ["0 2 * * MON-FRI", "Europe/Berlin"],
    ["0 0 29 2 *", "UTC"],
  ];
  for (const [expression, timeZone] of good) {
    const result = validateSchedule({
      expression,
      timeZone,
      minIntervalSeconds: 3600,
      now: new Date("2026-01-01T00:00:00Z"),
    });
    if (!result.ok) problems.push(`"${expression}" in ${timeZone} was refused: ${result.message}`);
  }
  return problems;
}

/** The missed-run plan (SPEC §5.6): which of the pending slots is handled, and whether it fires or is a missed run. @returns {string[]} */
export function runPlanFixtures() {
  const problems = [];
  const hourly = { expression: "0 * * * *", timeZone: "UTC", jitterSeconds: 120 };
  const limits = { maxLatenessSeconds: 21600, onTimeGraceSeconds: 120 };
  const plan = (nextFireAt, now, missedPolicy) =>
    planScheduledFire({
      ...hourly,
      ...limits,
      missedPolicy,
      nextFireAt: new Date(nextFireAt),
      now: new Date(now),
    });
  const expect = (label, got, want) => {
    for (const [key, value] of Object.entries(want)) {
      const actual = key === "slot" || key === "nextFireAt" ? got[key]?.toISOString() : got[key];
      if (actual !== value) problems.push(`${label}: ${key} is ${actual}, expected ${value}`);
    }
  };
  expect("on time", plan("2026-06-10T12:02:00Z", "2026-06-10T12:02:30Z", "run_once"), {
    action: "fire",
    slot: "2026-06-10T12:00:00.000Z",
    skippedEarlier: false,
    nextFireAt: "2026-06-10T13:02:00.000Z",
  });
  expect(
    "three slots missed, run_once fires only the latest",
    plan("2026-06-10T12:02:00Z", "2026-06-10T14:30:00Z", "run_once"),
    {
      action: "fire",
      slot: "2026-06-10T14:00:00.000Z",
      skippedEarlier: true,
      nextFireAt: "2026-06-10T15:02:00.000Z",
    },
  );
  expect(
    "older than the lateness limit: one missed run for the latest slot",
    planScheduledFire({
      expression: "0 2 * * *",
      timeZone: "UTC",
      jitterSeconds: 120,
      ...limits,
      missedPolicy: "run_once",
      nextFireAt: new Date("2026-06-09T02:02:00Z"),
      now: new Date("2026-06-10T09:00:00Z"),
    }),
    { action: "missed", slot: "2026-06-10T02:00:00.000Z", skippedEarlier: true },
  );
  expect(
    "skip policy, late: a missed run",
    plan("2026-06-10T12:02:00Z", "2026-06-10T12:20:00Z", "skip"),
    {
      action: "missed",
      slot: "2026-06-10T12:00:00.000Z",
    },
  );
  expect(
    "skip policy, on time: fires",
    plan("2026-06-10T12:02:00Z", "2026-06-10T12:03:00Z", "skip"),
    {
      action: "fire",
      slot: "2026-06-10T12:00:00.000Z",
    },
  );
  expect(
    "a stored time that is not a slot of the schedule: nothing",
    plan("2026-06-10T12:30:00Z", "2026-06-10T12:31:00Z", "run_once"),
    {
      action: "none",
    },
  );
  return problems;
}
