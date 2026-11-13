/**
 * Deterministic schedule fixtures (SPEC pipelines-triggers §5.6, implementation part E): fixed instants, two time zones with
 * daylight saving (Europe/Berlin and America/New_York) and both transitions. They are table data for the security checks
 * PIP-043 (the pure evaluation) and PIP-044 (the same instants through the scheduler handler); there is no feature test suite
 * (ADR-008). Every instant is UTC. 2026 transitions: Berlin spring forward 29 March 01:00Z (02:00 -> 03:00 local), fall back
 * 25 October 01:00Z (03:00 -> 02:00); New York spring forward 8 March 07:00Z (02:00 -> 03:00), fall back 1 November 06:00Z
 * (02:00 -> 01:00).
 */
import {
  jitterOffsetSeconds,
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
    name: "a wildcard-hour (hourly) schedule skips the gap instead of adding a fire that would shorten its interval",
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
    name: "Berlin fall back, step hours N > 1 (0 */2): the repeated 02:00 fires ONCE, at its first occurrence (00:00Z), the next fire is 04:00 local (03:00Z)",
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
    name: "Berlin fall back, step range (0 0-23/3): the 03:00 local nominal time occurs once on 25 October (the repeated hour is 02:00), so 0 0-23/3 fires 00:00 (22:00Z), 03:00 (02:00Z) and 06:00 (05:00Z) local, never twice",
    expression: "0 0-23/3 * * *",
    timeZone: "Europe/Berlin",
    after: "2026-10-24T20:00:00Z",
    expected: ["2026-10-24T22:00:00.000Z", "2026-10-25T02:00:00.000Z", "2026-10-25T05:00:00.000Z"],
  },
  {
    name: "New York fall back, step hours (0 */2): the repeated 01:00 is not a step hour; 02:00 local fires once (07:00Z)",
    expression: "0 */2 * * *",
    timeZone: "America/New_York",
    after: "2026-11-01T03:00:00Z",
    expected: ["2026-11-01T04:00:00.000Z", "2026-11-01T07:00:00.000Z", "2026-11-01T09:00:00.000Z"],
  },
  {
    name: "Berlin spring forward, step hours (0 */2): 02:00 is in the gap and is skipped (no fire at the gap end), 00:00 local then 04:00 local (02:00Z)",
    expression: "0 */2 * * *",
    timeZone: "Europe/Berlin",
    after: "2026-03-28T22:00:00Z",
    expected: ["2026-03-28T23:00:00.000Z", "2026-03-29T02:00:00.000Z", "2026-03-29T04:00:00.000Z"],
  },
  {
    name: "New York fall back, */1 is a wildcard: the repeated 01:15 fires at both real occurrences",
    expression: "15 */1 * * *",
    timeZone: "America/New_York",
    after: "2026-11-01T03:30:00Z",
    expected: [
      "2026-11-01T04:15:00.000Z",
      "2026-11-01T05:15:00.000Z",
      "2026-11-01T06:15:00.000Z",
      "2026-11-01T07:15:00.000Z",
    ],
  },
  {
    name: "Berlin fall back, hourly: the repeated 02:30 fires at both real occurrences (00:30Z and 01:30Z), once per real UTC hour",
    expression: "30 * * * *",
    timeZone: "Europe/Berlin",
    after: "2026-10-24T23:00:00Z",
    expected: [
      "2026-10-24T23:30:00.000Z",
      "2026-10-25T00:30:00.000Z",
      "2026-10-25T01:30:00.000Z",
      "2026-10-25T02:30:00.000Z",
    ],
  },
  {
    name: "New York fall back, hourly: the repeated 01:15 fires at both real occurrences (05:15Z EDT and 06:15Z EST)",
    expression: "15 * * * *",
    timeZone: "America/New_York",
    after: "2026-11-01T03:30:00Z",
    expected: [
      "2026-11-01T04:15:00.000Z",
      "2026-11-01T05:15:00.000Z",
      "2026-11-01T06:15:00.000Z",
      "2026-11-01T07:15:00.000Z",
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

/**
 * Fires inside one LOCAL DAY of a transition day, as UTC instants in `(from, to]`. A named-hour or step-hour (N > 1)
 * expression fires once in the repeated hour; a wildcard-hour expression (`*` or `*\/1`) fires once per REAL UTC hour (a fall-back
 * day has 25 real hours, a spring-forward day 23): the instants are asserted, so a double fire of one slot is a different instant count or a repeated instant.
 */
export const DAY_FIRES = Object.freeze([
  {
    name: "Berlin fall-back day (25 real hours), hourly 30 * * * *: 25 fires, one per real UTC hour",
    expression: "30 * * * *",
    timeZone: "Europe/Berlin",
    from: "2026-10-24T22:00:00Z",
    to: "2026-10-25T23:00:00Z",
    count: 25,
    first: "2026-10-24T22:30:00.000Z",
    last: "2026-10-25T22:30:00.000Z",
  },
  {
    name: "New York fall-back day (25 real hours), hourly 15 * * * *: 25 fires",
    expression: "15 * * * *",
    timeZone: "America/New_York",
    from: "2026-11-01T04:00:00Z",
    to: "2026-11-02T05:00:00Z",
    count: 25,
    first: "2026-11-01T04:15:00.000Z",
    last: "2026-11-02T04:15:00.000Z",
  },
  {
    name: "Berlin fall-back day, named hour 30 2 * * *: ONE fire (the first occurrence, 00:30Z)",
    expression: "30 2 * * *",
    timeZone: "Europe/Berlin",
    from: "2026-10-24T22:00:00Z",
    to: "2026-10-25T23:00:00Z",
    count: 1,
    first: "2026-10-25T00:30:00.000Z",
    last: "2026-10-25T00:30:00.000Z",
  },
  {
    name: "New York fall-back day, named hours 30 1,2 * * *: two fires, the repeated 01:30 once (05:30Z) and 02:30 (07:30Z)",
    expression: "30 1,2 * * *",
    timeZone: "America/New_York",
    from: "2026-11-01T04:00:00Z",
    to: "2026-11-02T05:00:00Z",
    count: 2,
    first: "2026-11-01T05:30:00.000Z",
    last: "2026-11-01T07:30:00.000Z",
  },
  {
    name: "Berlin spring-forward day (23 real hours), hourly 30 * * * *: 23 fires, none inside the gap",
    expression: "30 * * * *",
    timeZone: "Europe/Berlin",
    from: "2026-03-28T23:00:00Z",
    to: "2026-03-29T22:00:00Z",
    count: 23,
    first: "2026-03-28T23:30:00.000Z",
    last: "2026-03-29T21:30:00.000Z",
  },
  {
    name: "Berlin fall-back day, step hours 0 */2: 12 fires, the repeated 02:00 once (00:00Z), none at the second occurrence (01:00Z)",
    expression: "0 */2 * * *",
    timeZone: "Europe/Berlin",
    from: "2026-10-24T21:00:00Z",
    to: "2026-10-25T22:00:00Z",
    count: 12,
    first: "2026-10-24T22:00:00.000Z",
    last: "2026-10-25T21:00:00.000Z",
    never: ["2026-10-25T01:00:00.000Z"],
  },
  {
    name: "New York fall-back day, */1 wildcard hour: 25 fires",
    expression: "15 */1 * * *",
    timeZone: "America/New_York",
    from: "2026-11-01T04:00:00Z",
    to: "2026-11-02T05:00:00Z",
    count: 25,
    first: "2026-11-01T04:15:00.000Z",
    last: "2026-11-02T04:15:00.000Z",
  },
  {
    name: "New York spring-forward day (23 real hours), hourly 30 * * * *: 23 fires, none inside the gap",
    expression: "30 * * * *",
    timeZone: "America/New_York",
    from: "2026-03-08T05:00:00Z",
    to: "2026-03-09T04:00:00Z",
    count: 23,
    first: "2026-03-08T05:30:00.000Z",
    last: "2026-03-09T03:30:00.000Z",
  },
]);

/** Fall-back days walked through the scheduler handler (a wildcard-hour expression, both overlap occurrences). */
export const OVERLAP_WALKS = Object.freeze([
  {
    name: "Berlin hourly across the fall back",
    expression: "30 * * * *",
    timeZone: "Europe/Berlin",
    expected: ["2026-10-25T00:30:00.000Z", "2026-10-25T01:30:00.000Z", "2026-10-25T02:30:00.000Z"],
  },
  {
    name: "New York hourly across the fall back",
    expression: "15 * * * *",
    timeZone: "America/New_York",
    expected: ["2026-11-01T05:15:00.000Z", "2026-11-01T06:15:00.000Z", "2026-11-01T07:15:00.000Z"],
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
  {
    expression: "0 */2 * * *",
    timeZone: "Europe/Berlin",
    from: "2026-01-01T00:00:00Z",
    expected: 7200,
  },
  {
    expression: "30 * * * *",
    timeZone: "Europe/Berlin",
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
  for (const row of DAY_FIRES) {
    const got = [];
    for (
      let at = nextFireAfter(row.expression, row.timeZone, new Date(row.from));
      at && at.getTime() <= new Date(row.to).getTime();
      at = nextFireAfter(row.expression, row.timeZone, at)
    )
      got.push(at.toISOString());
    if (got.length !== row.count || got[0] !== row.first || got[got.length - 1] !== row.last)
      problems.push(`${row.name}: ${got.length} fires (${got[0]} .. ${got[got.length - 1]})`);
    if (new Set(got).size !== got.length) problems.push(`${row.name}: a slot fired twice`);
    for (const bad of row.never ?? [])
      if (got.includes(bad)) problems.push(`${row.name}: fired at ${bad}, the repeated occurrence`);
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
    ["30 * * * *", "America/New_York"],
    ["0 */2 * * *", "Europe/Berlin"],
    ["0 */2 * * *", "America/New_York"],
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

/** A fixed trigger id and window: the jitter of a slot is `hash(triggerId + slot) mod window` (SPEC §5.6). */
export const PLAN_TRIGGER_ID = "11111111-1111-4111-8111-111111111111";
export const PLAN_WINDOW = 300;
/** The planned fire time of a slot of the plan fixtures (slot + its jitter). @param {string} slotIso */
const fireOf = (slotIso) =>
  new Date(
    new Date(slotIso).getTime() +
      jitterOffsetSeconds(PLAN_TRIGGER_ID, new Date(slotIso), PLAN_WINDOW) * 1000,
  );

/** The missed-run plan (SPEC §5.6): which of the pending slots is handled, and whether it fires or is a missed run. @returns {string[]} */
export function runPlanFixtures() {
  const problems = [];
  const hourly = {
    expression: "0 * * * *",
    timeZone: "UTC",
    triggerId: PLAN_TRIGGER_ID,
    jitterWindowSeconds: PLAN_WINDOW,
  };
  const limits = { maxLatenessSeconds: 21600, onTimeGraceSeconds: 120 };
  const plan = (slotIso, now, missedPolicy) =>
    planScheduledFire({
      ...hourly,
      ...limits,
      missedPolicy,
      nextFireAt: fireOf(slotIso),
      now: new Date(now),
    });
  const after = (slotIso, seconds) =>
    new Date(fireOf(slotIso).getTime() + seconds * 1000).toISOString();
  const expect = (label, got, want) => {
    for (const [key, value] of Object.entries(want)) {
      const actual = key === "slot" || key === "nextFireAt" ? got[key]?.toISOString() : got[key];
      if (actual !== value) problems.push(`${label}: ${key} is ${actual}, expected ${value}`);
    }
  };
  expect("on time", plan("2026-06-10T12:00:00Z", after("2026-06-10T12:00:00Z", 30), "run_once"), {
    action: "fire",
    slot: "2026-06-10T12:00:00.000Z",
    skippedEarlier: false,
    nextFireAt: fireOf("2026-06-10T13:00:00Z").toISOString(),
  });
  expect(
    "three slots missed, run_once fires only the latest",
    plan("2026-06-10T12:00:00Z", after("2026-06-10T14:00:00Z", 1800), "run_once"),
    {
      action: "fire",
      slot: "2026-06-10T14:00:00.000Z",
      skippedEarlier: true,
      nextFireAt: fireOf("2026-06-10T15:00:00Z").toISOString(),
    },
  );
  expect(
    "older than the lateness limit: one missed run for the latest slot",
    planScheduledFire({
      ...hourly,
      expression: "0 2 * * *",
      ...limits,
      missedPolicy: "run_once",
      nextFireAt: fireOf("2026-06-09T02:00:00Z"),
      now: new Date("2026-06-10T09:00:00Z"),
    }),
    { action: "missed", slot: "2026-06-10T02:00:00.000Z", skippedEarlier: true },
  );
  expect(
    "skip policy, late: a missed run",
    plan("2026-06-10T12:00:00Z", after("2026-06-10T12:00:00Z", 1200), "skip"),
    { action: "missed", slot: "2026-06-10T12:00:00.000Z" },
  );
  expect(
    "skip policy, on time (default grace 120 s): fires",
    plan("2026-06-10T12:00:00Z", after("2026-06-10T12:00:00Z", 60), "skip"),
    { action: "fire", slot: "2026-06-10T12:00:00.000Z" },
  );
  expect(
    "a stored time that is not the planned time of any slot: nothing",
    planScheduledFire({
      ...hourly,
      ...limits,
      missedPolicy: "run_once",
      nextFireAt: new Date("2026-06-10T12:30:00Z"),
      now: new Date("2026-06-10T12:31:00Z"),
    }),
    { action: "none" },
  );
  // the slot is only handled once ITS planned time (slot + its jitter) has come
  const early = planScheduledFire({
    ...hourly,
    ...limits,
    missedPolicy: "run_once",
    nextFireAt: fireOf("2026-06-10T12:00:00Z"),
    now: new Date(fireOf("2026-06-10T12:00:00Z").getTime() - 1000),
  });
  if (early.action !== "none") problems.push(`before the planned time the plan is ${early.action}`);
  return problems;
}

/**
 * The jitter of a slot (SPEC §5.6, owner decision 2026-11-13): `hash(triggerId + slot) mod window`: deterministic for the same
 * trigger and slot, spread over slots and triggers, inside the window, and the slot key never moves. @returns {string[]}
 */
export function runJitterFixtures() {
  const problems = [];
  const ids = Array.from({ length: 8 }, (_, i) => `00000000-0000-4000-8000-00000000000${i}`);
  const slots = Array.from({ length: 24 }, (_, i) => new Date(Date.UTC(2026, 5, 10, i, 0, 0)));
  const window = 300;
  const offsets = new Set();
  for (const id of ids)
    for (const slot of slots) {
      const a = jitterOffsetSeconds(id, slot, window);
      const b = jitterOffsetSeconds(id, new Date(slot.getTime()), window);
      if (a !== b) problems.push(`jitter of ${id} at ${slot.toISOString()} is not deterministic`);
      if (!Number.isInteger(a) || a < 0 || a >= window)
        problems.push(`jitter ${a} is outside the window`);
      offsets.add(a);
    }
  if (offsets.size < 50)
    problems.push(`jitter hardly varies (${offsets.size} distinct offsets of 192)`);
  const sameTrigger = new Set(slots.map((s) => jitterOffsetSeconds(ids[0], s, window)));
  if (sameTrigger.size < 8) problems.push("one trigger's jitter does not differ across slots");
  const sameSlot = new Set(ids.map((id) => jitterOffsetSeconds(id, slots[0], window)));
  if (sameSlot.size < 3) problems.push("the jitter does not differ across triggers for one slot");
  if (jitterOffsetSeconds(ids[0], slots[0], 0) !== 0)
    problems.push("a window of 0 must give no jitter");
  // the jitter depends on the slot: the same trigger with only the slot changed gives another offset for at least one pair
  if (
    jitterOffsetSeconds(ids[0], slots[0], window) ===
      jitterOffsetSeconds(ids[0], slots[1], window) &&
    jitterOffsetSeconds(ids[0], slots[1], window) ===
      jitterOffsetSeconds(ids[0], slots[2], window) &&
    jitterOffsetSeconds(ids[0], slots[2], window) === jitterOffsetSeconds(ids[0], slots[3], window)
  )
    problems.push("the jitter ignores the slot");
  // the nominal slot key never moves: the plan reports the slot, not the slot plus jitter
  const trigger = ids[1];
  const slot = new Date("2026-06-10T12:00:00Z");
  const fireAt = new Date(slot.getTime() + jitterOffsetSeconds(trigger, slot, window) * 1000);
  const plan = planScheduledFire({
    expression: "0 * * * *",
    timeZone: "UTC",
    triggerId: trigger,
    jitterWindowSeconds: window,
    nextFireAt: fireAt,
    now: new Date(fireAt.getTime() + 1000),
    missedPolicy: "run_once",
    maxLatenessSeconds: 21600,
    onTimeGraceSeconds: 120,
  });
  if (plan.slot?.toISOString() !== slot.toISOString())
    problems.push(`the slot key moved with the jitter (${plan.slot?.toISOString()})`);
  return problems;
}
