import {
  FINDING_SCAN_TYPES,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  LIFECYCLE_GROUP_IDS,
  REPORTING_ROUTE_SCHEMAS,
  RISK_FORMULA_TEXT,
  SUCCESS_RATE_STATUSES,
  REPORT_EXECUTION_STATUSES,
  addDays,
  computeRiskScore,
  createReportBodySchema,
  diffDays,
  listDays,
  listReportsDtoSchema,
  localDayOf,
  reportRunDtoSchema,
  resolvePeriod,
} from "@qmentisai/shared";
import { ApiError } from "@/lib/api/index.js";

/**
 * In-repo development mock of the reporting API (`VITE_REPORTING_MOCK=true`). Deterministic data for every state of SCREENS 1: the
 * scenario comes from `?mock=<name>` on the first load (kept for the session of the page): `default`, `empty` (no findings yet),
 * `emptyperiod` (data exists, nothing in the period), `young` (history shorter than 3 days), `partial` (execution, quality and workload
 * forbidden), `stale`, `recomputing`, `forbidden` (everything 403), `error` (everything 500), `slow` (3 s latency), `toofew` and
 * `agentoff` (detection quality), `toolarge` and `limit` (Generate answers 422 and 429). Every response is parsed with the SAME shared
 * schemas as the real API, so the mock cannot drift from the contract.
 */

export const MOCK_TIME_ZONE = "Europe/Berlin";
export const MOCK_USER = Object.freeze({
  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  displayName: "Mira Keller",
});
const OTHER_USER = Object.freeze({
  id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  displayName: "Jon Okafor",
});
export const MOCK_WORKSPACES = Object.freeze([
  { id: "11111111-1111-4111-8111-111111111111", name: "Payments platform" },
  { id: "22222222-2222-4222-8222-222222222222", name: "Mobile apps" },
  { id: "33333333-3333-4333-8333-333333333333", name: "Data science" },
]);

let scenario = "default";
if (typeof window !== "undefined") {
  const asked = new URLSearchParams(window.location.search).get("mock");
  if (asked) scenario = asked;
}
/** Walk helper (development only): switch the scenario without a reload. @param {string} name */
export const setMockScenario = (name) => {
  scenario = name;
};
/** Request counters for the walk (polling evidence). */
export const mockCalls = { list: 0, read: 0, lastBody: null };
if (typeof window !== "undefined")
  window.__reportingMock = { set: setMockScenario, calls: mockCalls };

// ---- deterministic numbers ---------------------------------------------------------------------------------------------------

function hashOf(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
function rng(seed) {
  let a = hashOf(seed);
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const between = (rand, lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));
const round1 = (n) => Math.round(n * 10) / 10;
const wait = (ms, signal) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
      },
      { once: true },
    );
  });

const zero = (keys) => Object.fromEntries(keys.map((k) => [k, 0]));
const sum = (obj) => Object.values(obj).reduce((a, b) => a + b, 0);

// ---- base posture --------------------------------------------------------------------------------------------------------------

const BASE_SEVERITY = { critical: 6, high: 31, medium: 58, low: 29, info: 4 };
const BASE_STATUS = {
  new: 14,
  reopened: 8,
  in_review: 12,
  awaiting_approval: 8,
  approved: 20,
  assigned: 26,
  in_remediation: 20,
  fixed_pending_verification: 20,
  accepted_risk: 6,
  suppressed: 3,
  false_positive: 14,
  verified_fixed: 203,
};
const GROUPS = {
  needs_triage: ["new", "reopened"],
  in_review: ["in_review", "awaiting_approval"],
  confirmed_in_remediation: ["approved", "assigned", "in_remediation"],
  awaiting_verification: ["fixed_pending_verification"],
  accepted_or_suppressed: ["accepted_risk", "suppressed"],
  false_positive: ["false_positive"],
  fixed: ["verified_fixed"],
};

/** A per-workspace factor so two workspaces never show the same numbers. @param {string} workspaceId */
const factorOf = (workspaceId) => 0.6 + (hashOf(workspaceId) % 80) / 100;
const scale = (n, f) => Math.max(0, Math.round(n * f));

function currentCounts(workspaceId) {
  if (scenario === "empty")
    return {
      sev: zero(FINDING_SEVERITIES),
      status: zero(FINDING_STATUSES),
      groups: zero(LIFECYCLE_GROUP_IDS),
    };
  const f = factorOf(workspaceId);
  const sev = Object.fromEntries(Object.entries(BASE_SEVERITY).map(([k, v]) => [k, scale(v, f)]));
  const status = Object.fromEntries(Object.entries(BASE_STATUS).map(([k, v]) => [k, scale(v, f)]));
  const groups = Object.fromEntries(
    Object.entries(GROUPS).map(([g, list]) => [g, list.reduce((a, s) => a + status[s], 0)]),
  );
  // keep the severity total equal to the open statuses total (the real invariant behind "tile = list")
  const open = LIFECYCLE_GROUP_IDS.slice(0, 4).reduce((a, g) => a + groups[g], 0);
  const diff = open - sum(sev);
  sev.medium = Math.max(0, sev.medium + diff);
  if (sum(sev) !== open) status.assigned += sum(sev) - open;
  const groups2 = Object.fromEntries(
    Object.entries(GROUPS).map(([g, list]) => [g, list.reduce((a, s) => a + status[s], 0)]),
  );
  return { sev, status, groups: groups2 };
}

const nowDate = () => new Date();
const todayOf = () => localDayOf(nowDate(), MOCK_TIME_ZONE);

function metaFor(source) {
  const now = nowDate();
  const stale = scenario === "stale" && source === "rollup";
  const asOf =
    source === "live"
      ? now
      : new Date(Math.floor((now.getTime() - (stale ? 3 * 3600_000 : 0)) / 3600_000) * 3600_000);
  return { asOf: asOf.toISOString(), source, stale, timeZone: MOCK_TIME_ZONE };
}

const periodOf = (query) => {
  const r = resolvePeriod(
    query.from ? { from: query.from, to: query.to } : { period: query.period ?? "30" },
    { now: nowDate(), timeZone: MOCK_TIME_ZONE },
  );
  return { from: r.from, to: r.to, dayCount: r.dayCount, preset: r.preset };
};
const hasNoActivity = () => scenario === "empty" || scenario === "emptyperiod";

// ---- DTO builders ----------------------------------------------------------------------------------------------------------------

function posture(query) {
  const wid = query.workspaceId;
  const c = currentCounts(wid);
  const asOfDay = query.asOf ?? null;
  const f = asOfDay ? 1 + Math.min(0.5, diffDays(asOfDay, todayOf()) * 0.004) : 1;
  const sev = Object.fromEntries(Object.entries(c.sev).map(([k, v]) => [k, Math.round(v * f)]));
  const status = { ...c.status };
  const open = sum(sev);
  if (asOfDay) {
    // the as-of view keeps the invariant: re-split the open statuses to the new total
    const openStatuses = [
      "new",
      "in_review",
      "awaiting_approval",
      "approved",
      "assigned",
      "in_remediation",
      "fixed_pending_verification",
      "reopened",
    ];
    const cur = openStatuses.reduce((a, s) => a + status[s], 0);
    status.assigned = Math.max(0, status.assigned + (open - cur));
  }
  const groups = Object.fromEntries(
    Object.entries(GROUPS).map(([g, list]) => [g, list.reduce((a, s) => a + status[s], 0)]),
  );
  const rand = rng(`posture${wid}`);
  const byType = { sca: Math.round(open * 0.55), sast: Math.round(open * 0.31), secrets: 0 };
  byType.secrets = open - byType.sca - byType.sast;
  const backlog = ["new", "reopened", "in_review", "awaiting_approval", "approved"].reduce(
    (a, s) => a + status[s],
    0,
  );
  const live = !asOfDay;
  const na = (value) => value; // known fields pass through
  // AS OF a past day the rollup keeps only some counters; the rest are null (never 0). A day before the first exact day: all null.
  const first = firstExactDay();
  const exact = live || (first !== null && asOfDay >= first);
  const known = (value) => (live || exact ? value : null);
  const knownStatus = Object.fromEntries(
    Object.entries(status).map(([k, v]) => [
      k,
      live ? v : exact && k === "fixed_pending_verification" ? v : null,
    ]),
  );
  const knownGroups = Object.fromEntries(
    Object.entries(groups).map(([k, v]) => [
      k,
      live
        ? v
        : exact && ["awaiting_verification", "accepted_or_suppressed"].includes(k)
          ? v
          : null,
    ]),
  );
  const conn =
    scenario === "connections"
      ? { active: 6, unavailable: 3, disconnected: 2 }
      : scenario === "empty"
        ? { active: 0, unavailable: 0, disconnected: 0 }
        : { active: 9, unavailable: 0, disconnected: 1 };
  return {
    asOfDay,
    partial: !live,
    open: known(open),
    bySeverity: known(sev),
    byType: known(byType),
    byGroup: live || exact ? knownGroups : null,
    byStatus: live || exact ? knownStatus : null,
    backlog: known(backlog),
    workInProgress: known(open - backlog),
    criticalHighOpen: known(sev.critical + sev.high),
    exceptions: {
      inForce: known(status.accepted_risk + status.suppressed),
      expiringWithin30Days: live ? (open ? between(rand, 0, 3) : 0) : null,
    },
    awaitingDecision: {
      awaitingApproval: live ? status.awaiting_approval : null,
      pendingExceptions: live ? (open ? between(rand, 1, 4) : 0) : null,
    },
    newLast24Hours: asOfDay ? null : open ? between(rand, 2, 9) : 0,
    pipelinesHealthy:
      scenario === "partial" || !live
        ? null
        : open === 0 && scenario === "empty"
          ? { healthy: 0, total: 0 }
          : { healthy: 11, total: 12 },
    githubConnections: scenario === "partial" || !live ? null : na(conn),
  };
}

/** The first day of the exact state series (forward-only): `stateSeriesFrom` of the trends. */
function firstExactDay() {
  const today = todayOf();
  if (scenario === "empty") return null;
  if (scenario === "young") return addDays(today, -1);
  if (scenario === "forwardonly") return addDays(today, -10);
  if (scenario === "asofpartial") return addDays(today, -5);
  return addDays(today, -150);
}

function trends(query) {
  const period = periodOf(query);
  const wid = query.workspaceId;
  const today = todayOf();
  const dataFrom =
    scenario === "empty" ? null : scenario === "young" ? addDays(today, -1) : addDays(today, -150);
  const stateFrom = firstExactDay();
  const series = (query.series ?? "flow,severity,backlog,net_change,awaiting_verification").split(
    ",",
  );
  const final = currentCounts(wid).sev;
  const days = listDays(period.from, period.to);
  const points = days.map((day) => {
    const flowKnown = dataFrom !== null && day >= dataFrom;
    const stateKnown = stateFrom !== null && day >= stateFrom;
    const back = diffDays(day, today);
    const rand = rng(`trend${wid}${day}`);
    const weekend = [0, 6].includes(new Date(`${day}T12:00:00Z`).getUTCDay());
    const idle = scenario === "emptyperiod";
    const openBySeverity = Object.fromEntries(
      FINDING_SEVERITIES.map((s) => {
        const slope = { critical: 0.06, high: 0.3, medium: 0.4, low: 0.2, info: 0.01 }[s];
        const wobble = idle ? 0 : between(rng(`o${wid}${day}${s}`), -1, 1);
        return [s, idle ? final[s] : Math.max(0, final[s] + Math.round(back * slope) + wobble)];
      }),
    );
    const fixed = idle ? 0 : weekend ? between(rand, 0, 2) : between(rand, 2, 8);
    const created = idle ? 0 : weekend ? between(rand, 0, 3) : between(rand, 2, 9);
    const point = { day };
    // every requested series is a number or an explicit null (a gap is never 0)
    if (series.includes("flow"))
      Object.assign(point, {
        new: flowKnown ? created : null,
        fixed: flowKnown ? fixed : null,
        closedWithoutFix: flowKnown ? (idle ? 0 : between(rand, 0, 3)) : null,
        reopened: flowKnown ? (idle ? 0 : between(rand, 0, 1)) : null,
      });
    if (series.includes("severity")) point.openBySeverity = stateKnown ? openBySeverity : null;
    if (series.includes("backlog")) point.open = stateKnown ? sum(openBySeverity) : null;
    if (series.includes("net_change")) point.netChange = flowKnown ? created - fixed : null;
    if (series.includes("awaiting_verification"))
      point.awaitingVerification = stateKnown ? (idle ? 0 : between(rand, 4, 22)) : null;
    return point;
  });
  const lastOpen = points.length ? (points[points.length - 1].open ?? 0) : 0;
  const firstOpen =
    points.find((p) => p.open !== undefined && p.open !== null && p.open > 0)?.open ?? 0;
  let projection = null;
  if (
    series.includes("backlog") &&
    stateFrom &&
    lastOpen > 0 &&
    firstOpen > lastOpen &&
    points.length >= 14
  ) {
    const pace = (firstOpen - lastOpen) / points.length;
    const need = Math.ceil(lastOpen / pace);
    projection = {
      label: "estimate",
      days: Array.from({ length: Math.min(need, 120) }, (_, i) => ({
        day: addDays(today, i + 1),
        open: Math.max(0, round1(lastOpen - pace * (i + 1))),
      })),
    };
  }
  return {
    period,
    points,
    severityBackfilled: false,
    stateSeriesFrom: stateFrom,
    dataFrom,
    recomputing: scenario === "recomputing",
    projection,
  };
}

const stats = (rand, count, median, p90) =>
  count === 0
    ? { count: 0, medianDays: null, p90Days: null, meanDays: null }
    : {
        count,
        medianDays: round1(median + rand()),
        p90Days: round1(p90 + rand() * 2),
        meanDays: round1(median * 1.2 + rand()),
      };

function remediation(query) {
  const period = periodOf(query);
  const rand = rng(`rem${query.workspaceId}${period.from}`);
  const none = hasNoActivity();
  const sevStats = Object.fromEntries(
    FINDING_SEVERITIES.map((s, i) => [
      s,
      stats(
        rand,
        none ? 0 : Math.max(0, 12 - i * 2) + 3,
        [3.2, 6.8, 12.5, 24, 40][i],
        [7, 14, 28, 52, 90][i],
      ),
    ]),
  );
  const weeks = [];
  for (let d = period.from; d <= period.to; d = addDays(d, 7)) weeks.push(d);
  return {
    period,
    timeToRemediate: {
      overall: stats(rand, none ? 0 : 64, 9.4, 21),
      bySeverity: sevStats,
      reopenedThenFixed: none ? 0 : 3,
    },
    velocity: weeks.map((weekStart) => ({ weekStart, fixed: none ? 0 : between(rand, 6, 24) })),
    timeToFirstDecision: {
      overall: stats(rand, none ? 0 : 71, 1.4, 4.8),
      byType: Object.fromEntries(
        FINDING_SCAN_TYPES.map((t, i) => [
          t,
          stats(rand, none ? 0 : 20 + i * 5, 1.1 + i * 0.6, 3.5 + i),
        ]),
      ),
    },
    verificationLag: stats(rand, none ? 0 : 55, 0.8, 2.5),
    reopenRate: none
      ? { numerator: 0, denominator: 0, rate: null, tooFew: true }
      : { numerator: 4, denominator: 64, rate: 0.0625, tooFew: false },
  };
}

function sla(query) {
  const c = currentCounts(query.workspaceId).sev;
  const sevs = FINDING_SEVERITIES.filter((s) => s !== "info");
  const open = {};
  for (const s of sevs) {
    const breached = scenario === "empty" ? 0 : { critical: 1, high: 2, medium: 0, low: 0 }[s];
    const dueSoon = Math.min(c[s] - breached, Math.round(c[s] * 0.12));
    open[s] = {
      onTrack: Math.max(0, c[s] - breached - dueSoon),
      dueSoon: Math.max(0, dueSoon),
      breached,
    };
  }
  const total = { onTrack: 0, dueSoon: 0, breached: 0 };
  for (const s of sevs) for (const k of Object.keys(total)) total[k] += open[s][k];
  const closed = Object.fromEntries(
    sevs.map((s, i) => {
      const withTarget = hasNoActivity() ? 0 : 20 - i * 4;
      const within = Math.round(withTarget * (0.95 - i * 0.07));
      return [
        s,
        {
          withTarget,
          withinSla: within,
          compliance: withTarget ? Math.round((within / withTarget) * 100) / 100 : null,
        },
      ];
    }),
  );
  return { closed, open: { bySeverity: open, total } };
}

function aging(query) {
  const c = currentCounts(query.workspaceId).sev;
  const split = [0.3, 0.4, 0.22, 0.08];
  const names = ["0-7", "8-30", "31-90", "90+"];
  const buckets = names.map((bucket) => ({ bucket, bySeverity: zero(FINDING_SEVERITIES) }));
  for (const s of FINDING_SEVERITIES) {
    let left = c[s];
    buckets.forEach((b, i) => {
      const n = i === 3 ? left : Math.min(left, Math.round(c[s] * split[i]));
      b.bySeverity[s] = n;
      left -= n;
    });
  }
  const titles = [
    "<img src=x onerror=alert(1)> Hardcoded token in config",
    '=HYPERLINK("http://example.invalid/x","Click for report")',
    "Outdated lodash allows prototype pollution in a very long finding title that keeps going to check that long titles are clipped and still readable by anyone",
    "SQL injection in order lookup",
    "Weak hash algorithm MD5 used for session ids",
    "Private key committed to repository",
    "Unsafe deserialization of untrusted input",
    "Path traversal in file download handler",
    "Cleartext transmission of credentials",
    "Missing integrity check on downloaded artefact",
  ];
  const repos = [
    "payments-api",
    "web-checkout",
    "<b>billing</b>-worker",
    "ledger-service",
    "auth-gateway",
  ];
  const oldest =
    scenario === "empty"
      ? []
      : titles.map((title, i) => ({
          id: `${(900 + i).toString(16).padStart(8, "0")}-0000-4000-8000-000000000000`,
          title,
          severity: i < 3 ? "critical" : "high",
          ageDays: 210 - i * 17,
          repositoryName: repos[i % repos.length],
        }));
  return { buckets, oldest };
}

const EXEC_KEYS = REPORT_EXECUTION_STATUSES;
function scanActivity(query) {
  const period = periodOf(query);
  const days = listDays(period.from, period.to);
  const none = hasNoActivity();
  const perDay = days.map((day) => {
    const rand = rng(`exec${query.workspaceId}${day}`);
    const byStatus = zero(EXEC_KEYS);
    if (!none) {
      byStatus.succeeded = between(rand, 3, 14);
      byStatus.failed = between(rand, 0, 3);
      byStatus.partial = between(rand, 0, 2);
      byStatus.timed_out = rand() < 0.2 ? 1 : 0;
      byStatus.cancelled = rand() < 0.15 ? 1 : 0;
      byStatus.skipped = between(rand, 0, 2);
      byStatus.blocked = rand() < 0.1 ? 1 : 0;
    }
    return { day, total: sum(byStatus), byStatus };
  });
  const num = perDay.reduce((a, d) => a + d.byStatus.succeeded, 0);
  const den = perDay.reduce(
    (a, d) => a + SUCCESS_RATE_STATUSES.reduce((x, s) => x + d.byStatus[s], 0),
    0,
  );
  const total = perDay.reduce((a, d) => a + d.total, 0);
  return {
    period,
    perDay,
    successRate: {
      numerator: num,
      denominator: den,
      rate: den ? Math.round((num / den) * 1000) / 1000 : null,
    },
    duration: none ? { medianMs: null, p90Ms: null } : { medianMs: 184_000, p90Ms: 612_000 },
    queueWait: none ? { medianMs: null, p90Ms: null } : { medianMs: 6_200, p90Ms: 41_000 },
    completeness: none
      ? { complete: 0, incomplete: 0 }
      : { complete: Math.round(den * 0.92), incomplete: den - Math.round(den * 0.92) },
    ingestionEligibleShare: { eligible: Math.round(total * 0.78), total },
  };
}

function coverage() {
  if (scenario === "connections")
    return {
      repositories: { covered: 6, total: 11 },
      uncovered: [
        {
          repositoryId: "c0000000-0000-4000-8000-000000000021",
          repositoryName: "legacy-reports",
          reason: "no_pipeline",
        },
        {
          repositoryId: "c0000000-0000-4000-8000-000000000022",
          repositoryName: "infra-tools",
          reason: "pipeline_disabled",
        },
        {
          repositoryId: "c0000000-0000-4000-8000-000000000023",
          repositoryName: "ledger-service",
          reason: "connection_unavailable",
        },
        {
          repositoryId: "c0000000-0000-4000-8000-000000000024",
          repositoryName: "<b>old</b>-gateway",
          reason: "connection_unavailable",
        },
        {
          repositoryId: "c0000000-0000-4000-8000-000000000025",
          repositoryName: "notifier",
          reason: "no_recent_scan",
        },
      ],
      pipelines: [],
    };
  if (scenario === "empty")
    return { repositories: { covered: 0, total: 0 }, uncovered: [], pipelines: [] };
  const types = (flags) =>
    ["sbom", "sca", "sast", "secrets"].map((type, i) => ({
      type,
      enabled: flags[i] !== 0,
      lastComplete: flags[i] === 0 ? null : flags[i] === 1,
    }));
  return {
    repositories: { covered: 9, total: 11 },
    uncovered: [
      {
        repositoryId: "c0000000-0000-4000-8000-000000000001",
        repositoryName: "legacy-reports",
        reason: "no_pipeline",
      },
      {
        repositoryId: "c0000000-0000-4000-8000-000000000002",
        repositoryName: "payments-<script>alert(1)</script>",
        reason: "last_scan_partial",
      },
    ],
    pipelines: [
      {
        pipelineId: "d0000000-0000-4000-8000-000000000001",
        pipelineName: "payments-api main",
        repositoryId: "c0000000-0000-4000-8000-000000000011",
        scanTypes: types([1, 1, 1, 1]),
      },
      {
        pipelineId: "d0000000-0000-4000-8000-000000000002",
        pipelineName: "web-checkout main",
        repositoryId: "c0000000-0000-4000-8000-000000000012",
        scanTypes: types([1, 1, 2, 0]),
      },
      {
        pipelineId: "d0000000-0000-4000-8000-000000000003",
        pipelineName: "=cmd|' /C calc'!A0",
        repositoryId: "c0000000-0000-4000-8000-000000000013",
        scanTypes: types([0, 1, 1, 1]),
      },
    ],
  };
}

function sbom(query) {
  const period = periodOf(query);
  const none = scenario === "empty";
  return {
    components: none ? 0 : 1842,
    vulnerable: none ? 0 : 137,
    byEcosystem: none
      ? []
      : [
          { ecosystem: "npm", components: 1100 },
          { ecosystem: "maven", components: 400 },
          { ecosystem: "pypi", components: 242 },
          { ecosystem: "go", components: 100 },
        ],
    trend: listDays(period.from, period.to).map((day) => {
      const back = diffDays(day, todayOf());
      return {
        day,
        components: none ? 0 : 1842 - back * 3,
        vulnerable: none ? 0 : 137 + Math.round(back * 0.4),
      };
    }),
  };
}

function rate(num, den, forceTooFew) {
  const tooFew = forceTooFew || den < 20;
  return {
    numerator: num,
    denominator: den,
    rate: tooFew || den === 0 ? null : Math.round((num / den) * 1000) / 1000,
    tooFew,
  };
}
function quality() {
  const toofew = scenario === "toofew" || scenario === "empty";
  const off = scenario === "agentoff";
  return {
    period: periodOf({ period: "30" }),
    falsePositiveRate: {
      overall: toofew ? rate(5, 14) : rate(14, 61),
      byType: { sca: rate(5, 20), sast: rate(8, 31), secrets: rate(1, 10) },
    },
    noisyRules: toofew
      ? []
      : [
          {
            ruleId: "javascript.lang.security.audit.eval-detected",
            scanType: "sast",
            decisions: 28,
            falsePositiveShare: 0.46,
          },
          {
            ruleId: "<b>python.flask.debug-enabled</b>",
            scanType: "sast",
            decisions: 24,
            falsePositiveShare: 0.38,
          },
          {
            ruleId: "GHSA-xxxx-yyyy-zzzz",
            scanType: "sca",
            decisions: 21,
            falsePositiveShare: 0.29,
          },
        ],
    advisoryCoverage: off ? rate(0, 61) : rate(52, 61),
    advisoryAgreement: {
      agreed: off ? 0 : 33,
      decided: off ? 0 : 47,
      rate: off || toofew ? null : 0.702,
      tooFew: off || toofew,
      matrix: off
        ? {
            advisoryFpHumanFp: 0,
            advisoryTpHumanTp: 0,
            advisoryFpHumanTp: 0,
            advisoryTpHumanFp: 0,
            advisoryUncertain: 0,
          }
        : {
            advisoryFpHumanFp: 9,
            advisoryTpHumanTp: 24,
            advisoryFpHumanTp: 6,
            advisoryTpHumanFp: 8,
            advisoryUncertain: 14,
          },
    },
    humanOverrideRate: off ? rate(0, 0) : rate(14, 38),
    advisoryOutcomes: off
      ? [{ status: "not_configured", providerKind: null, count: 61 }]
      : [
          { status: "ready", providerKind: "hosted", count: 52 },
          { status: "consent_blocked", providerKind: "hosted", count: 4 },
          { status: "not_configured", providerKind: null, count: 3 },
          { status: "failed", providerKind: "hosted", count: 2 },
        ],
  };
}

const REPOS = [
  ["payments-api", "c0000000-0000-4000-8000-000000000011"],
  ["web-checkout", "c0000000-0000-4000-8000-000000000012"],
  ["<b>billing</b>-worker", "c0000000-0000-4000-8000-000000000013"],
  ["ledger-service", "c0000000-0000-4000-8000-000000000014"],
  ["auth-gateway", "c0000000-0000-4000-8000-000000000015"],
  ["=SUM(1+1)-reports", "c0000000-0000-4000-8000-000000000016"],
  ["mobile-core", "c0000000-0000-4000-8000-000000000017"],
  ["notifier", "c0000000-0000-4000-8000-000000000018"],
];
function repoRows(seed, limit) {
  return REPOS.slice(0, limit)
    .map(([name, id], i) => {
      const rand = rng(`${seed}${id}`);
      const critical =
        scenario === "empty" ? 0 : Math.max(0, 3 - Math.floor(i / 2) - between(rand, 0, 1));
      const high = scenario === "empty" ? 0 : between(rand, 1, 9);
      const medium = scenario === "empty" ? 0 : between(rand, 2, 14);
      const low = scenario === "empty" ? 0 : between(rand, 0, 8);
      const breachedCriticalHigh = critical && i < 3 ? 1 : 0;
      return {
        repositoryId: id,
        repositoryName: name,
        critical,
        high,
        medium,
        low,
        breachedCriticalHigh,
        score: computeRiskScore({ critical, high, medium, low, breachedCriticalHigh }),
      };
    })
    .sort((a, b) => b.score - a.score);
}
function topRisk(query) {
  return {
    items: repoRows(`risk${query.workspaceId}`, Math.min(Number(query.limit ?? 10), REPOS.length)),
  };
}
function breakdown(query) {
  const by = query.by;
  const names =
    by === "repository"
      ? REPOS.map(([n, id]) => [n, id])
      : by === "pipeline"
        ? REPOS.map(([n], i) => [`${n} main`, `d0000000-0000-4000-8000-0000000000${20 + i}`])
        : by === "scan_type"
          ? FINDING_SCAN_TYPES.map((t) => [t, t])
          : [
              ["javascript.lang.security.audit.eval-detected", "r1"],
              ["<b>python.flask.debug-enabled</b>", "r2"],
              ["GHSA-xxxx-yyyy-zzzz", "r3"],
            ];
  const items = names.map(([label, key], i) => {
    const rand = rng(`bd${query.workspaceId}${key}`);
    const bySeverity = Object.fromEntries(
      FINDING_SEVERITIES.map((s, j) => [
        s,
        scenario === "empty" ? 0 : between(rand, 0, Math.max(1, 9 - j * 2 - Math.floor(i / 3))),
      ]),
    );
    return {
      key,
      label,
      open: sum(bySeverity),
      bySeverity,
      slaBreached: bySeverity.critical > 1 ? 1 : 0,
      lastScan: {
        status: i % 4 === 3 ? "failed" : "succeeded",
        at: new Date(Date.now() - (i + 1) * 5_400_000).toISOString(),
      },
    };
  });
  return { by, items: items.slice(0, Number(query.limit ?? 25)), nextCursor: null };
}
function workload() {
  const base = [
    ["Ada Lindqvist", 11, 2, 1],
    ["Jon Okafor", 8, 1, 0],
    ["Mira Keller", 6, 3, 1],
    ["Sam <i>Tan</i>", 4, 0, 0],
  ];
  return {
    assignees:
      scenario === "empty"
        ? []
        : base.map(([displayName, open, dueSoon, breached], i) => ({
            user: { id: `e000000${i}-0000-4000-8000-000000000000`, displayName },
            open,
            dueSoon,
            breached,
          })),
    unassigned: scenario === "empty" ? 0 : 23,
  };
}
function overview(query) {
  const period = periodOf(query);
  const rows = MOCK_WORKSPACES.map((w, i) => {
    if (i === 2)
      return {
        workspaceId: w.id,
        name: w.name,
        open: null,
        bySeverity: null,
        slaBreached: null,
        executions: null,
        successRate: null,
      };
    const c = currentCounts(w.id).sev;
    return {
      workspaceId: w.id,
      name: w.name,
      open: sum(c),
      bySeverity: c,
      slaBreached: scenario === "empty" ? 0 : i === 0 ? 3 : 0,
      executions: scenario === "empty" ? 0 : period.dayCount * (4 - i),
      successRate: scenario === "empty" ? null : 0.91 - i * 0.04,
    };
  });
  const seen = rows.filter((r) => r.open !== null);
  const bySeverity = Object.fromEntries(
    FINDING_SEVERITIES.map((s) => [s, seen.reduce((a, r) => a + r.bySeverity[s], 0)]),
  );
  return {
    period,
    workspaces: scenario === "empty" ? [] : rows,
    totals: {
      open: sum(bySeverity),
      bySeverity,
      slaBreached: seen.reduce((a, r) => a + r.slaBreached, 0),
    },
    topRisk: repoRows("overview", 10).slice(0, 10),
  };
}

const BUILDERS = {
  "GET /reporting/posture": [posture, "live"],
  "GET /reporting/trends": [trends, "rollup"],
  "GET /reporting/remediation": [remediation, "live"],
  "GET /reporting/sla": [sla, "live"],
  "GET /reporting/aging": [aging, "live"],
  "GET /reporting/scan-activity": [scanActivity, "rollup"],
  "GET /reporting/coverage": [coverage, "live"],
  "GET /reporting/sbom": [sbom, "rollup"],
  "GET /reporting/quality": [quality, "rollup"],
  "GET /reporting/breakdown": [breakdown, "live"],
  "GET /reporting/top-risk": [topRisk, "live"],
  "GET /reporting/workload": [workload, "live"],
  "GET /reporting/overview": [overview, "live"],
};
const PARTIAL_FORBIDDEN = new Set([
  "GET /reporting/scan-activity",
  "GET /reporting/coverage",
  "GET /reporting/sbom",
  "GET /reporting/quality",
  "GET /reporting/workload",
]);

// ---- generated reports -----------------------------------------------------------------------------------------------------------

const LOADED_AT = Date.now();
const ago = (ms) => new Date(Date.now() - ms).toISOString();
const ahead = (ms) => new Date(Date.now() + ms).toISOString();
const DAY = 86_400_000;
const WS1 = MOCK_WORKSPACES[0].id;

/** @type {Array<any>} */
const reports = [
  {
    id: "f0000000-0000-4000-8000-000000000001",
    template: "executive_summary",
    format: "pdf",
    workspaceId: WS1,
    status: "ready",
    errorCode: null,
    period: periodRange(30),
    asOfDay: null,
    requestedBy: MOCK_USER,
    createdAt: ago(3 * 3600_000),
    startedAt: ago(3 * 3600_000 - 2000),
    finishedAt: ago(3 * 3600_000 - 9000),
    expiresAt: ahead(26 * 3600_000),
    bytes: 184_320,
    rowCount: null,
    canDownload: true,
  },
  {
    id: "f0000000-0000-4000-8000-000000000002",
    template: "findings_by_pipeline",
    format: "csv",
    workspaceId: WS1,
    status: "ready",
    errorCode: null,
    period: null,
    asOfDay: null,
    requestedBy: OTHER_USER,
    createdAt: ago(DAY),
    startedAt: ago(DAY - 1500),
    finishedAt: ago(DAY - 5000),
    expiresAt: ahead(6 * 3600_000),
    bytes: 48_211,
    rowCount: 128,
    canDownload: true,
  },
  {
    id: "f0000000-0000-4000-8000-000000000003",
    template: "remediation_performance",
    format: "pdf",
    workspaceId: WS1,
    status: "running",
    errorCode: null,
    period: periodRange(90),
    asOfDay: null,
    requestedBy: MOCK_USER,
    createdAt: ago(20_000),
    startedAt: ago(12_000),
    finishedAt: null,
    expiresAt: null,
    bytes: null,
    rowCount: null,
    canDownload: false,
    holdMs: 40_000,
  },
  {
    id: "f0000000-0000-4000-8000-000000000004",
    template: "sla_compliance",
    format: "csv",
    workspaceId: WS1,
    status: "queued",
    errorCode: null,
    period: periodRange(30),
    asOfDay: null,
    requestedBy: MOCK_USER,
    createdAt: ago(5_000),
    startedAt: null,
    finishedAt: null,
    expiresAt: null,
    bytes: null,
    rowCount: null,
    canDownload: false,
    holdMs: 20_000,
  },
  {
    id: "f0000000-0000-4000-8000-000000000005",
    template: "findings_by_pipeline",
    format: "pdf",
    workspaceId: WS1,
    status: "failed",
    errorCode: "too_large",
    period: null,
    asOfDay: null,
    requestedBy: OTHER_USER,
    createdAt: ago(2 * DAY),
    startedAt: ago(2 * DAY - 1000),
    finishedAt: ago(2 * DAY - 6000),
    expiresAt: null,
    bytes: null,
    rowCount: null,
    canDownload: false,
  },
  {
    id: "f0000000-0000-4000-8000-000000000006",
    template: "sbom_inventory",
    format: "csv",
    workspaceId: WS1,
    status: "expired",
    errorCode: null,
    period: null,
    asOfDay: null,
    requestedBy: MOCK_USER,
    createdAt: ago(33 * DAY),
    startedAt: ago(33 * DAY - 1000),
    finishedAt: ago(33 * DAY - 7000),
    expiresAt: ago(3 * DAY),
    bytes: 902_114,
    rowCount: 1842,
    canDownload: false,
  },
  {
    id: "f0000000-0000-4000-8000-000000000007",
    template: "point_in_time_snapshot",
    format: "csv",
    workspaceId: WS1,
    status: "failed",
    errorCode: "timeout",
    period: null,
    asOfDay: addDays(localDayOf(new Date(), MOCK_TIME_ZONE), -30),
    requestedBy: OTHER_USER,
    createdAt: ago(5 * DAY),
    startedAt: ago(5 * DAY - 1000),
    finishedAt: ago(5 * DAY - 90_000),
    expiresAt: null,
    bytes: null,
    rowCount: null,
    canDownload: false,
  },
];
function periodRange(days) {
  const to = localDayOf(new Date(), MOCK_TIME_ZONE);
  return { from: addDays(to, -(days - 1)), to };
}
const idempotent = new Map();

/** Runs progress: a created run goes queued, running, ready by age; a seeded run waits `holdMs` after load so the polling is visible. */
function progressed(report) {
  if (!["queued", "running"].includes(report.status)) return report;
  if (report.holdMs !== undefined) {
    if (Date.now() - LOADED_AT < report.holdMs) return report;
  } else {
    const age = Date.now() - new Date(report.createdAt).getTime();
    if (age < 3_000) return report;
    if (age < 9_000)
      return { ...report, status: "running", startedAt: report.startedAt ?? ago(age - 3_000) };
  }
  const ready = {
    ...report,
    status: "ready",
    startedAt: report.startedAt ?? ago(6_000),
    finishedAt: ago(0),
    expiresAt: ahead(DAY),
    bytes: 51_200,
    rowCount: report.format === "csv" ? 128 : null,
    canDownload: true,
  };
  Object.assign(report, ready);
  return ready;
}

function checked(route, data) {
  const schema = REPORTING_ROUTE_SCHEMAS[route];
  schema.data.parse(data);
  return data;
}

// ---- the service -----------------------------------------------------------------------------------------------------------

export function createMockReportingService() {
  const gate = async (route, signal) => {
    await wait(scenario === "slow" ? 3000 : 220, signal);
    if (scenario === "forbidden" || (scenario === "partial" && PARTIAL_FORBIDDEN.has(route)))
      throw new ApiError({
        status: 403,
        code: "FORBIDDEN",
        message: "You do not have access to this.",
        correlationId: "mock-403-0001",
      });
    if (scenario === "error")
      throw new ApiError({
        status: 500,
        code: "INTERNAL_ERROR",
        message: "Something went wrong on our side.",
        correlationId: "mock-500-0001",
      });
  };
  return {
    async read(route, query, { signal } = {}) {
      mockCalls.read += 1;
      await gate(route, signal);
      const entry = BUILDERS[route];
      if (!entry)
        throw new ApiError({
          status: 404,
          code: "NOT_FOUND",
          message: "Not found.",
          correlationId: "mock-404",
        });
      if (route === "GET /reporting/posture" && query.asOf && diffDays(query.asOf, todayOf()) > 100)
        throw new ApiError({
          status: 409,
          code: "REPORT_AS_OF_UNAVAILABLE",
          message: "No data for that day.",
          correlationId: "mock-409",
        });
      const [build, source] = entry;
      const data = checked(route, build(query));
      const meta = { ...metaFor(query.asOf ? "rollup" : source) };
      REPORTING_ROUTE_SCHEMAS[route].meta.parse(
        route === "GET /reporting/top-risk" ? { ...meta, formula: RISK_FORMULA_TEXT } : meta,
      );
      return {
        data,
        meta: route === "GET /reporting/top-risk" ? { ...meta, formula: RISK_FORMULA_TEXT } : meta,
      };
    },
    async listReports(query, { signal } = {}) {
      mockCalls.list += 1;
      await gate("reports", signal);
      const all = reports
        .filter(
          (r) =>
            !query.workspaceId || r.workspaceId === query.workspaceId || r.workspaceId === null,
        )
        .filter((r) => !query.status || progressed(r).status === query.status)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const start = Number(query.cursor ?? 0) || 0;
      const limit = Number(query.limit ?? 25);
      const items = all.slice(start, start + limit).map((r) => stripHold(progressed(r)));
      const nextCursor = start + limit < all.length ? String(start + limit) : null;
      return listReportsDtoSchema.parse({ items, nextCursor });
    },
    async getReport(id, { signal } = {}) {
      await gate("reports", signal);
      const found = reports.find((r) => r.id === id);
      if (!found)
        throw new ApiError({
          status: 404,
          code: "NOT_FOUND",
          message: "Not found.",
          correlationId: "mock-404",
        });
      return reportRunDtoSchema.parse(stripHold(progressed(found)));
    },
    async createReport(body, key) {
      await wait(400);
      const parsed = createReportBodySchema.parse(body);
      mockCalls.lastBody = parsed;
      if (scenario === "toolarge")
        throw new ApiError({
          status: 422,
          code: "REPORT_TOO_LARGE",
          message: "Too many rows (212,000). Narrow the period or filters.",
          correlationId: "mock-422",
        });
      if (scenario === "limit")
        throw new ApiError({
          status: 429,
          code: "REPORT_LIMIT_REACHED",
          message: "Too many requests.",
          correlationId: "mock-429",
        });
      if (key && idempotent.has(key)) return { reportId: idempotent.get(key) };
      const id = crypto.randomUUID();
      const period = parsed.from
        ? { from: parsed.from, to: parsed.to }
        : parsed.period
          ? periodRange(Number(parsed.period))
          : null;
      reports.push({
        id,
        template: parsed.template,
        format: parsed.format,
        workspaceId: parsed.workspaceId ?? null,
        status: "queued",
        errorCode: null,
        period,
        asOfDay: parsed.asOfDay ?? null,
        requestedBy: MOCK_USER,
        createdAt: new Date().toISOString(),
        startedAt: null,
        finishedAt: null,
        expiresAt: null,
        bytes: null,
        rowCount: null,
        canDownload: false,
      });
      if (key) idempotent.set(key, id);
      return { reportId: id };
    },
    async deleteReport(id) {
      await wait(250);
      const at = reports.findIndex((r) => r.id === id);
      if (at >= 0) reports.splice(at, 1);
      return null;
    },
    async downloadReport(id) {
      await wait(300);
      const found = reports.find((r) => r.id === id);
      if (!found || progressed(found).status !== "ready")
        throw new ApiError({
          status: 409,
          code: "REPORT_NOT_READY",
          message: "The report is not ready.",
          correlationId: "mock-409",
        });
      const text =
        found.format === "csv"
          ? '﻿Finding id,Title\r\nF-1,"\'=HYPERLINK(""x"")"\r\n'
          : "%PDF-1.4\n% mock\n";
      return {
        blob: new Blob([text], { type: found.format === "csv" ? "text/csv" : "application/pdf" }),
        fileName: `report-${id.slice(0, 8)}.${found.format}`,
      };
    },
  };
}

function stripHold({ holdMs: _hold, ...rest }) {
  return rest;
}
