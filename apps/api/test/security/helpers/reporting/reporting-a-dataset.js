import { randomUUID } from "node:crypto";
import {
  FINDING_SEVERITY_RANK,
  LIFECYCLE_GROUP_OF_STATUS,
  OPEN_FINDING_STATUSES,
  SLA_DEFAULT_HOURS,
  SLA_STOPPED_STATUSES,
} from "@qmentisai/shared";
import { buildFindingsWorld, findingData, setActor } from "../findings/findings-world.js";
import { chain, driveExecution, runningTask } from "../execution-db.js";

/**
 * The dataset of the Reporting rollup checks (Part A): findings with a KNOWN timeline (the GROUND TRUTH is kept in memory next to the
 * rows, so the rollup is compared with what really happened, not with itself): severity overrides by approved reviews, a tool re-rate
 * that leaves no trace, reopenings, accepted risk with an expiry (one already expired by time), suppression, false positives with an
 * advisory at decision time, fixed and verified findings, executions of every status, an SBOM result; in several pipelines, two workspaces
 * and two tenants. Rows are written through plain Prisma with explicit timestamps (the history is append-only, so a past instant is
 * written, never edited). `buildBulkDataset` generates 100,000 findings with SQL for the timing run.
 */

export const HOUR = 3_600_000;
export const DAY_MS = 24 * HOUR;
const rand = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

const hoursOf = (severity) => SLA_DEFAULT_HOURS[severity] ?? null;
const sevRank = (s) => FINDING_SEVERITY_RANK[s];

/**
 * The SLA clock a finding has in `status` (SL-2): none when the status stops it or the severity has no target.
 * @param {string} status @param {string} severity @param {Date} started @returns {{ slaStartedAt: Date, slaDueAt: Date | null }}
 */
export function clockOf(status, severity, started) {
  const h = hoursOf(severity);
  const running =
    OPEN_FINDING_STATUSES.includes(status) && !SLA_STOPPED_STATUSES.includes(status) && h !== null;
  return {
    slaStartedAt: started,
    slaDueAt: running ? new Date(started.getTime() + h * HOUR) : null,
  };
}

/**
 * One history-and-state step with an explicit `createdAt` (the legitimate machine, written at a past instant).
 * @param {any} db @param {any} f the current row @param {string} to @param {Date} at
 * @param {{ actor?: "user" | "system", reason: string, set?: Record<string, unknown> }} o
 */
export async function stepAt(db, f, to, at, { actor = "user", reason, set = {} }) {
  return db.$transaction(async (tx) => {
    await setActor(tx, actor);
    const rev = f.rev + 1;
    const row = await tx.finding.update({
      where: { tenantId_id: { tenantId: f.tenantId, id: f.id } },
      data: { status: to, rev, statusChangedAt: at, ...set },
    });
    await tx.findingStatusHistory.create({
      data: {
        tenantId: f.tenantId,
        workspaceId: f.workspaceId,
        repositoryId: f.repositoryId,
        pipelineId: f.pipelineId,
        findingId: f.id,
        rev,
        fromStatus: f.status,
        toStatus: to,
        actorType: actor,
        actorUserId: actor === "user" ? randomUUID() : null,
        actorCode: actor === "system" ? "ingestion" : null,
        reasonCode: reason,
        createdAt: at,
      },
    });
    return row;
  });
}

/** A tool re-rate on recurrence: the severity changes with NO history row and NO decision (what ingestion does, SPEC 5.8 EX-5). */
async function reRate(db, f, severity, at) {
  return db.$transaction(async (tx) => {
    await setActor(tx, "system");
    const keepsClock = f.slaDueAt !== null && f.slaStartedAt;
    return tx.finding.update({
      where: { tenantId_id: { tenantId: f.tenantId, id: f.id } },
      data: {
        toolSeverity: severity,
        severity,
        severityRank: sevRank(severity),
        rev: f.rev + 1,
        lastSeenAt: at,
        ...(keepsClock && hoursOf(severity) !== null
          ? { slaDueAt: new Date(new Date(f.slaStartedAt).getTime() + hoursOf(severity) * HOUR) }
          : {}),
      },
    });
  });
}

/**
 * Builds one finding by a SCRIPT of timed steps and returns the row plus its ground truth.
 * Script steps: `{ at, to, ... }` where `to` is a status; optional `override` (severity of an approved review override), `advisory`
 * (`{ suggestion, confidence }` recorded before an approved decision), `reRate` (a tool severity change at `at`, no status move),
 * `expiresAt` (accepted risk or suppression), `endedBy` (`expired`|`revoked`).
 * @param {any} c the findings world @param {any} pipeline @param {{ scanType?: string, toolSeverity: string, firstAt: Date, steps: any[], component?: string }} spec
 */
export async function buildFinding(
  c,
  pipeline,
  { scanType = "sast", toolSeverity, firstAt, steps, component = null },
) {
  const db = c.db;
  const truth = {
    id: null,
    pipelineId: pipeline.id,
    scanType,
    timeline: [],
    severityTimeline: [{ at: firstAt, severity: toolSeverity }],
    clockTimeline: [],
  };
  const clock0 = clockOf("new", toolSeverity, firstAt);
  const kind = { sca: "vulnerability", sast: "code_issue", secrets: "secret" }[scanType];
  const extra = component ? { componentPurl: component, componentName: component } : {};
  let f = await db.$transaction(async (tx) => {
    await setActor(tx, "system");
    const row = await tx.finding.create({
      data: findingData(pipeline, {
        scanType,
        kind,
        toolSeverity,
        severity: toolSeverity,
        severityRank: sevRank(toolSeverity),
        firstDetectedAt: firstAt,
        lastSeenAt: firstAt,
        ...clock0,
        ...extra,
      }),
    });
    await tx.findingStatusHistory.create({
      data: {
        tenantId: row.tenantId,
        workspaceId: row.workspaceId,
        repositoryId: row.repositoryId,
        pipelineId: row.pipelineId,
        findingId: row.id,
        rev: 0,
        fromStatus: null,
        toStatus: "new",
        actorType: "system",
        actorCode: "ingestion",
        reasonCode: "detected",
        createdAt: firstAt,
      },
    });
    return row;
  });
  truth.id = f.id;
  truth.timeline.push({ at: firstAt, status: "new" });
  truth.clockTimeline.push({ at: firstAt, started: firstAt, severity: toolSeverity });
  let severity = toolSeverity;
  let started = firstAt;
  let reopenCount = 0;
  let review = null;
  let exception = null;
  for (const s of steps) {
    const at = s.at;
    if (s.reRate) {
      f = await reRate(db, f, s.reRate, at);
      severity = s.reRate;
      truth.severityTimeline.push({ at, severity });
      truth.clockTimeline.push({ at, started, severity });
      continue;
    }
    const to = s.to;
    const from = f.status;
    let set = {};
    let reason;
    let actor = "user";
    if (to === "in_review") {
      reason =
        from === "reopened"
          ? "rereview"
          : from === "awaiting_approval"
            ? "rejected"
            : from === "false_positive"
              ? "fp_reopened"
              : "review_started";
      set = from === "new" ? { claimedByUserId: randomUUID() } : { pendingReviewId: null };
    } else if (to === "awaiting_approval") {
      reason = "review_recorded";
      let advisoryId = null;
      if (s.advisory && scanType !== "secrets") {
        const adv = await db.findingAiAdvisory.create({
          data: {
            ...c.chainOf(f),
            inputHash: randomUUID().replaceAll("-", "").padEnd(64, "0"),
            status: "ok",
            suggestion: s.advisory.suggestion,
            confidence: s.advisory.confidence,
            reasoning: "Fixture only.",
            egressLevel: "metadata",
            provider: "ollama",
            model: "m",
            createdAt: new Date(at.getTime() - 60_000),
          },
        });
        advisoryId = adv.id;
      }
      review = await db.findingReview.create({
        data: {
          ...c.chainOf(f),
          reviewerUserId: randomUUID(),
          decision: s.decision ?? "true_positive",
          rationale: "Reachable from user input, confirmed by reading the handler.",
          severityOverride: s.override ?? null,
          advisoryIdAtDecision: advisoryId,
          createdAt: at,
        },
      });
      set = { pendingReviewId: review.id };
    } else if (to === "approved") {
      reason = "approved_tp";
      await db.findingReview.update({
        where: { tenantId_id: { tenantId: f.tenantId, id: review.id } },
        data: { state: "approved", decidedAt: at },
      });
      const override = review.severityOverride ?? null;
      const effective = override ?? f.toolSeverity;
      set = {
        pendingReviewId: null,
        severityOverride: override,
        severity: effective,
        severityRank: sevRank(effective),
      };
      if (effective !== severity) {
        severity = effective;
        truth.severityTimeline.push({ at, severity });
      }
      const clock = clockOf("approved", severity, started);
      set.slaDueAt = clock.slaDueAt;
    } else if (to === "false_positive") {
      reason = "approved_fp";
      await db.findingReview.update({
        where: { tenantId_id: { tenantId: f.tenantId, id: review.id } },
        data: { state: "approved", decidedAt: at },
      });
      set = { pendingReviewId: null, slaDueAt: null };
    } else if (to === "assigned") {
      reason = "assigned";
      set = {
        assigneeUserId: randomUUID(),
        assignedAt: at,
        ...(from === "reopened"
          ? { slaDueAt: clockOf("assigned", severity, started).slaDueAt }
          : {}),
      };
    } else if (to === "in_remediation") {
      reason = "work_started";
    } else if (to === "fixed_pending_verification") {
      reason = s.system ? "absent_in_complete_scan" : "fix_submitted";
      actor = s.system ? "system" : "user";
      set = { slaDueAt: null, ...(s.system ? {} : { fixClaimedAt: at }) };
    } else if (to === "verified_fixed") {
      reason = "verified";
      actor = "system";
      set = { verifiedAt: at, closedAt: at, absentCount: 1, slaDueAt: null };
    } else if (to === "reopened") {
      actor = "system";
      if (from === "accepted_risk" || from === "suppressed") {
        reason = from === "suppressed" ? "suppression_expired" : "risk_acceptance_expired";
        if (exception)
          await db.findingException.update({
            where: { tenantId_id: { tenantId: f.tenantId, id: exception.id } },
            data: { state: s.endedBy === "revoked" ? "revoked" : "expired", endedAt: at },
          });
        set = { activeExceptionId: null, exceptionExpiresAt: null, acceptedSeverity: null };
      } else reason = "recurred";
      reopenCount += 1;
      started = at;
      set = {
        ...set,
        reopenedAt: at,
        reopenCount,
        slaStartedAt: at,
        slaDueAt: clockOf("reopened", severity, at).slaDueAt,
      };
    } else if (to === "accepted_risk" || to === "suppressed") {
      reason = to === "accepted_risk" ? "risk_accepted" : "suppressed";
      exception = await db.findingException.create({
        data: {
          ...c.chainOf(f),
          kind: to === "accepted_risk" ? "accept_risk" : "suppress",
          requestedByUserId: randomUUID(),
          justification: "Fixture justification of an exception for the rollup checks.",
          expiresAt: s.expiresAt ?? null,
          acceptedSeverity: severity,
          createdAt: new Date(at.getTime() - 60_000),
        },
      });
      await db.findingException.update({
        where: { tenantId_id: { tenantId: f.tenantId, id: exception.id } },
        data: { state: "approved", decidedAt: at },
      });
      set = {
        activeExceptionId: exception.id,
        exceptionExpiresAt: s.expiresAt ?? null,
        acceptedSeverity: severity,
        slaDueAt: null,
      };
    } else throw new Error(`the dataset has no recipe for ${from} -> ${to}`);
    f = await stepAt(db, f, to, at, { actor, reason, set });
    truth.timeline.push({ at, status: to, exceptionExpiresAt: s.expiresAt ?? null });
    truth.clockTimeline.push({ at, started, severity });
  }
  return { row: f, truth };
}

/** Ground truth at `T`: status, severity and SLA clock of one finding. @param {any} truth @param {Date} T */
export function truthAt(truth, T) {
  const last = (list) => list.filter((x) => x.at.getTime() <= T.getTime()).at(-1);
  const st = last(truth.timeline);
  if (!st) return null; // does not exist yet
  const sev = last(truth.severityTimeline).severity;
  const ck = last(truth.clockTimeline);
  return {
    status: st.status,
    severity: sev,
    started: ck.started,
    exceptionExpiresAt: st.exceptionExpiresAt ?? null,
  };
}

const FRACTION = 0.25;
/**
 * The ground-truth state counters at `T`, keyed `pipelineId|scanType|severity` (the same grouping and definitions as the rollup, computed
 * independently from the in-memory timeline). SLA uses the clock AS OF T from the timeline (reset on reopen, severity at T).
 * @param {any[]} truths @param {Date} T @returns {Record<string, Record<string, number>>}
 */
export function truthState(truths, T) {
  const out = {};
  for (const t of truths) {
    const s = truthAt(t, T);
    if (!s) continue;
    const open = OPEN_FINDING_STATUSES.includes(s.status);
    const exc =
      ["accepted_risk", "suppressed"].includes(s.status) &&
      (s.exceptionExpiresAt === null || s.exceptionExpiresAt.getTime() > T.getTime());
    if (!open && !exc) continue;
    const key = `${t.pipelineId}|${t.scanType}|${s.severity}`;
    const r = (out[key] ??= {
      open: 0,
      backlog: 0,
      wip: 0,
      awaiting: 0,
      onTrack: 0,
      dueSoon: 0,
      breached: 0,
      exceptions: 0,
      ageSeconds: 0,
    });
    if (exc) r.exceptions += 1;
    if (!open) continue;
    r.open += 1;
    if (
      LIFECYCLE_GROUP_OF_STATUS[s.status] === "awaiting_verification" ||
      ["assigned", "in_remediation"].includes(s.status)
    )
      r.wip += 1;
    else r.backlog += 1;
    if (s.status === "fixed_pending_verification") r.awaiting += 1;
    r.ageSeconds += Math.floor(Math.max(0, T.getTime() - t.timeline[0].at.getTime()) / 1000);
    const clock = clockOf(s.status, s.severity, s.started);
    if (clock.slaDueAt) {
      const due = clock.slaDueAt.getTime();
      const left = due - T.getTime();
      if (T.getTime() > due) r.breached += 1;
      else if (left <= FRACTION * (due - s.started.getTime())) r.dueSoon += 1;
      else r.onTrack += 1;
    }
  }
  return out;
}

/** An execution of `pipeline` with the given facts (driven through the machine; results are written while it runs, the terminal status last). */
export async function buildExecution(
  c,
  pipeline,
  version,
  {
    status,
    requestedAt,
    startedAt = null,
    finishedAt = null,
    scanKind = "full",
    trust = "trusted",
    results = [],
  },
) {
  const db = c.db;
  const extra = { requestedAt, createdAt: requestedAt };
  if (status === "blocked" || status === "skipped")
    return c.execution(pipeline, version, {
      ...extra,
      status,
      statusReason: "suite_reason",
      scanKind,
      trust,
    });
  const e = await c.execution(pipeline, version, { ...extra, scanKind, trust });
  if (status === "queued") return e;
  await driveExecution(db, e.id, "preparing");
  await db.$executeRaw`UPDATE executions SET status = 'running', started_at = ${startedAt}::timestamptz WHERE id = ${e.id}::uuid`;
  for (const r of results) {
    const task = await runningTask(c, { ...e, status: "running" }, r.scanType ?? "sast");
    await db.scanTaskAttempt.create({
      data: {
        ...chain(e),
        tenantId: task.tenantId,
        executionId: e.id,
        scanTaskId: task.id,
        attempt: task.attempt,
      },
    });
    await db.scanResult.create({
      data: {
        ...chain(e),
        tenantId: task.tenantId,
        executionId: e.id,
        scanTaskId: task.id,
        attempt: task.attempt,
        scanType: r.scanType ?? "sast",
        engineId: "suite-engine",
        engineVersion: "1.0.0",
        completeness: r.completeness,
        createdAt: r.createdAt ?? requestedAt,
      },
    });
  }
  if (status !== "running")
    // ONE statement into the terminal status with the finish time (terminal executions are immutable afterwards)
    await db.$executeRawUnsafe(
      `UPDATE executions SET status = $2::execution_status, status_reason = $3, lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL, finished_at = $4::timestamptz WHERE id = $1::uuid`,
      e.id,
      status,
      status === "succeeded" ? null : "suite_reason",
      finishedAt,
    );
  return e;
}

/** An SBOM result (scan type `sbom`) with `components` component items, created at `at`. */
export async function buildSbom(c, pipeline, version, at, components) {
  const db = c.db;
  const e = await c.execution(pipeline, version, { requestedAt: at });
  await driveExecution(db, e.id, "running");
  const task = await runningTask(c, { ...e, status: "running" }, "sbom");
  await db.scanTaskAttempt.create({
    data: {
      ...chain(e),
      tenantId: task.tenantId,
      executionId: e.id,
      scanTaskId: task.id,
      attempt: task.attempt,
    },
  });
  const result = await db.scanResult.create({
    data: {
      ...chain(e),
      tenantId: task.tenantId,
      executionId: e.id,
      scanTaskId: task.id,
      attempt: task.attempt,
      scanType: "sbom",
      engineId: "suite-engine",
      engineVersion: "1.0.0",
      completeness: "complete",
      itemCount: components.length,
      createdAt: at,
    },
  });
  let ordinal = 0;
  for (const purl of components)
    await db.scanResultItem.create({
      data: {
        tenantId: task.tenantId,
        executionId: e.id,
        scanResultId: result.id,
        ordinal: ordinal++,
        kind: "component",
        severity: "info",
        title: purl,
        componentPurl: purl,
        componentVersion: "1.0.0",
      },
    });
  return result;
}

/**
 * The rich dataset: three pipelines (tenant A workspace 1 and 2, tenant B), ~24 findings each over `days` days before `base`, scripted
 * lifecycles and the ground truth of each. Deterministic for a seed.
 * @param {any} c the Reporting world (`buildReportingWorld`) @param {{ now: Date, days?: number, seed?: number, perPipeline?: number }} o
 */
export async function buildRichDataset(c, { now, days = 40, seed = 7, perPipeline = 24 }) {
  const w = await buildFindingsWorld(c.db);
  const A1 = (await w.published(w.A, 0)).pipeline;
  const A2 = (await w.published(w.A, 1)).pipeline;
  const B1 = (await w.published(w.B, 0)).pipeline;
  const versionOf = async (p) =>
    c.db.pipelineConfigVersion.findFirst({ where: { tenantId: p.tenantId, pipelineId: p.id } });
  const rnd = rand(seed);
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  const base = new Date(Math.floor((now.getTime() - days * DAY_MS) / HOUR) * HOUR);
  const at = (d, h = 0) => new Date(base.getTime() + d * DAY_MS + h * HOUR);
  const sevs = ["critical", "high", "medium", "low", "info"];
  const out = {
    world: w,
    pipelines: { A1, A2, B1 },
    truths: [],
    findings: [],
    base,
    at,
    executions: [],
    reviews: [],
  };
  const scripts = [
    // 0 open, untouched
    () => ({ steps: [] }),
    // 1 override by an approved review, then assigned
    (t0) => ({
      steps: [
        { at: t0 + 1, to: "in_review" },
        {
          at: t0 + 2,
          to: "awaiting_approval",
          override: pick(["critical", "low", "medium"]),
          advisory: { suggestion: "likely_true_positive", confidence: 85 },
        },
        { at: t0 + 3, to: "approved" },
        { at: t0 + 4, to: "assigned" },
      ],
    }),
    // 2 fixed by a person, verified
    (t0) => ({
      steps: [
        { at: t0 + 1, to: "in_review" },
        { at: t0 + 1.5, to: "awaiting_approval" },
        { at: t0 + 2, to: "approved" },
        { at: t0 + 3, to: "assigned" },
        { at: t0 + 4, to: "in_remediation" },
        { at: t0 + 6, to: "fixed_pending_verification" },
        { at: t0 + 8, to: "verified_fixed" },
      ],
    }),
    // 3 verified then reopened by a recurrence
    (t0) => ({
      steps: [
        { at: t0 + 1, to: "fixed_pending_verification", system: true },
        { at: t0 + 2, to: "verified_fixed" },
        { at: t0 + 5, to: "reopened" },
        { at: t0 + 6, to: "in_review" },
      ],
    }),
    // 4 accepted risk, valid until the future
    (t0) => ({
      steps: [
        { at: t0 + 2, to: "accepted_risk", expiresAt: new Date(now.getTime() + 20 * DAY_MS) },
      ],
    }),
    // 5 accepted risk that expired by time (the job has not run: still accepted)
    (t0) => ({
      steps: [{ at: t0 + 2, to: "accepted_risk", expiresAt: new Date(now.getTime() - 2 * HOUR) }],
    }),
    // 6 false positive with an advisory that agreed
    (t0) => ({
      steps: [
        { at: t0 + 1, to: "in_review" },
        {
          at: t0 + 2,
          to: "awaiting_approval",
          decision: "false_positive",
          advisory: {
            suggestion: pick(["likely_false_positive", "likely_true_positive", "uncertain"]),
            confidence: pick([60, 90]),
          },
        },
        { at: t0 + 3, to: "false_positive" },
      ],
    }),
    // 7 suppressed with no expiry; the first round is later expired and reopened, the second stays suppressed
    (t0, sev, i) => ({
      steps:
        i < 10
          ? [
              { at: t0 + 1, to: "suppressed" },
              { at: t0 + 9, to: "reopened" },
            ]
          : [{ at: t0 + 1, to: "suppressed" }],
    }),
    // 8 a tool re-rate on recurrence leaves no trace (severity changes, nothing else)
    (t0, sev) => ({ steps: [{ at: t0 + 3, reRate: sev === "critical" ? "low" : "critical" }] }),
    // 9 fixed pending verification
    (t0) => ({ steps: [{ at: t0 + 1, to: "fixed_pending_verification", system: true }] }),
  ];
  for (const [label, pipe] of [
    ["A1", A1],
    ["A2", A2],
    ["B1", B1],
  ]) {
    for (let i = 0; i < perPipeline; i += 1) {
      const sev0 = pick(sevs);
      // a re-rate keeps the running SLA clock only when the finding has one (an `info` finding has none), as ingestion does
      const sev = i % scripts.length === 8 && sev0 === "info" ? "high" : sev0;
      const t0 = Math.floor(rnd() * (days - 12));
      const script = scripts[i % scripts.length](t0 + 0, sev, i);
      const steps = script.steps.map((s) => ({
        ...s,
        at: s.at === undefined ? undefined : at(s.at, 1 + Math.floor(rnd() * 20)),
      }));
      const scanType = i % 7 === 0 ? "secrets" : i % 3 === 0 ? "sca" : "sast";
      const component = scanType === "sca" ? `pkg:npm/${label.toLowerCase()}-lib-${i}` : null;
      const made = await buildFinding(w, pipe, {
        scanType,
        toolSeverity: sev,
        firstAt: at(t0, 0),
        steps,
        component,
      });
      out.truths.push(made.truth);
      out.findings.push({ ...made.row, label, scriptIndex: i % scripts.length });
    }
  }
  // executions: every status over the period, in each pipeline
  const statuses = [
    "succeeded",
    "succeeded",
    "failed",
    "partial",
    "timed_out",
    "cancelled",
    "skipped",
    "blocked",
    "succeeded",
  ];
  for (const pipe of [A1, A2, B1]) {
    const version = await versionOf(pipe);
    for (let i = 0; i < 18; i += 1) {
      const status = statuses[i % statuses.length];
      const requestedAt = at(Math.floor(rnd() * (days - 1)), Math.floor(rnd() * 23));
      const started = ["blocked", "skipped"].includes(status)
        ? null
        : new Date(requestedAt.getTime() + (30 + Math.floor(rnd() * 90)) * 1000);
      const finished = started
        ? new Date(started.getTime() + (60 + Math.floor(rnd() * 600)) * 1000)
        : null;
      out.executions.push({
        pipelineId: pipe.id,
        status,
        row: await buildExecution(c.A ? w : w, pipe, version, {
          status,
          requestedAt,
          startedAt: started,
          finishedAt: finished,
          results:
            status === "succeeded" && i % 2 === 0
              ? [{ scanType: "sast", completeness: "complete", createdAt: requestedAt }]
              : [],
        }),
      });
    }
  }
  // an SBOM per tenant A pipeline (the latest result of the day), components matching two of the SCA findings
  const sbomAt = at(days - 3, 4);
  const lib = out.findings.filter((f) => f.scanType === "sca" && f.label === "A1");
  await buildSbom(w, A1, await versionOf(A1), sbomAt, [
    ...lib.map((f) => f.componentPurl),
    "pkg:npm/other-1",
    "pkg:npm/other-2",
  ]);
  out.sbomAt = sbomAt;
  return out;
}

/**
 * 100,000 findings in one tenant with SQL (the timing run of the backfill): `n` findings over `days` days, status history rows with real
 * timestamps (new, then a share fixed, closed or reopened), 12,000 executions. Written with the database's own `generate_series`; the
 * DISABLE of triggers is NOT used: the rows go through the same constraints (the actor setting is set for the transaction).
 * @param {any} db @param {{ tenant: any, pipelines: any[], n?: number, days?: number, now: Date }} o
 */
export async function buildBulkDataset(db, { pipelines, n = 100_000, days = 120, now }) {
  const per = Math.ceil(n / pipelines.length);
  for (const p of pipelines) {
    await db.$transaction(
      async (tx) => {
        await setActor(tx, "system");
        await tx.$executeRaw`
          WITH ins AS (
          INSERT INTO findings (id, tenant_id, workspace_id, repository_id, pipeline_id, fingerprint, correlation_key, scan_type, kind, rule_id, title,
            tool_severity, severity, severity_rank, confidence, anchor_kind, path, start_line, end_line, first_detected_at, first_execution_id,
            first_commit_sha, last_seen_at, last_seen_execution_id, last_seen_commit_sha, sla_started_at, sla_due_at, status, rev)
          SELECT gen_random_uuid(), ${p.tenantId}::uuid, ${p.workspaceId}::uuid, ${p.repositoryId}::uuid, ${p.id}::uuid,
            'fp1:' || md5(random()::text || g::text) || md5(g::text || random()::text), md5(g::text || random()::text) || md5(random()::text),
            'sast', 'code_issue', 'rule.' || (g % 200), 'Use of eval',
            (ARRAY['critical','high','medium','low','info'])[1 + (g % 5)]::finding_severity,
            (ARRAY['critical','high','medium','low','info'])[1 + (g % 5)]::finding_severity,
            (ARRAY[4,3,2,1,0])[1 + (g % 5)], 'medium', 'focus_text', 'src/f' || (g % 1000) || '.js', 10, 10,
            ${now}::timestamptz - ((g % ${days * 24})::text || ' hours')::interval, gen_random_uuid(), repeat('a', 40),
            ${now}::timestamptz - ((g % ${days * 24})::text || ' hours')::interval, gen_random_uuid(), repeat('a', 40),
            ${now}::timestamptz - ((g % ${days * 24})::text || ' hours')::interval,
            ${now}::timestamptz - ((g % ${days * 24})::text || ' hours')::interval + interval '720 hours', 'new', 0
          FROM generate_series(1, ${per}) g
          RETURNING tenant_id, workspace_id, repository_id, pipeline_id, id, first_detected_at)
          INSERT INTO finding_status_history (id, tenant_id, workspace_id, repository_id, pipeline_id, finding_id, rev, from_status, to_status, actor_type, actor_code, reason_code, created_at)
          SELECT gen_random_uuid(), tenant_id, workspace_id, repository_id, pipeline_id, id, 0, NULL, 'new', 'system', 'ingestion', 'detected', first_detected_at
          FROM ins`;
      },
      { timeout: 600_000 },
    );
    // a third of the findings move on (fixed pending verification, a half of those verified): real history rows at later instants
    await db.$transaction(
      async (tx) => {
        await setActor(tx, "system");
        await tx.$executeRaw`
          WITH moved AS (
            UPDATE findings SET status = 'fixed_pending_verification', rev = rev + 1, sla_due_at = NULL, status_changed_at = first_detected_at + interval '3 days'
            WHERE tenant_id = ${p.tenantId}::uuid AND pipeline_id = ${p.id}::uuid AND status = 'new' AND abs(hashtext(id::text)) % 3 = 0
              AND first_detected_at + interval '3 days' < ${now}::timestamptz
            RETURNING tenant_id, workspace_id, repository_id, pipeline_id, id, first_detected_at)
          INSERT INTO finding_status_history (id, tenant_id, workspace_id, repository_id, pipeline_id, finding_id, rev, from_status, to_status, actor_type, actor_code, reason_code, created_at)
          SELECT gen_random_uuid(), tenant_id, workspace_id, repository_id, pipeline_id, id, 1, 'new', 'fixed_pending_verification', 'system', 'ingestion', 'absent_in_complete_scan', first_detected_at + interval '3 days'
          FROM moved`;
        await tx.$executeRaw`
          WITH moved AS (
            UPDATE findings SET status = 'verified_fixed', rev = rev + 1, verified_at = first_detected_at + interval '6 days', closed_at = first_detected_at + interval '6 days',
              absent_count = 1, status_changed_at = first_detected_at + interval '6 days'
            WHERE tenant_id = ${p.tenantId}::uuid AND pipeline_id = ${p.id}::uuid AND status = 'fixed_pending_verification' AND abs(hashtext(id::text)) % 2 = 0
              AND first_detected_at + interval '6 days' < ${now}::timestamptz
            RETURNING tenant_id, workspace_id, repository_id, pipeline_id, id, first_detected_at)
          INSERT INTO finding_status_history (id, tenant_id, workspace_id, repository_id, pipeline_id, finding_id, rev, from_status, to_status, actor_type, actor_code, reason_code, created_at)
          SELECT gen_random_uuid(), tenant_id, workspace_id, repository_id, pipeline_id, id, 2, 'fixed_pending_verification', 'verified_fixed', 'system', 'ingestion', 'verified', first_detected_at + interval '6 days'
          FROM moved`;
      },
      { timeout: 600_000 },
    );
  }
}

/**
 * `n` executions of one pipeline spread over `days` days (blocked and skipped ones, which may be created directly): the load of the
 * executions series in the timing run. @param {any} c the findings world @param {any} pipeline @param {any} version
 * @param {{ n?: number, days?: number, now: Date }} o
 */
export async function buildBulkExecutions(c, pipeline, version, { n = 4000, days = 120, now }) {
  const rows = Array.from({ length: n }, (_, i) => {
    const requestedAt = new Date(
      now.getTime() - ((i * 7919) % (days * 24)) * HOUR - (i % 60) * 60_000,
    );
    return c.execData(pipeline, version, {
      requestedAt,
      createdAt: requestedAt,
      status: i % 2 === 0 ? "skipped" : "blocked",
      statusReason: "suite_reason",
      idempotencyKey: `scm:bulk-${i}-${randomUUID()}:push`,
      scmDeliveryId: `bulk-${i}-${randomUUID()}`,
    });
  });
  for (let i = 0; i < rows.length; i += 1000)
    await c.db.execution.createMany({ data: rows.slice(i, i + 1000) });
}
