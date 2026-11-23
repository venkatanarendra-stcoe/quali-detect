import { ABSENCE_SOURCE_STATUSES, FINDING_SEVERITY_RANK, FINDINGS_LIMITS } from "./constants.js";
import { evaluateCoverage } from "./coverage.js";
import { computeCorrelationKey, fingerprintItems } from "./fingerprint.js";
import { hasCredentialShape, redactCredentialShapes } from "./normalize.js";

/**
 * The pure ingestion plan (docs/modules/findings/SPEC.md 5.3 to 5.5, IN-4 to IN-9, D-24, D-25): given the findings that exist for one
 * `(pipeline, scan type)`, the items of ONE result and the facts of the verified execution, say what to create, update and
 * transition. No I/O, no clock, no randomness: the same input always gives the same plan, and replaying an execution is a no-op
 * because the caller refuses a second `finding_ingestions` row (IN-4).
 *
 * The caller (Part A1) applies the plan in one transaction under the pipeline advisory lock; this function never decides
 * authorization and never reads a message: `execution` is built from database rows (IN-2).
 *
 * @typedef {object} ExistingFinding
 * @property {string} id
 * @property {string} fingerprint
 * @property {string} scanType
 * @property {string} status
 * @property {string} toolSeverity
 * @property {string | null} [severityOverride]
 * @property {string | null} [acceptedSeverity] the severity accepted by an approved accept-risk exception
 * @property {number} absentCount
 * @property {number} [reopenCount]
 * @property {Date | string | null} [fixClaimedAt] set when a HUMAN submitted the fix
 * @property {Date | string | null} [lastSeenAt]
 * @property {string[]} [lastSeenTools]
 * @property {string | null} [ecosystem]
 * @property {string | null} [path]
 * @property {string | null} [pendingReviewId]
 * @property {string | null} [pendingExceptionId]
 *
 * @typedef {object} IngestionExecutionFacts
 * @property {string} tenantId
 * @property {string} pipelineId from the verified execution row
 * @property {string} executionId
 * @property {"sca" | "sast" | "secrets"} scanType
 * @property {Date} startedAt
 * @property {string | null} commitSha
 * @property {"trusted" | "untrusted_fork"} trust
 * @property {string} refType
 * @property {string} refName
 * @property {string | null} trackedRef `finding_pipeline_state.tracked_ref` (default: the repository's default branch)
 * @property {boolean} pipelineDeleted
 * @property {boolean} hasResult a result of this scan type exists
 * @property {boolean} typeEnabled the pipeline still enables the scan type
 * @property {boolean} resolutionEligibleEvent the event's flag
 * @property {boolean} resolutionEligibleDb the value recomputed from database rows
 * @property {import("./coverage.js").CoverageResult | null} result
 * @property {import("./coverage.js").CoverageToolRun[]} toolRuns
 * @property {{ lastIngestedStartedAt: Date | null, resolutionWatermarkStartedAt: Date | null }} markers
 * @property {number} [fixConfirmations] N of D-25 (default 1)
 */

const rank = (s) => FINDING_SEVERITY_RANK[s] ?? 0;
const effective = (override, tool) => override ?? tool;
const toMs = (d) => (d ? new Date(d).getTime() : null);

/** The columns an observation writes (never a secret value; titles and rules pass the platform redaction again, IN-7). */
function project(entry, execution) {
  const it = entry.item;
  const refused = [];
  const clean = (field, text, max) => {
    const value = String(text ?? "");
    if (hasCredentialShape(value)) refused.push(field);
    return redactCredentialShapes(value).slice(0, max);
  };
  const ruleId = clean("ruleId", it.ruleId, FINDINGS_LIMITS.ruleIdMax);
  const title =
    clean("title", it.title || it.ruleName || it.ruleId, FINDINGS_LIMITS.titleMax) || ruleId;
  return {
    refused,
    fields: {
      scanType: it.scanType,
      ruleId,
      ruleName: it.ruleName ? clean("ruleName", it.ruleName, 200) : null,
      title,
      toolSeverity: it.severity,
      severityAssumed: it.severityAssumed === true,
      confidence: it.confidence ?? "medium",
      cwe: (it.cwe ?? []).slice(0, 10),
      advisoryIds: (it.advisories ?? [])
        .slice(0, 20)
        .map((a) => ({ id: a.id, family: a.family ?? "other" })),
      componentPurl: it.component?.purl ?? null,
      componentName: it.component?.name ?? null,
      componentVersion: it.component?.version ?? null,
      ecosystem: it.component?.ecosystem ?? null,
      fixedVersions: (it.fix?.fixedVersions ?? []).slice(0, 10),
      path: it.location?.path ?? null,
      startLine: it.location?.startLine ?? null,
      endLine: it.location?.endLine ?? null,
      anchorKind: entry.anchorKind,
      lastSeenTools: [...new Set(it.toolIds ?? [])].slice(0, 6),
      lastSeenAt: execution.startedAt,
      lastSeenExecutionId: execution.executionId,
      lastSeenCommitSha: execution.commitSha,
    },
    evidence: it.evidence ?? null,
    scmRef: it.scmRef ?? null,
    url: it.url ?? null,
  };
}

/**
 * @param {{ existing: ExistingFinding[], observed: import("./fingerprint.js").ObservedItem[], execution: IngestionExecutionFacts }} input
 * @returns {{
 *   ingest: boolean,
 *   skipReason: string | null,
 *   resolutionEligible: boolean,
 *   creates: Array<{ fingerprint: string, correlationKey: string | null, occ: number, anchorKind: string, severity: string, fields: any, evidence: any, scmRef: any, url: string | null, advisoryRequest: true }>,
 *   updates: Array<{ findingId: string, fields: any, evidence: any, scmRef: any, url: string | null, severity: string, occurrenceDelta: 0 | 1 }>,
 *   transitions: Array<{ transitionId: string, findingId: string, from: string, to: string, reasonCode: string, actor: { type: "system", code: "ingestion" }, effects: Record<string, unknown> }>,
 *   verifications: Array<{ findingId: string, outcome: "verified" | "failed" | "recurred" }>,
 *   exceptionInvalidations: Array<{ findingId: string, reason: "severity_increased" }>,
 *   supersede: Array<{ findingId: string, reviewId: string | null, exceptionId: string | null }>,
 *   advisoryRequests: Array<{ fingerprint?: string, findingId?: string, kind: "created" | "reopened" }>,
 *   resolutionSkipped: Record<string, number>,
 *   dropped: { skipped_bad_path: number, skipped_invalid: number, fields_refused: number },
 *   staleObservations: number,
 *   counters: { itemsSeen: number, created: number, recurred: number, autoPending: number, verified: number, reopened: number, dropped: number },
 *   markers: { lastIngestedStartedAt: Date, resolutionWatermarkStartedAt: Date | null }
 * }}
 */
export function planIngestion({ existing, observed, execution }) {
  const empty = (skipReason) => ({
    ingest: false,
    skipReason,
    resolutionEligible: false,
    creates: [],
    updates: [],
    transitions: [],
    verifications: [],
    exceptionInvalidations: [],
    supersede: [],
    advisoryRequests: [],
    resolutionSkipped: {},
    dropped: { skipped_bad_path: 0, skipped_invalid: 0, fields_refused: 0 },
    staleObservations: 0,
    counters: {
      itemsSeen: 0,
      created: 0,
      recurred: 0,
      autoPending: 0,
      verified: 0,
      reopened: 0,
      dropped: 0,
    },
    markers: {
      lastIngestedStartedAt: execution.markers.lastIngestedStartedAt ?? execution.startedAt,
      resolutionWatermarkStartedAt: execution.markers.resolutionWatermarkStartedAt ?? null,
    },
  });

  // IN-3: eligibility to be ingested at all (D-24: trusted execution on the tracked baseline only)
  if (execution.pipelineDeleted) return empty("pipeline_deleted");
  if (execution.trust !== "trusted") return empty("untrusted_fork");
  if (execution.trackedRef === null || execution.trackedRef === undefined)
    return empty("no_baseline");
  if (execution.refType !== "branch" || execution.refName !== execution.trackedRef)
    return empty("not_baseline_ref");
  if (!execution.hasResult) return empty("no_results");

  const plan = empty(null);
  plan.ingest = true;
  const startedMs = execution.startedAt.getTime();
  plan.counters.itemsSeen = observed.length;

  const fingerprinted = fingerprintItems(observed, execution.pipelineId);
  plan.dropped.skipped_bad_path = fingerprinted.dropped.skipped_bad_path;
  plan.dropped.skipped_invalid = fingerprinted.dropped.skipped_invalid;
  plan.counters.dropped = plan.dropped.skipped_bad_path + plan.dropped.skipped_invalid;

  const byFingerprint = new Map(existing.map((f) => [f.fingerprint, f]));
  const seen = new Set();
  const N = execution.fixConfirmations ?? FINDINGS_LIMITS.fixConfirmationsDefault;

  for (const entry of fingerprinted) {
    const projected = project(entry, execution);
    plan.dropped.fields_refused += projected.refused.length;
    const current = byFingerprint.get(entry.fingerprint);
    if (!current) {
      plan.creates.push({
        fingerprint: entry.fingerprint,
        correlationKey: computeCorrelationKey(entry.item, execution.tenantId),
        occ: entry.occ,
        anchorKind: entry.anchorKind,
        severity: entry.item.severity,
        fields: projected.fields,
        evidence: projected.evidence,
        scmRef: projected.scmRef,
        url: projected.url,
        advisoryRequest: true,
      });
      plan.advisoryRequests.push({ fingerprint: entry.fingerprint, kind: "created" });
      plan.counters.created += 1;
      continue;
    }
    seen.add(entry.fingerprint);
    const lastSeen = toMs(current.lastSeenAt);
    // IN-6: an observation of an OLDER execution never moves last_seen backwards and never reopens
    if (lastSeen !== null && startedMs < lastSeen) {
      plan.staleObservations += 1;
      continue;
    }
    const newEffective = effective(current.severityOverride ?? null, entry.item.severity);
    plan.updates.push({
      findingId: current.id,
      fields: projected.fields,
      evidence: projected.evidence,
      scmRef: projected.scmRef,
      url: projected.url,
      severity: newEffective,
      occurrenceDelta: 1,
    });
    plan.counters.recurred += 1;
    const status = current.status;
    if (status === "fixed_pending_verification" || status === "verified_fixed") {
      // SM-16: any positive observation reopens, whatever the scan kind (D-25)
      const outcome = current.fixClaimedAt ? "failed" : "recurred";
      plan.transitions.push({
        transitionId: "SM-16",
        findingId: current.id,
        from: status,
        to: "reopened",
        reasonCode: "recurred",
        actor: { type: "system", code: "ingestion" },
        effects: { reopenCountDelta: 1, absentCount: 0, slaRestart: true },
      });
      plan.verifications.push({ findingId: current.id, outcome });
      plan.advisoryRequests.push({ findingId: current.id, kind: "reopened" });
      plan.counters.reopened += 1;
    } else if (
      status === "accepted_risk" &&
      current.acceptedSeverity &&
      rank(newEffective) > rank(current.acceptedSeverity)
    ) {
      // EX-5: the severity rose above what was accepted
      plan.exceptionInvalidations.push({ findingId: current.id, reason: "severity_increased" });
      plan.transitions.push({
        transitionId: "SM-21",
        findingId: current.id,
        from: status,
        to: "reopened",
        reasonCode: "severity_increased",
        actor: { type: "system", code: "ingestion" },
        effects: { reopenCountDelta: 1, absentCount: 0, slaRestart: true },
      });
      plan.counters.reopened += 1;
    }
  }

  // Absence (5.4): only findings of this scan type that were not observed, evaluated one by one
  const wm = execution.markers.resolutionWatermarkStartedAt ?? null;
  const eligible =
    execution.resolutionEligibleEvent === true && execution.resolutionEligibleDb === true;
  const disagrees = execution.resolutionEligibleEvent !== execution.resolutionEligibleDb;
  for (const f of existing) {
    if (f.scanType !== execution.scanType || seen.has(f.fingerprint)) continue;
    const resolvable =
      ABSENCE_SOURCE_STATUSES.includes(f.status) || f.status === "fixed_pending_verification";
    if (!resolvable) continue; // accepted_risk, suppressed, false_positive, verified_fixed: their own rules
    // an older execution never resolves a finding seen more recently
    const lastSeen = toMs(f.lastSeenAt);
    const verdict = evaluateCoverage(
      f,
      {
        resolutionEligible: eligible,
        eligibilityDisagrees: disagrees,
        isBaseline: true,
        startedAt: execution.startedAt,
        resolutionWatermarkStartedAt: wm,
        typeEnabled: execution.typeEnabled,
      },
      execution.result,
      execution.toolRuns,
    );
    if (!verdict.absent || (lastSeen !== null && lastSeen > startedMs)) {
      const reason = verdict.absent ? "stale_watermark" : verdict.reason;
      plan.resolutionSkipped[reason] = (plan.resolutionSkipped[reason] ?? 0) + 1;
      continue;
    }
    if (f.status === "fixed_pending_verification") {
      const next = f.absentCount + 1;
      plan.updates.push({
        findingId: f.id,
        fields: { absentCount: next },
        evidence: null,
        scmRef: null,
        url: null,
        severity: effective(f.severityOverride ?? null, f.toolSeverity),
        occurrenceDelta: 0,
      });
      if (next >= N) {
        plan.transitions.push({
          transitionId: "SM-15",
          findingId: f.id,
          from: f.status,
          to: "verified_fixed",
          reasonCode: "verified",
          actor: { type: "system", code: "ingestion" },
          effects: { absentCount: next, verified: true },
        });
        plan.verifications.push({ findingId: f.id, outcome: "verified" });
        plan.counters.verified += 1;
      }
    } else {
      plan.transitions.push({
        transitionId: "SM-14",
        findingId: f.id,
        from: f.status,
        to: "fixed_pending_verification",
        reasonCode: "absent_in_complete_scan",
        actor: { type: "system", code: "ingestion" },
        effects: { absentCount: 1, slaStop: true },
      });
      if (f.pendingReviewId || f.pendingExceptionId)
        plan.supersede.push({
          findingId: f.id,
          reviewId: f.pendingReviewId ?? null,
          exceptionId: f.pendingExceptionId ?? null,
        });
      plan.counters.autoPending += 1;
    }
  }
  // a disagreement is logged by the caller and fails closed: nothing was resolved and the watermark does not move
  plan.resolutionEligible = eligible && !disagrees;
  plan.markers = {
    lastIngestedStartedAt:
      execution.markers.lastIngestedStartedAt &&
      execution.markers.lastIngestedStartedAt.getTime() > startedMs
        ? execution.markers.lastIngestedStartedAt
        : execution.startedAt,
    // moves forward only, and only when this execution was allowed to resolve (conditions 1 and 2 of 5.4)
    resolutionWatermarkStartedAt:
      plan.resolutionEligible && (wm === null || startedMs > wm.getTime())
        ? execution.startedAt
        : wm,
  };
  return plan;
}
