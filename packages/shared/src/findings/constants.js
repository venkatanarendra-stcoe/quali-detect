import { SEVERITIES, SEVERITY_RANK } from "../scan-engines/constants.js";

/**
 * Constants of the Findings module (docs/modules/findings/SPEC.md, contract freeze Part A0). One definition of each word for the
 * API, the workers, the database mirror (`finding_transition_allowed`, compared by the suite) and the UI. Nothing here is
 * secret; nothing here is a permission decision (the central authorization engine decides).
 */

/** Finding statuses in `finding_status` ENUM DECLARATION ORDER (SPEC 6.1). The database enum has exactly this order. */
export const FINDING_STATUSES = Object.freeze([
  "new",
  "in_review",
  "awaiting_approval",
  "approved",
  "false_positive",
  "assigned",
  "in_remediation",
  "fixed_pending_verification",
  "verified_fixed",
  "reopened",
  "accepted_risk",
  "suppressed",
]);

/** The eight "open" statuses (SPEC 5.11 `all_open`, 7.2 partial indexes). */
export const OPEN_FINDING_STATUSES = Object.freeze([
  "new",
  "in_review",
  "awaiting_approval",
  "approved",
  "assigned",
  "in_remediation",
  "fixed_pending_verification",
  "reopened",
]);

/** Open statuses a user may attach an exception request to (EX-1) and that SM-19/SM-20 start from. */
export const EXCEPTION_SOURCE_STATUSES = Object.freeze([
  "new",
  "in_review",
  "approved",
  "assigned",
  "in_remediation",
  "reopened",
]);

/** Statuses the absence rule may move to `fixed_pending_verification` (SM-14, SPEC 5.4). */
export const ABSENCE_SOURCE_STATUSES = Object.freeze([
  "new",
  "in_review",
  "awaiting_approval",
  "approved",
  "assigned",
  "in_remediation",
  "reopened",
]);

/** Scan types that produce findings (SBOM components are inventory, D-27) and their finding kind. */
export const FINDING_SCAN_TYPES = Object.freeze(["sca", "sast", "secrets"]);
export const FINDING_KIND_VALUES = Object.freeze(["vulnerability", "code_issue", "secret"]);
export const FINDING_KIND_OF_SCAN_TYPE = Object.freeze({
  sca: "vulnerability",
  sast: "code_issue",
  secrets: "secret",
});

/** Severities in `severity` declaration order (critical first) and their rank (4 critical .. 0 info). */
export const FINDING_SEVERITIES = SEVERITIES;
export const FINDING_SEVERITY_RANK = SEVERITY_RANK;
export const FINDING_CONFIDENCES = Object.freeze(["low", "medium", "high"]);

/** How the content key of the fingerprint was made (SPEC 5.2.2, 7.2). */
export const ANCHOR_KINDS = Object.freeze([
  "focus_text",
  "masked_line",
  "line",
  "ordinal",
  "component",
]);
export const ORIGIN_TRUSTS = Object.freeze(["trusted", "untrusted_fork"]);

/** Fingerprint algorithm version (SPEC 5.2.5). The stored value starts with `fp<version>:`. */
export const FINGERPRINT_VERSION = 1;
export const FINGERPRINT_DOMAIN = "qm.finding.fp.v1";
export const FINGERPRINT_PATTERN = /^fp1:[0-9a-f]{64}$/;

/** Actor kinds of a history row and the fixed codes of the system actors (SPEC 3.3). */
export const FINDING_ACTOR_TYPES = Object.freeze(["user", "system"]);
export const FINDING_SYSTEM_ACTOR_CODES = Object.freeze(["ingestion", "sla", "expiry", "fp_agent"]);

export const REVIEW_DECISIONS = Object.freeze(["true_positive", "false_positive"]);
export const REVIEW_STATES = Object.freeze([
  "pending",
  "approved",
  "rejected",
  "withdrawn",
  "superseded",
]);
export const EXCEPTION_KINDS = Object.freeze(["accept_risk", "suppress"]);
export const EXCEPTION_STATES = Object.freeze([
  "pending",
  "approved",
  "rejected",
  "withdrawn",
  "superseded",
  "expired",
  "revoked",
  "invalidated",
]);
export const APPROVAL_DECISIONS = Object.freeze(["approve", "reject"]);
export const REMEDIATION_KINDS = Object.freeze(["work_started", "fix_submitted"]);
export const VERIFICATION_OUTCOMES = Object.freeze(["verified", "failed", "recurred"]);
export const INGESTION_STATUSES = Object.freeze(["ingested", "skipped", "failed"]);
/** Why an execution (or one scan type of it) was not ingested (IN-3). */
export const INGESTION_SKIP_REASONS = Object.freeze([
  "untrusted_fork",
  "not_baseline_ref",
  "no_baseline",
  "no_results",
  "pipeline_deleted",
]);
/** Why a finding was NOT resolved by an execution (5.4); counted as `resolution_skipped` by reason. */
export const RESOLUTION_SKIP_REASONS = Object.freeze([
  "not_eligible",
  "eligibility_disagrees",
  "not_baseline",
  "stale_watermark",
  "no_result",
  "incomplete",
  "truncated",
  "coverage_not_complete",
  "tools_degraded",
  "partial_scope",
  "coverage_gap",
  "tool_not_run",
  "type_disabled",
]);

/** Advisory (FP agent) vocabulary (SPEC 9.3). */
export const ADVISORY_SUGGESTIONS = Object.freeze([
  "likely_true_positive",
  "likely_false_positive",
  "uncertain",
]);
export const ADVISORY_ROW_STATUSES = Object.freeze([
  "ok",
  "failed",
  "consent_required",
  "not_configured",
  "skipped_untrusted",
  "skipped_cap",
  "timeout",
  "invalid_output",
]);
export const ADVISORY_DTO_STATUSES = Object.freeze([
  "none",
  "pending",
  "ready",
  "failed",
  "consent_blocked",
  "not_configured",
]);
export const ADVISORY_EGRESS_LEVELS = Object.freeze(["none", "local", "metadata", "snippet"]);
export const ADVISORY_SCHEMA_VERSION = 1;
export const ADVISORY_PATH_CLASSES = Object.freeze([
  "test",
  "vendor",
  "docs",
  "config",
  "generated",
  "source",
]);

/** Bounds (SPEC 5.7, 5.8, 5.10, 8, 9.3). */
export const FINDINGS_LIMITS = Object.freeze({
  rationaleMin: 10,
  rationaleMax: 2000,
  justificationMin: 20,
  justificationMax: 2000,
  compensatingControlsMax: 1000,
  commentMax: 4000,
  approvalCommentMax: 2000,
  assignmentNoteMax: 500,
  remediationNoteMax: 1000,
  pullRequestUrlMax: 500,
  historyNoteMax: 2000,
  acceptRiskMaxDays: 180,
  suppressMaxDays: 365,
  bulkMax: 50,
  pageSizes: Object.freeze([25, 50, 100]),
  defaultPageSize: 25,
  maxLimit: 100,
  queryMin: 2,
  queryMax: 100,
  titleMax: 200,
  ruleIdMax: 200,
  pathMax: 1024,
  snippetBytesMax: 4096,
  reasoningMax: 1000,
  advisorySnippetChars: 1500,
  advisorySnippetLines: 40,
  advisoryLineChars: 200,
  advisoryPathChars: 512,
  boardFirstItems: 25,
  similarMax: 20,
  slaHoursMax: 87600,
  fixConfirmationsDefault: 1,
  advisoryRequestPerFindingPerHour: 3,
  advisoryRequestPerUserPerHour: 30,
});

/** `rev`-checked conflict reasons of `FINDING_STATE_CONFLICT` (SPEC 8). */
export const FINDING_CONFLICT_REASONS = Object.freeze([
  "stale_revision",
  "transition_not_allowed",
  "exception_pending",
  "pipeline_deleted",
  "already_decided",
]);
/** `details.reason` values of `VALIDATION_FAILED` and `FORBIDDEN` the module uses (SPEC 8, 5.6). */
export const FINDING_VALIDATION_REASONS = Object.freeze([
  "credential_shape",
  "assignee_not_eligible",
  "expiry_out_of_range",
  "override_requires_tp",
  "approver_not_eligible",
]);
export const FINDING_FORBIDDEN_REASONS = Object.freeze([
  "separation_of_duties",
  "missing_permission",
]);

/** Audit action names (SPEC 11.4). Registered by the parts that write them; the names are frozen here. */
export const FINDING_AUDIT_ACTIONS = Object.freeze([
  "finding.review_started",
  "finding.review_recorded",
  "finding.review_withdrawn",
  "finding.approval_decided",
  "finding.approval_denied",
  "finding.severity_overridden",
  "finding.assigned",
  "finding.unassigned",
  "finding.remediation_started",
  "finding.fix_submitted",
  "finding.verified",
  "finding.reopened",
  "finding.auto_pending",
  "finding.exception_requested",
  "finding.exception_decided",
  "finding.exception_withdrawn",
  "finding.exception_revoked",
  "finding.exception_expired",
  "finding.comment_added",
  "finding.advisory_requested",
  "tenant.findings_sla_changed",
  "tenant.llm_code_consent_changed",
]);

/** Feature flags (both default OFF, SPEC IN-1, 9.2). Names only; the config schemas read them. */
export const FINDINGS_FLAG_NAMES = Object.freeze({
  ingestion: "FINDINGS_INGESTION_ENABLED",
  agent: "FINDINGS_AGENT_ENABLED",
});

// ------------------------------------------------------------------------------------------------------------------------
// Saved views (SPEC 5.11) and SLA (SPEC 5.9, D-30).
// ------------------------------------------------------------------------------------------------------------------------

/** Fixed server-side definitions of the four saved views (never stored). */
export const SAVED_VIEWS = Object.freeze({
  all_open: Object.freeze({ id: "all_open", statuses: OPEN_FINDING_STATUSES }),
  needs_review: Object.freeze({
    id: "needs_review",
    statuses: Object.freeze(["new", "in_review"]),
  }),
  assigned_to_me: Object.freeze({
    id: "assigned_to_me",
    statuses: OPEN_FINDING_STATUSES,
    assigneeIsCaller: true,
  }),
  breached_sla: Object.freeze({
    id: "breached_sla",
    statuses: OPEN_FINDING_STATUSES,
    slaBreached: true,
  }),
});
export const SAVED_VIEW_IDS = Object.freeze(Object.keys(SAVED_VIEWS));

/** Default SLA targets in hours (Recommended placeholders, D-30); `null` means none (info). A tenant row overrides one severity. */
export const SLA_DEFAULT_HOURS = Object.freeze({
  critical: 168,
  high: 720,
  medium: 2160,
  low: 4320,
  info: null,
});
/** `due_soon` when this fraction of the target or less remains. */
export const SLA_DUE_SOON_FRACTION = 0.25;
export const SLA_STATES = Object.freeze(["on_track", "due_soon", "breached", "not_applicable"]);

/** Statuses in which no SLA clock runs (SL-2): `sla_due_at` is null. */
export const SLA_STOPPED_STATUSES = Object.freeze([
  "accepted_risk",
  "suppressed",
  "false_positive",
  "verified_fixed",
  "fixed_pending_verification",
]);

/**
 * The SLA target of a severity.
 * @param {string} severity
 * @param {Record<string, number | null | undefined>} [overrides] tenant rows by severity (hours)
 * @returns {number | null} hours, or null when the severity has no target
 */
export function slaTargetHours(severity, overrides = {}) {
  const own = overrides[severity];
  if (typeof own === "number") return own;
  return Object.hasOwn(SLA_DEFAULT_HOURS, severity) ? SLA_DEFAULT_HOURS[severity] : null;
}

/**
 * The derived SLA state (SL-3): never stored. `startedAt` and `dueAt` are what the row holds.
 * @param {{ startedAt: Date | string | null, dueAt: Date | string | null, now: Date }} input
 * @returns {"on_track" | "due_soon" | "breached" | "not_applicable"}
 */
export function deriveSlaState({ startedAt, dueAt, now }) {
  if (!dueAt || !startedAt) return "not_applicable";
  const due = new Date(dueAt).getTime();
  const start = new Date(startedAt).getTime();
  const t = now.getTime();
  if (t > due) return "breached";
  const target = due - start;
  return target > 0 && due - t <= target * SLA_DUE_SOON_FRACTION ? "due_soon" : "on_track";
}

// ------------------------------------------------------------------------------------------------------------------------
// The state machine (SPEC 6.1). THE ONLY set of allowed transitions; mirrored by the SQL function
// `finding_transition_allowed(from, to, actor_type)` (compared by the suite, FNDDB-02).
// ------------------------------------------------------------------------------------------------------------------------

/**
 * @typedef {object} FindingTransition
 * @property {string} id `SM-n` as in the SPEC
 * @property {ReadonlyArray<string | null>} from allowed source statuses (`null` is "no row yet", detect only)
 * @property {string | null} to target status; `null` only for the reassignment of SM-10 (status unchanged)
 * @property {string} action action id of {@link FINDING_ACTIONS}
 * @property {ReadonlyArray<"user" | "system">} actors
 * @property {ReadonlyArray<string>} reasons history reason codes this transition may carry
 */

const t = (id, from, to, action, actors, reasons) =>
  Object.freeze({
    id,
    from: Object.freeze(from),
    to,
    action,
    actors: Object.freeze(actors),
    reasons: Object.freeze(reasons),
  });

/** @type {ReadonlyArray<FindingTransition>} */
export const FINDING_TRANSITIONS = Object.freeze([
  t("SM-1", [null], "new", "detect", ["system"], ["detected"]),
  t("SM-2", ["new"], "in_review", "claim", ["user"], ["review_started"]),
  t(
    "SM-3",
    ["new", "in_review"],
    "awaiting_approval",
    "record_review",
    ["user"],
    ["review_recorded"],
  ),
  t("SM-4", ["awaiting_approval"], "in_review", "withdraw_review", ["user"], ["review_withdrawn"]),
  t("SM-5", ["awaiting_approval"], "approved", "approve_review", ["user"], ["approved_tp"]),
  t("SM-6", ["awaiting_approval"], "false_positive", "approve_review", ["user"], ["approved_fp"]),
  t("SM-7", ["awaiting_approval"], "in_review", "reject_review", ["user"], ["rejected"]),
  t("SM-8", ["false_positive"], "in_review", "reopen_review", ["user"], ["fp_reopened"]),
  t("SM-9", ["approved"], "assigned", "assign", ["user"], ["assigned"]),
  t(
    "SM-10",
    ["assigned", "in_remediation"],
    // `to: null` = the status does not move; the assignee changes and a history row is written
    null,
    "reassign",
    ["user"],
    ["reassigned"],
  ),
  t("SM-11", ["assigned", "in_remediation"], "approved", "unassign", ["user"], ["unassigned"]),
  t("SM-12", ["assigned"], "in_remediation", "start_work", ["user"], ["work_started"]),
  t(
    "SM-13",
    ["assigned", "in_remediation"],
    "fixed_pending_verification",
    "submit_fix",
    ["user"],
    ["fix_submitted"],
  ),
  t(
    "SM-14",
    ABSENCE_SOURCE_STATUSES,
    "fixed_pending_verification",
    "auto_pending",
    ["system"],
    ["absent_in_complete_scan"],
  ),
  t("SM-15", ["fixed_pending_verification"], "verified_fixed", "verify", ["system"], ["verified"]),
  t(
    "SM-16",
    ["fixed_pending_verification", "verified_fixed"],
    "reopened",
    "recur",
    ["system"],
    ["recurred"],
  ),
  t("SM-17", ["reopened"], "assigned", "assign", ["user"], ["assigned"]),
  t("SM-18", ["reopened"], "in_review", "reopen_review", ["user"], ["rereview"]),
  t(
    "SM-19",
    EXCEPTION_SOURCE_STATUSES,
    "accepted_risk",
    "approve_exception",
    ["user"],
    ["risk_accepted"],
  ),
  t(
    "SM-20",
    EXCEPTION_SOURCE_STATUSES,
    "suppressed",
    "approve_exception",
    ["user"],
    ["suppressed"],
  ),
  t(
    "SM-21",
    ["accepted_risk", "suppressed"],
    "reopened",
    "end_exception",
    ["user", "system"],
    ["risk_acceptance_expired", "suppression_expired", "revoked", "severity_increased"],
  ),
]);

/** Every history reason code (the union of the table). */
export const FINDING_REASON_CODES = Object.freeze([
  ...new Set(FINDING_TRANSITIONS.flatMap((x) => x.reasons)),
]);

const TRANSITION_INDEX = (() => {
  /** @type {Map<string, Set<"user" | "system">>} */
  const m = new Map();
  for (const tr of FINDING_TRANSITIONS) {
    if (tr.to === null) continue;
    for (const from of tr.from) {
      const key = `${from ?? ""}>${tr.to}`;
      const set = m.get(key) ?? new Set();
      for (const a of tr.actors) set.add(a);
      m.set(key, set);
    }
  }
  return m;
})();

/**
 * Whether `from` to `to` is an allowed transition for the actor kind. `from === null` is the creation of a finding. Equal
 * statuses are allowed only for the reassignment of SM-10 (`assigned`, `in_remediation`). Mirrors `finding_transition_allowed`.
 * @param {string | null} from
 * @param {string} to
 * @param {"user" | "system"} actorType
 * @returns {boolean}
 */
export function isTransitionAllowed(from, to, actorType) {
  const actors = TRANSITION_INDEX.get(`${from ?? ""}>${to}`);
  if (actors?.has(actorType)) return true;
  // SM-10: the status stays, the assignee changes (user only)
  return (
    actorType === "user" &&
    from === to &&
    FINDING_TRANSITIONS.some((x) => x.to === null && x.from.includes(from))
  );
}

/** Every ordered pair of statuses (and the creation) with its allowed actors, for the suite and the SQL comparison. */
export function allTransitionPairs() {
  const pairs = [];
  for (const from of [null, ...FINDING_STATUSES])
    for (const to of FINDING_STATUSES)
      pairs.push({
        from,
        to,
        user: isTransitionAllowed(from, to, "user"),
        system: isTransitionAllowed(from, to, "system"),
      });
  return pairs;
}

/**
 * Actions: what a caller asks for, mapped to the permission the central engine checks (SPEC 3.1, 8.2). `ownRule` says an extra
 * condition the SERVICE enforces (the permission alone does not decide). The DTO's `lifecycle.allowedActions` lists these ids.
 */
export const FINDING_ACTIONS = Object.freeze({
  claim: Object.freeze({ permission: "finding.review", transitions: ["SM-2"] }),
  record_review: Object.freeze({ permission: "finding.review", transitions: ["SM-3"] }),
  withdraw_review: Object.freeze({
    permission: "finding.review",
    transitions: ["SM-4"],
    ownRule: "reviewer_only",
  }),
  approve_review: Object.freeze({
    permission: "approval.approve",
    transitions: ["SM-5", "SM-6"],
    ownRule: "separation_of_duties",
  }),
  reject_review: Object.freeze({
    permission: "approval.reject",
    transitions: ["SM-7"],
    ownRule: "separation_of_duties",
  }),
  reopen_review: Object.freeze({ permission: "finding.review", transitions: ["SM-8", "SM-18"] }),
  assign: Object.freeze({ permission: "finding.assign", transitions: ["SM-9", "SM-17"] }),
  reassign: Object.freeze({ permission: "finding.assign", transitions: ["SM-10"] }),
  unassign: Object.freeze({ permission: "finding.assign", transitions: ["SM-11"] }),
  start_work: Object.freeze({
    permission: "finding.remediate",
    transitions: ["SM-12"],
    ownRule: "assignee_or_assign_holder",
  }),
  submit_fix: Object.freeze({
    permission: "finding.remediate",
    transitions: ["SM-13"],
    ownRule: "assignee_or_assign_holder",
  }),
  request_accept_risk: Object.freeze({ permission: "finding.accept_risk", transitions: [] }),
  request_suppression: Object.freeze({ permission: "finding.suppress", transitions: [] }),
  withdraw_exception: Object.freeze({
    permission: null,
    transitions: [],
    ownRule: "requester_only",
  }),
  approve_exception: Object.freeze({
    permission: "approval.approve",
    transitions: ["SM-19", "SM-20"],
    ownRule: "separation_of_duties",
  }),
  reject_exception: Object.freeze({
    permission: "approval.reject",
    transitions: [],
    ownRule: "separation_of_duties",
  }),
  revoke_accept_risk: Object.freeze({ permission: "finding.accept_risk", transitions: ["SM-21"] }),
  revoke_suppression: Object.freeze({ permission: "finding.suppress", transitions: ["SM-21"] }),
  comment: Object.freeze({ permission: "finding.comment", transitions: [] }),
  request_advisory: Object.freeze({ permission: "finding.review", transitions: [] }),
});
export const FINDING_ACTION_IDS = Object.freeze(Object.keys(FINDING_ACTIONS));
