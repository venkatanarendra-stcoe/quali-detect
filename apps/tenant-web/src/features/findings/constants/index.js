import {
  AlarmClock,
  CircleCheck,
  CircleDot,
  Clock,
  Eye,
  EyeOff,
  RotateCcw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Timer,
  UserCheck,
  Wrench,
} from "lucide-react";
import { BOARD_COLUMNS, FINDING_SEVERITIES, FINDINGS_LIMITS } from "@qmentisai/shared";

/**
 * Presentation constants of the Findings screens (docs/modules/findings/SCREENS.md section 2). Vocabularies (statuses, severities,
 * board columns) come from `@qmentisai/shared`; only labels, icons and tones live here. Nothing in this file decides a permission.
 */

/** Status label, icon and tone (SCREENS 2). Tone only colours the icon and, for danger and warning, the text; the label is always shown. */
export const STATUS_PRESENTATION = Object.freeze({
  new: { label: "New", icon: CircleDot, tone: "neutral" },
  in_review: { label: "In review", icon: Eye, tone: "neutral" },
  awaiting_approval: { label: "Awaiting approval", icon: Clock, tone: "warning" },
  approved: { label: "Confirmed, unassigned", icon: ShieldAlert, tone: "danger" },
  false_positive: { label: "False positive", icon: ShieldOff, tone: "neutral", muted: true },
  assigned: { label: "Assigned", icon: UserCheck, tone: "neutral" },
  in_remediation: { label: "In progress", icon: Wrench, tone: "neutral" },
  fixed_pending_verification: {
    label: "Fixed, pending verification",
    icon: ScanSearch,
    tone: "warning",
  },
  verified_fixed: { label: "Verified fixed", icon: CircleCheck, tone: "success" },
  reopened: { label: "Reopened", icon: RotateCcw, tone: "warning" },
  accepted_risk: { label: "Accepted risk", icon: ShieldCheck, tone: "neutral" },
  suppressed: { label: "Suppressed", icon: EyeOff, tone: "neutral", muted: true },
});

/** @param {string} status */
export const statusPresentation = (status) =>
  STATUS_PRESENTATION[status] ?? { label: status, icon: CircleDot, tone: "neutral" };

export const SEVERITY_LABELS = Object.freeze({
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
});
export const SEVERITY_OPTIONS = FINDING_SEVERITIES.map((value) => ({
  value,
  label: SEVERITY_LABELS[value],
}));

export const SCAN_TYPE_OPTIONS = Object.freeze([
  { value: "sca", label: "SCA (dependencies)" },
  { value: "sast", label: "SAST (code)" },
  { value: "secrets", label: "Secrets" },
]);
export const SCAN_TYPE_LABELS = Object.freeze({ sca: "SCA", sast: "SAST", secrets: "Secrets" });

export const STATUS_OPTIONS = Object.keys(STATUS_PRESENTATION).map((value) => ({
  value,
  label: STATUS_PRESENTATION[value].label,
}));

export const SLA_OPTIONS = Object.freeze([
  { value: "on_track", label: "On track" },
  { value: "due_soon", label: "Due soon" },
  { value: "breached", label: "Breached" },
]);

export const AI_SUGGESTION_OPTIONS = Object.freeze([
  { value: "likely_true_positive", label: "Likely true positive" },
  { value: "likely_false_positive", label: "Likely false positive" },
  { value: "uncertain", label: "Uncertain" },
  { value: "none", label: "No advice" },
]);
export const SUGGESTION_LABELS = Object.freeze({
  likely_true_positive: "Likely true positive",
  likely_false_positive: "Likely false positive",
  uncertain: "Uncertain",
});
export const SUGGESTION_HINT_LABELS = Object.freeze({
  likely_true_positive: "Likely TP",
  likely_false_positive: "Likely FP",
  uncertain: "Uncertain",
});

/** Saved views of the list (SPEC 5.11): id -> tab label and the summary key of its count. */
export const SAVED_VIEW_TABS = Object.freeze([
  { id: "all_open", label: "All open", count: "allOpen" },
  { id: "needs_review", label: "Needs review", count: "needsReview" },
  { id: "assigned_to_me", label: "Assigned to me", count: "assignedToMe" },
  { id: "breached_sla", label: "Breached SLA", count: "breachedSla" },
]);

export const SLA_ICON = Object.freeze({
  on_track: Timer,
  due_soon: Timer,
  breached: AlarmClock,
});

export const BOARD_COLUMN_META = Object.freeze({
  assigned: { label: "Assigned", note: null },
  in_remediation: { label: "In progress", note: null },
  fixed_pending_verification: {
    label: "Fixed, pending verification",
    note: "Verified by the next complete scan.",
  },
  verified_fixed: { label: "Verified fixed", note: "Last 30 days." },
  reopened: { label: "Reopened", note: null },
});
export { BOARD_COLUMNS };

/** Statuses a bulk action may apply to (SCREENS 4, D-29): the server re-checks every row. */
export const BULK_START_REVIEW_STATUSES = Object.freeze(["new"]);
export const BULK_ASSIGN_STATUSES = Object.freeze([
  "approved",
  "assigned",
  "in_remediation",
  "reopened",
]);
export const BULK_MAX = FINDINGS_LIMITS.bulkMax;

/** Plain sentences for the tooltips of disabled controls (the permission key is never shown). */
export const REASONS = Object.freeze({
  sod_review: "You recorded a decision on this finding. Another lead must approve it.",
  sod_exception: "You requested this. Another lead must approve it.",
  no_assign: "You need permission to assign findings.",
  own_only: "You can only move findings assigned to you.",
  no_state: "This finding can't take a request in its current status.",
  stale: "The finding changed. Reload to continue.",
});

/** The stable `details.reason` of a 409 `FINDING_STATE_CONFLICT` as a sentence (SCREENS 5, 6, 9). */
export const CONFLICT_TEXT = Object.freeze({
  stale_revision: "This finding changed since you opened it. Reload to continue.",
  transition_not_allowed:
    "This finding can't take that action in its current status. Reload to continue.",
  exception_pending: "A request is already pending for this finding. Reload to see it.",
  pipeline_deleted: "The pipeline was deleted, so this finding can no longer change.",
  already_decided: "This request was already decided or the finding changed.",
});

/** The stable `details.reason` of a 403 `FORBIDDEN` as a sentence (never a permission key). */
export const FORBIDDEN_TEXT = Object.freeze({
  separation_of_duties: REASONS.sod_review,
  not_assignee: "You can only move findings assigned to you.",
  not_reviewer: "Only the person who recorded this decision can withdraw it.",
  not_requester: "Only the person who made this request can withdraw it.",
  missing_permission: "You don't have permission to do this.",
});

export const CREDENTIAL_SHAPE_TEXT =
  "This text looks like a secret or credential. Remove it and try again.";

export const ACTION_LABELS = Object.freeze({
  claim: "Start review",
  record_review: "Record decision",
  withdraw_review: "Withdraw decision",
  approve_review: "Approve",
  reject_review: "Reject",
  reopen_review: "Reopen for review",
  assign: "Assign",
  reassign: "Reassign",
  unassign: "Unassign",
  start_work: "Start work",
  submit_fix: "Submit fix",
  request_accept_risk: "Request accepted risk",
  request_suppression: "Request suppression",
  withdraw_exception: "Withdraw request",
  approve_exception: "Approve request",
  reject_exception: "Reject request",
  revoke_accept_risk: "Revoke acceptance",
  revoke_suppression: "Revoke suppression",
  request_advisory: "Request advisory again",
});

export const LIMITS = FINDINGS_LIMITS;

/**
 * The most days ahead the date picker offers. The server allows an expiry of at most 180 days (accepted risk) or 365 days
 * (suppression) from ITS clock, with no slack (AS_BUILT_B deviation 10); the picker stores the END of the chosen local day, so the
 * last offered date is one day short of the limit (179 and 364).
 */
export const EXPIRY_PICKER_MAX_DAYS = Object.freeze({
  accept_risk: FINDINGS_LIMITS.acceptRiskMaxDays - 1,
  suppress: FINDINGS_LIMITS.suppressMaxDays - 1,
});
