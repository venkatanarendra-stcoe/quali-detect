import {
  Ban,
  CalendarClock,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleDot,
  CircleSlash,
  CircleX,
  Clock,
  GitBranch,
  GitPullRequest,
  Hand,
  Loader,
  LoaderCircle,
  RotateCcw,
  SkipForward,
  Timer,
} from "lucide-react";
import { SCAN_TASK_ORDER } from "@qmentisai/shared";
import { DECISION_REASONS } from "@/features/pipelines/constants/index.js";

/**
 * Execution status chips (SCREENS §1, DESIGN_SYSTEM "Executions and scan tasks"): icon + text, never colour alone. `tone` is
 * the existing Badge tone; `active` statuses use the neutral foreground and a spinner (DESIGN_SYSTEM `--status-active`:
 * "never mint or blue"), `spin` stops under `prefers-reduced-motion`.
 */
export const EXECUTION_STATUSES = Object.freeze({
  queued: { label: "Queued", tone: "neutral", icon: Clock },
  preparing: { label: "Preparing", tone: "neutral", icon: Loader, active: true, spin: true },
  running: { label: "Running", tone: "neutral", icon: LoaderCircle, active: true, spin: true },
  succeeded: { label: "Succeeded", tone: "success", icon: CircleCheck },
  failed: { label: "Failed", tone: "danger", icon: CircleX },
  partial: { label: "Partial", tone: "warning", icon: CircleAlert },
  cancelled: { label: "Cancelled", tone: "neutral", icon: CircleSlash },
  timed_out: { label: "Timed out", tone: "danger", icon: Timer },
  blocked: { label: "Blocked", tone: "warning", icon: Ban },
  skipped: { label: "Skipped", tone: "neutral", icon: SkipForward },
  cancelling: { label: "Cancelling", tone: "warning", icon: LoaderCircle, spin: true },
});
const humanize = (code) =>
  String(code)
    .replace(/_/g, " ")
    .replace(/^./, (c) => c.toUpperCase());
export const executionStatus = (status) =>
  EXECUTION_STATUSES[status] ?? { label: humanize(status), tone: "neutral", icon: CircleDot };

/** Statuses of the filter (the API enum without the legacy `cancelling`), in lifecycle order. */
export const FILTER_STATUSES = Object.freeze([
  "queued",
  "preparing",
  "running",
  "succeeded",
  "failed",
  "partial",
  "cancelled",
  "timed_out",
  "blocked",
  "skipped",
]);
/** The "Active" preset of the status filter. */
export const ACTIVE_STATUSES = Object.freeze(["queued", "preparing", "running"]);
export const CANCELLABLE_STATUSES = ACTIVE_STATUSES;
export const isActiveStatus = (status) => ACTIVE_STATUSES.includes(status);
export const isTerminalStatus = (status) =>
  Boolean(status) && !isActiveStatus(status) && status !== "cancelling";
/** A cancel is in progress: the chip stays "Running" and a sub-label says "Cancelling" (SPEC CF-1). */
export const isCancelling = (e) =>
  Boolean(e.cancelRequested) && (e.status === "preparing" || e.status === "running");

/** Plain words for `statusReason` codes of an execution (unknown codes fall back to the code in words). */
export const STATUS_REASONS = Object.freeze({
  ...DECISION_REASONS,
  superseded: "Replaced by a newer request",
  pipeline_deleted: "The pipeline was deleted",
  quota_exceeded: "Quota exceeded",
  entitlement_required: "Not included in the plan",
  concurrency_skipped: "Another request was already in flight",
  queue_full: "The queue is full",
  queue_expired: "Queued too long",
  expired_stale: "Queued too long",
  config_invalid: "Config invalid",
  config_snapshot_mismatch: "Config invalid",
  execution_deadline: "Time limit reached",
  user_cancelled: "Cancelled by a user",
  tasks_failed: "Some scans failed",
  tasks_unsupported: "Some scan types are not supported yet",
  worker_lost: "Worker lost",
  reclaim_limit: "Worker lost",
  lease_lost: "Worker lost",
  lease_expired: "Worker lost",
  archive_host_refused: "Source could not be fetched",
  archive_integrity: "Source failed an integrity check",
  archive_missing: "Source archive is missing",
  archive_too_large: "Source is too large",
  github_unavailable: "GitHub was unavailable",
  tenant_suspended: "The organization is suspended",
  tenant_inactive: "The organization is not active",
  internal_error: "Internal error",
});
/**
 * Reason text of an execution. `tasks_unsupported` on a failed execution means nothing could run.
 * @param {string | null | undefined} code
 * @param {string} [status]
 */
export function reasonText(code, status) {
  if (!code) return null;
  if (code === "tasks_unsupported" && status === "failed")
    return "No enabled scan type is supported yet";
  return STATUS_REASONS[code] ?? humanize(code);
}

/** Scan task statuses. `unsupported` is NOT a failure (SPEC §17.ab): neutral chip "Not supported". */
export const TASK_STATUSES = Object.freeze({
  pending: { label: "Pending", tone: "neutral", icon: Clock },
  queued: { label: "Queued", tone: "neutral", icon: Clock },
  running: { label: "Running", tone: "neutral", icon: LoaderCircle, active: true, spin: true },
  succeeded: { label: "Succeeded", tone: "success", icon: CircleCheck },
  failed: { label: "Failed", tone: "danger", icon: CircleX },
  timed_out: { label: "Timed out", tone: "danger", icon: Timer },
  cancelled: { label: "Cancelled", tone: "neutral", icon: CircleSlash },
  skipped: { label: "Skipped", tone: "neutral", icon: SkipForward },
  unsupported: { label: "Not supported", tone: "neutral", icon: CircleDashed },
});
export const taskStatus = (status) =>
  TASK_STATUSES[status] ?? { label: humanize(status), tone: "neutral", icon: CircleDot };

export const TASK_REASONS = Object.freeze({
  engine_not_registered: "No engine is available for this scan type yet.",
  engine_failed: "The engine reported a failure.",
  engine_error: "The engine reported an error.",
  engine_unavailable: "The engine was unavailable.",
  parse_failed: "The engine output could not be read.",
  task_deadline: "The scan reached its time limit.",
  execution_deadline: "The execution reached its time limit.",
  user_cancelled: "Cancelled by a user.",
  cancel_requested: "Cancelled by a user.",
  worker_lost: "The worker running this scan was lost.",
  walk_limit: "The repository is larger than the scan limit.",
  storage_error: "Results could not be stored.",
});
export const taskReasonText = (code) =>
  code ? (TASK_REASONS[code] ?? `${humanize(code)}.`) : null;

export const TASK_TITLES = Object.freeze({
  sbom: "SBOM",
  sca: "SCA",
  sast: "SAST",
  secrets: "Secrets",
});
/** Display order of the task cards (SBOM, SCA, SAST, Secrets). */
export const TASK_ORDER = SCAN_TASK_ORDER;

export const TRIGGER_FILTERS = Object.freeze([
  { value: "push", label: "Push" },
  { value: "pull_request", label: "Pull request" },
  { value: "schedule", label: "Schedule" },
  { value: "manual", label: "Manual" },
]);
export const TRIGGER_ICONS = Object.freeze({
  push: GitBranch,
  pull_request: GitPullRequest,
  schedule: CalendarClock,
  manual: Hand,
});

export const SCAN_KIND_REASONS = Object.freeze({
  first_run: "first run for this pipeline",
  config_changed: "the configuration changed",
  branch_created: "a new branch",
  force_push: "a force push",
  tag: "a tag",
  scheduled: "scheduled",
  manual: "requested manually",
  configured_full: "the pipeline always scans fully",
  pull_request: "pull request",
  incremental: "only changes since the last scan",
});
export const scanKindText = (kind, reason) => {
  const label = kind === "full" ? "Full" : "Incremental";
  const why = reason ? (SCAN_KIND_REASONS[reason] ?? humanize(reason).toLowerCase()) : null;
  return why ? `${label}: ${why}` : label;
};

export const LOG_LEVELS = Object.freeze(["error", "warn", "info", "debug"]);
export const RETRY_ICON = RotateCcw;

/** Event types of the history (`execution_events.type`) that are not a plain status change. */
export const EVENT_LABELS = Object.freeze({
  recovered: "Resumed after a worker restart",
  cancel_requested: "Cancel requested",
  limit_deferred: "Waiting for capacity",
  retry_requested: "Retry requested",
  task_unsupported: "A scan type is not supported yet",
});

/** Refusals of cancel and retry (`409 details.reason`, SPEC §8.1) in plain words. */
export const CONFLICT_MESSAGES = Object.freeze({
  already_finished: "This execution has already finished.",
  not_cancellable: "This execution cannot be cancelled.",
  not_retryable_status:
    "Only a failed, partial, cancelled, timed out or blocked execution can be retried.",
  pipeline_deleted: "The pipeline was deleted.",
  pipeline_disabled: "The pipeline is disabled. Enable it, then retry.",
  repository_not_active: "The repository is not active (disabled, unavailable or disconnected).",
  workspace_archived: "The workspace is archived, so nothing can run in it.",
  retry_chain_limit: "This execution has been retried the maximum number of times.",
});

export const CANCEL_DENIED = "You need permission to cancel executions in this workspace.";
export const RETRY_DENIED = "You need permission to run pipelines in this workspace.";

export const LIST_PAGE_SIZE = 25;
export const SHORT_ID_LENGTH = 8;
