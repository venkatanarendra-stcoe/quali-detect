import {
  Archive,
  Ban,
  CircleCheck,
  CircleSlash,
  GitBranch,
  GitPullRequest,
  Hand,
  PauseCircle,
  PlugZap,
  TriangleAlert,
  CalendarClock,
  Unplug,
  Trash2,
} from "lucide-react";
import { DEFAULT_BRANCH_TOKEN, PIPELINE_SCAN_TYPES } from "@qmentisai/shared";

/** Wizard steps; numbering is stable in the URL (`?step=`). Notifications stays hidden until its module exists (SCREENS §5). */
export const WIZARD_STEPS = Object.freeze([
  { id: "basics", label: "Basics" },
  { id: "triggers", label: "Triggers" },
  { id: "scans", label: "Scans" },
  { id: "controls", label: "Execution controls" },
  { id: "review", label: "Review" },
]);

export const TRIGGER_LABELS = Object.freeze({
  push: "Push",
  pull_request: "Pull request",
  schedule: "Schedule",
  manual: "Manual",
});
export const TRIGGER_ICONS = Object.freeze({
  push: GitBranch,
  pull_request: GitPullRequest,
  schedule: CalendarClock,
  manual: Hand,
});

export const SCAN_LABELS = Object.freeze({
  sca: "SCA",
  sbom: "SBOM",
  sast: "SAST",
  secrets: "Secret Scanning",
});
export const SCAN_SHORT = Object.freeze({
  sca: "SCA",
  sbom: "SBOM",
  sast: "SAST",
  secrets: "Secrets",
});
export const SCAN_HELP = Object.freeze({
  sca: "Finds known vulnerabilities in dependencies, read from manifests and lockfiles.",
  sbom: "Produces a software bill of materials from manifests and lockfiles.",
  sast: "Static analysis of source files. Nothing is built or run.",
  secrets: "Looks for credentials committed to the repository.",
});
export const SEVERITY_LABELS = Object.freeze({
  none: "Never fail",
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
});

/** Derived effective state chip (SPEC §5.2): label, tone, icon and the sentence used in banners and tooltips. */
export const EFFECTIVE_STATES = Object.freeze({
  running_normally: {
    label: "Enabled",
    tone: "success",
    icon: CircleCheck,
    reason: null,
  },
  disabled: {
    label: "Disabled",
    tone: "neutral",
    icon: PauseCircle,
    reason: "The pipeline is disabled. Enable it to start scanning.",
  },
  repository_disabled: {
    label: "Repository disabled",
    tone: "warning",
    icon: Ban,
    reason:
      "Stopped: the repository is disabled. The pipeline resumes automatically when the repository is enabled.",
  },
  repository_unavailable: {
    label: "Repository unavailable",
    tone: "warning",
    icon: PlugZap,
    reason:
      "Stopped: the repository is unavailable. The pipeline resumes automatically when the repository is active.",
  },
  repository_disconnected: {
    label: "Repository disconnected",
    tone: "warning",
    icon: Unplug,
    reason:
      "Stopped: the repository is disconnected. The pipeline resumes automatically when the repository is active.",
  },
  workspace_archived: {
    label: "Workspace archived",
    tone: "neutral",
    icon: Archive,
    reason: "Stopped: the workspace is archived. Restore the workspace to resume the pipeline.",
  },
  tenant_unavailable: {
    label: "Organization unavailable",
    tone: "warning",
    icon: TriangleAlert,
    reason: "Stopped: the organization is not active.",
  },
  deleted: { label: "Deleted", tone: "neutral", icon: Trash2, reason: null },
});

/** Human labels of the trigger decision reason codes (SPEC §7.8). */
export const DECISION_REASONS = Object.freeze({
  fork_policy_skip: "Fork pull request, policy is Do not run",
  draft_policy_skip: "Draft pull request",
  repository_inactive: "Repository disconnected or unavailable",
  repository_disabled: "Repository disabled",
  workspace_archived: "Workspace archived",
  pipeline_disabled: "Pipeline disabled",
  trigger_disabled: "Trigger disabled",
  cancelled_pr_closed: "Pull request closed, queued run cancelled",
});
export const SOURCE_LABELS = Object.freeze({
  scm_event: "Webhook event",
  schedule_slot: "Schedule slot",
  manual: "Manual run",
});

/** Dry-run no_match and policy reasons. */
export const DRY_RUN_REASONS = Object.freeze({
  ...DECISION_REASONS,
  trigger_type_mismatch: "No trigger of this type",
  unsupported_ref: "Not a branch push",
  branch_excluded: "The branch is excluded by a pattern",
  branch_not_included: "The branch is not in the include patterns",
  branch_created_skipped: "New branches are skipped",
  force_push_skipped: "Force pushes are skipped",
  action_not_selected: "This pull request action is not selected",
  pull_request_merged: "The pull request is merged",
  target_branch_not_matched: "The target branch does not match",
  tag_not_enabled: "Tag pushes are not enabled",
  tag_excluded: "The tag is excluded by a pattern",
  tag_not_included: "The tag is not in the include patterns",
});
export const DRY_RUN_DECISIONS = Object.freeze({
  would_run: { label: "Would run", tone: "success", icon: CircleCheck },
  no_match: { label: "No match", tone: "neutral", icon: CircleSlash },
  blocked_by_policy: { label: "Blocked by policy", tone: "warning", icon: Ban },
  not_effective: { label: "Pipeline not active", tone: "warning", icon: PauseCircle },
});

/** Refusals of the manual run (409 `details.reason`) and other conflicts, in plain words (SPEC §5.6, R-3, R-4). */
export const CONFLICT_MESSAGES = Object.freeze({
  pipeline_disabled: "The pipeline is disabled. Enable it, then run it.",
  repository_not_active:
    "The repository is not active (disabled, unavailable or disconnected). Pipelines can run once it is active again.",
  workspace_archived: "The workspace is archived, so nothing can run in it.",
  manual_disabled:
    "Manual runs are switched off for this pipeline. Turn on the Manual trigger first.",
  name_taken: "A pipeline with this name already exists on the repository.",
  version_conflict:
    "Someone else changed this pipeline's configuration after you opened it. Reload the latest version, then re-apply your changes.",
  pipeline_incomplete: "Enable at least one scan type and one trigger first.",
  has_active_executions: "Cancel the running executions first, then delete the pipeline.",
  repository_pipeline_limit: "This repository already has the maximum number of pipelines.",
});

export const FORK_POLICY_LABELS = Object.freeze({
  skip: "Do not run",
  run_without_credentials: "Run without credentials",
});

export const PR_ACTION_LABELS = Object.freeze({
  opened: "Opened",
  synchronize: "New commits pushed",
  reopened: "Reopened",
  ready_for_review: "Ready for review",
});

/** Which wizard step a configuration path belongs to. @param {string} path */
export function stepOfPath(path) {
  const head = path.replace(/^config\./, "").split(".")[0];
  if (head === "triggers") return "triggers";
  if (head === "scans" || head === "exclusions") return "scans";
  if (head === "name" || head === "description" || head === "repositoryId") return "basics";
  if (head === "changeNote") return "review";
  return "controls";
}

const DEFAULT_ENGINE = Object.freeze({ id: "default" });

/** The configuration a new pipeline starts with: push on the default branch, pull requests, manual; SCA and secrets on. */
export function newConfig(limits) {
  const scans = Object.fromEntries(
    PIPELINE_SCAN_TYPES.map((type) => [
      type,
      {
        enabled: type === "sca" || type === "secrets",
        engine: { ...DEFAULT_ENGINE },
        severityThreshold: "low",
      },
    ]),
  );
  return {
    schemaVersion: 1,
    triggers: [
      pushTrigger(),
      pullRequestTrigger(),
      { key: "manual", type: "manual", enabled: true },
    ],
    scans,
    scanMode: { default: "incremental", fullEvery: null },
    failOn: { severity: "high", scope: "new", onEngineError: "fail" },
    exclusions: { paths: [] },
    execution: {
      timeoutSeconds: limits?.timeoutDefaultSeconds ?? 1800,
      scanTaskTimeoutSeconds: limits?.scanTaskTimeoutDefaultSeconds ?? 900,
      concurrency: { policy: "supersede", maxQueued: 5, maxActive: 1 },
      cancellation: "graceful",
    },
    notifications: {},
  };
}

export const pushTrigger = () => ({
  key: "push",
  type: "push",
  enabled: true,
  branches: { include: [DEFAULT_BRANCH_TOKEN], exclude: [] },
  tags: { enabled: false, include: [], exclude: [] },
  onBranchCreated: "run",
  onForcePush: "run",
});
export const pullRequestTrigger = () => ({
  key: "pull_request",
  type: "pull_request",
  enabled: true,
  actions: ["opened", "synchronize", "reopened", "ready_for_review"],
  targetBranches: { include: [DEFAULT_BRANCH_TOKEN], exclude: [] },
  drafts: "skip",
  forkPolicy: "skip",
});
export const scheduleTrigger = (key) => ({
  key,
  type: "schedule",
  enabled: true,
  cron: "0 2 * * *",
  timezone: "UTC",
  ref: DEFAULT_BRANCH_TOKEN,
  scanKind: "full",
  missedPolicy: "run_once",
});
