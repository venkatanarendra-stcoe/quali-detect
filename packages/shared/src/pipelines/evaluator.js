import { matchIncludeExclude } from "./glob.js";
import { gateReasonOf } from "./effective-state.js";

/**
 * The pure trigger evaluator (SPEC §5.3, §5.4, §5.7, §6.2 steps 6-7): given a normalized SCM event and ONE trigger
 * definition of a pipeline configuration, decides `match`, `no_match` or `policy_skip` with stable reason codes. The trigger
 * router (worker) and the dry-run endpoint call the same function, so the preview and production cannot diverge. No Node,
 * database or framework imports: it never reads anything but its arguments.
 *
 * Normalized events (exactly the `scm.push.received` / `scm.pull_request.received` payload fields it uses):
 * - push: `{ kind: "push", ref, branch, created, deleted, forced }` (`branch` is null for tags)
 * - pull request: `{ kind: "pull_request", action, number, baseRef, headRef, isFork, draft, merged }`
 *
 * Order (SPEC §6.2): shape/pattern match (a non-match is a COUNTER only), then the state gates (`stopped: "gate"`), then the
 * fork and draft policy (`stopped: "policy"`); a stop at either stage is a policy skip that leaves a trigger decision row.
 * The fork flag is used exactly as received and never recomputed (`isFork` already maps "unknown" to true).
 */

const TAG_PREFIX = "refs/tags/";

/**
 * @typedef {{ kind: "push", ref: string, branch: string | null, created?: boolean, deleted?: boolean, forced?: boolean }} PushEvent
 * @typedef {{ kind: "pull_request", action: string, number: number, baseRef: string | null, headRef?: string | null, isFork: boolean, draft: boolean | null, merged?: boolean | null }} PullRequestEvent
 * @typedef {{
 *   decision: "match" | "no_match" | "policy_skip",
 *   stopped: "gate" | "policy" | null,
 *   reasons: string[],
 *   scanKind: "full" | "incremental" | null,
 *   scanKindReason: string | null,
 *   trust: "trusted" | "untrusted_fork" | null,
 *   refType: "branch" | "tag" | "pull_request" | null,
 *   refName: string | null,
 *   concurrencyGroup: string | null,
 * }} TriggerEvaluation
 */

const result = (decision, extra = {}) => ({
  decision,
  stopped: null,
  reasons: [],
  scanKind: null,
  scanKindReason: null,
  trust: null,
  refType: null,
  refName: null,
  concurrencyGroup: null,
  ...extra,
});
const noMatch = (reason) => result("no_match", { reasons: [reason] });

/**
 * Requested scan kind and its reason (SPEC §5.7 table, evaluated in this order). `shape` is what the event or trigger
 * dictates; `history` carries what only the caller can know (a first request, a changed scan-relevant configuration).
 * @param {{
 *   triggerType: "push" | "pull_request" | "schedule" | "manual",
 *   shape?: "branch_created" | "force_push" | "tag" | null,
 *   scanMode?: { default?: "incremental" | "full" },
 *   requestedKind?: "full" | "incremental",
 *   history?: { isFirstRequest?: boolean, configChanged?: boolean },
 * }} input
 * @returns {{ scanKind: "full" | "incremental", scanKindReason: string }}
 */
export function resolveScanKind({
  triggerType,
  shape = null,
  scanMode,
  requestedKind,
  history = {},
}) {
  if (history.isFirstRequest) return { scanKind: "full", scanKindReason: "first_run" };
  if (history.configChanged) return { scanKind: "full", scanKindReason: "config_changed" };
  if (shape) return { scanKind: "full", scanKindReason: shape };
  if (triggerType === "schedule")
    return { scanKind: requestedKind ?? "full", scanKindReason: "scheduled" };
  if (triggerType === "manual")
    return { scanKind: requestedKind ?? "full", scanKindReason: "manual" };
  if (scanMode?.default === "full") return { scanKind: "full", scanKindReason: "configured_full" };
  return {
    scanKind: "incremental",
    scanKindReason: triggerType === "pull_request" ? "pull_request" : "incremental",
  };
}

/** @param {any} trigger @param {PushEvent} event @param {{ defaultBranch?: string | null }} repo */
function matchPush(trigger, event, repo) {
  if (event.deleted) return noMatch("deleted_ref");
  const isTag = typeof event.ref === "string" && event.ref.startsWith(TAG_PREFIX);
  if (isTag) {
    const tag = event.ref.slice(TAG_PREFIX.length);
    if (!trigger.tags?.enabled) return noMatch("tags_disabled");
    const m = matchIncludeExclude(tag, trigger.tags);
    if (!m.matched) return noMatch(m.reason === "excluded" ? "tag_excluded" : "tag_not_included");
    return result("match", {
      refType: "tag",
      refName: tag,
      concurrencyGroup: `ref:${event.ref}`,
      shape: "tag",
    });
  }
  if (event.branch === null || event.branch === undefined) return noMatch("unsupported_ref");
  const m = matchIncludeExclude(event.branch, trigger.branches ?? {}, {
    defaultBranch: repo.defaultBranch,
  });
  if (!m.matched)
    return noMatch(m.reason === "excluded" ? "branch_excluded" : "branch_not_included");
  if (event.created && trigger.onBranchCreated === "skip") return noMatch("branch_created_skipped");
  if (!event.created && event.forced && trigger.onForcePush === "skip")
    return noMatch("force_push_skipped");
  return result("match", {
    refType: "branch",
    refName: event.branch,
    concurrencyGroup: `ref:${event.ref}`,
    shape: event.created ? "branch_created" : event.forced ? "force_push" : null,
  });
}

/** @param {any} trigger @param {PullRequestEvent} event @param {{ defaultBranch?: string | null }} repo */
function matchPullRequest(trigger, event, repo) {
  if (!(trigger.actions ?? []).includes(event.action)) return noMatch("action_not_selected");
  if (event.merged === true) return noMatch("pull_request_merged");
  if (typeof event.baseRef !== "string") return noMatch("target_branch_not_matched");
  const m = matchIncludeExclude(event.baseRef, trigger.targetBranches ?? {}, {
    defaultBranch: repo.defaultBranch,
  });
  if (!m.matched) return noMatch("target_branch_not_matched");
  return result("match", {
    refType: "pull_request",
    refName: `pull/${event.number}`,
    concurrencyGroup: `pr:${event.number}`,
    shape: null,
  });
}

/**
 * Evaluates one trigger against one event.
 * @param {{
 *   trigger: any,
 *   event: PushEvent | PullRequestEvent,
 *   repository?: { defaultBranch?: string | null },
 *   effectiveState?: string,
 *   scanMode?: { default?: "incremental" | "full" },
 *   history?: { isFirstRequest?: boolean, configChanged?: boolean },
 * }} input `effectiveState` defaults to `running_normally`
 * @returns {TriggerEvaluation}
 */
export function evaluateTrigger({
  trigger,
  event,
  repository = {},
  effectiveState = "running_normally",
  scanMode,
  history,
}) {
  if (trigger?.type !== event.kind) return noMatch("trigger_type_mismatch");
  const matched =
    event.kind === "push"
      ? matchPush(trigger, event, repository)
      : matchPullRequest(trigger, event, repository);
  if (matched.decision !== "match") return matched;
  const { shape, ...base } = /** @type {any} */ (matched);

  const gate =
    gateReasonOf(effectiveState) ?? (trigger.enabled === false ? "trigger_disabled" : null);
  if (gate) return { ...base, decision: "policy_skip", stopped: "gate", reasons: [gate] };

  if (event.kind === "pull_request") {
    if (event.isFork && trigger.forkPolicy !== "run_without_credentials")
      return { ...base, decision: "policy_skip", stopped: "policy", reasons: ["fork_policy_skip"] };
    if (event.draft === true && trigger.drafts !== "run")
      return {
        ...base,
        decision: "policy_skip",
        stopped: "policy",
        reasons: ["draft_policy_skip"],
      };
  }
  const kind = resolveScanKind({ triggerType: event.kind, shape, scanMode, history });
  const trust = event.kind === "pull_request" && event.isFork ? "untrusted_fork" : "trusted";
  return { ...base, ...kind, trust, decision: "match", stopped: null, reasons: [] };
}

/**
 * Evaluates every trigger of one pipeline configuration that the event could concern (same trigger type).
 * @param {{ config: any, event: PushEvent | PullRequestEvent, repository?: { defaultBranch?: string | null }, effectiveState?: string, history?: { isFirstRequest?: boolean, configChanged?: boolean } }} input
 * @returns {Array<TriggerEvaluation & { triggerKey: string, triggerType: string }>}
 */
export function evaluatePipelineTriggers({ config, event, repository, effectiveState, history }) {
  return (config?.triggers ?? [])
    .filter((trigger) => trigger.type === event.kind)
    .map((trigger) => ({
      triggerKey: trigger.key,
      triggerType: trigger.type,
      ...evaluateTrigger({
        trigger,
        event,
        repository,
        effectiveState,
        scanMode: config.scanMode,
        history,
      }),
    }));
}

/**
 * The dry-run vocabulary (SPEC §8): `would_run`, `no_match`, `blocked_by_policy` (fork/draft), `not_effective` (state gates).
 * @param {TriggerEvaluation} evaluation
 * @returns {"would_run" | "no_match" | "blocked_by_policy" | "not_effective"}
 */
export function toDryRunDecision(evaluation) {
  if (evaluation.decision === "match") return "would_run";
  if (evaluation.decision === "no_match") return "no_match";
  return evaluation.stopped === "gate" ? "not_effective" : "blocked_by_policy";
}
