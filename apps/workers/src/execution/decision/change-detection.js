import { DIFF_SOURCES, DIFF_STATUSES } from "@qmentisai/shared";

/**
 * Change detection of the scan decision (docs/modules/scan-decisioning/SPEC.md 5.2, 17.a), a thin orchestration over the GitHub
 * client's `listChangedFiles`. A FULL run takes no diff and makes NO API call. An incremental run reads the changed files of the
 * pinned SHAs: a push (and any other trigger with a stored base) through the compare API, a pull request (same repository and
 * fork alike) through the pull-request files API of the BASE repository. Everything is fail closed: the result is `complete` only
 * for a whole, validated list; `truncated` and `unavailable` carry no files and make the floor "all enabled types".
 *
 * The caller passes facts it loaded from the database (never from a message): this module trusts no tenant input and logs only
 * ids, statuses, counts and durations (SD-10), never paths or the token (which this module never sees).
 * @param {{
 *   execution: { id?: string, scanKind: string, triggerType?: string, baseSha?: string | null, commitSha?: string | null, pullRequestNumber?: number | null },
 *   repository: { fullName: string, externalInstallationId: string },
 *   github: { listChangedFiles: Function },
 *   config: { scanDecision: { maxChangedFiles: number, maxPages: number } },
 *   signal?: AbortSignal,
 *   logger?: any,
 * }} input
 * @returns {Promise<{
 *   status: "not_needed" | "complete" | "truncated" | "unavailable",
 *   source: "none" | "github_compare" | "github_pull_files" | "unavailable",
 *   files: Array<{ path: string, previousPath: string | null, status: string, additions: number, deletions: number }>,
 *   reason: string | null,
 *   durationMs: number,
 * }>}
 */
export async function detectChanges({ execution, repository, github, config, signal, logger }) {
  const started = Date.now();
  const done = (status, source, files, reason) => {
    logger?.info?.(
      {
        executionId: execution?.id,
        diffStatus: status,
        diffSource: source,
        reason,
        changedTotal: files.length,
        durationMs: Date.now() - started,
      },
      "Change detection finished",
    );
    return { status, source, files, reason, durationMs: Date.now() - started };
  };
  // FL-5: a full run needs no diff and makes no API call. Only an explicit incremental run reads one; any other value is
  // treated as "no diff available" by the floor (fail closed), not as a reason to call GitHub.
  if (execution?.scanKind === "full")
    return done(DIFF_STATUSES.NOT_NEEDED, DIFF_SOURCES.NONE, [], null);
  if (execution?.scanKind !== "incremental")
    return done(DIFF_STATUSES.UNAVAILABLE, DIFF_SOURCES.UNAVAILABLE, [], "unsupported_scan_kind");

  let answer;
  try {
    answer = await github.listChangedFiles({
      externalInstallationId: repository.externalInstallationId,
      // The BASE repository registered for this pipeline: a fork pull request is read through it as well.
      repository: { fullName: repository.fullName },
      kind: execution.triggerType === "pull_request" ? "pull_request" : "push",
      baseSha: execution.baseSha ?? null,
      headSha: execution.commitSha ?? null,
      pullRequestNumber: execution.pullRequestNumber ?? null,
      maxFiles: config.scanDecision.maxChangedFiles,
      maxPages: config.scanDecision.maxPages,
      signal,
    });
  } catch {
    // listChangedFiles never throws; a defect there must still fail closed.
    return done(DIFF_STATUSES.UNAVAILABLE, DIFF_SOURCES.UNAVAILABLE, [], "internal_error");
  }
  const status = Object.values(DIFF_STATUSES).includes(answer?.status) ? answer.status : null;
  if (status === null || status === DIFF_STATUSES.NOT_NEEDED || !Array.isArray(answer.files))
    return done(DIFF_STATUSES.UNAVAILABLE, DIFF_SOURCES.UNAVAILABLE, [], "invalid_answer");
  if (status !== DIFF_STATUSES.COMPLETE)
    return done(
      status,
      status === DIFF_STATUSES.UNAVAILABLE ? DIFF_SOURCES.UNAVAILABLE : answer.source,
      [],
      typeof answer.reason === "string" ? answer.reason : null,
    );
  return done(status, answer.source, answer.files, null);
}
