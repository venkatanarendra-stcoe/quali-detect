/**
 * Domain errors of the findings repositories (docs/modules/findings/SPEC.md 8). The API maps them to HTTP: `FindingNotFoundError` is
 * the identical 404, `FindingConflictError` is `409 FINDING_STATE_CONFLICT` with `details.reason`. A repository never builds an HTTP
 * response; it only names the reason.
 */
export class FindingNotFoundError extends Error {
  constructor() {
    super("The finding was not found.");
    this.name = "FindingNotFoundError";
  }
}

export class FindingConflictError extends Error {
  /** @param {"stale_revision" | "transition_not_allowed" | "exception_pending" | "pipeline_deleted" | "already_decided"} reason */
  constructor(reason) {
    super(`The finding state conflicts with the request (${reason}).`);
    this.name = "FindingConflictError";
    this.reason = reason;
  }
}
