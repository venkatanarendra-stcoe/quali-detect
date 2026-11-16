/** Audit action names of the execution orchestrator (docs/modules/executions/SPEC.md §11; the API's constants live in apps/api, a worker cannot import them). */
export const AUDIT = Object.freeze({
  PREPARING: "execution.preparing",
  STARTED: "execution.started",
  SUCCEEDED: "execution.succeeded",
  FAILED: "execution.failed",
  PARTIAL: "execution.partial",
  TIMED_OUT: "execution.timed_out",
  CANCELLED: "execution.cancelled",
  EXPIRED: "execution.expired",
  RECOVERED: "execution.recovered",
  LEASE_RECLAIMED: "execution.lease_reclaimed",
  WORKER_LOST: "execution.worker_lost",
});

/** Audit action of a terminal status. */
export const AUDIT_BY_STATUS = Object.freeze({
  succeeded: AUDIT.SUCCEEDED,
  failed: AUDIT.FAILED,
  partial: AUDIT.PARTIAL,
  timed_out: AUDIT.TIMED_OUT,
  cancelled: AUDIT.CANCELLED,
});

/** Hard cap of an execution deadline, whatever the snapshot says (PT §5.8, ER-16). */
export const EXECUTION_TIMEOUT_CAP_SECONDS = 7200;
/** Default deadline when the snapshot cannot be read (the execution is failed right after the claim). */
export const DEFAULT_DEADLINE_SECONDS = 1800;
export const ARCHIVE_NAME = "source.tar.gz";

/**
 * Prepare failures that are the PLATFORM's fault and give the quota unit back (SPEC §5.9): GitHub or storage unavailable,
 * a snapshot that does not match. Failures caused by the tenant's repository (missing ref, oversize or invalid archive,
 * lost access) consume the unit.
 */
export const PLATFORM_PREPARE_FAILURES = Object.freeze([
  "github_unavailable",
  "storage_error",
  "config_snapshot_mismatch",
  "config_invalid",
]);

/** Control characters stripped from every string that comes from an engine or a repository before it is stored. */
// eslint-disable-next-line no-control-regex
export const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
