import { NonRetryableError } from "@qmentisai/infra";
import { REPORTING_MESSAGE_TYPES, isDayString, localDayOf } from "@qmentisai/shared";
import { loadTenant, runBackfill, runClose, runIncremental } from "./job.js";

/**
 * The handler of `reporting.rollup.requested` (docs/modules/reporting-dashboards/SPEC.md 7.2, 10). The consumer has validated the envelope
 * and the payload against the catalogue, checked the tenant against the database and claimed the message id; this handler STILL
 * re-validates that the tenant named by the ENVELOPE exists and is usable, refuses a payload that names another tenant, and reads the time
 * zone from the database. It is idempotent (the upserts are keyed by the natural key and rewrite nothing that did not change), bounded
 * (a backfill runs in throttled batches), writes nothing while `REPORTING_ENABLED` is false and fails with the stable codes of
 * `ROLLUP_ERROR_CODES` (non-retryable for validation and ownership, retryable for a transient database error or a timeout).
 * @param {import("./index.js").ReportingWorkerDeps} deps
 * @returns {(message: any, context: { log?: any, attempt?: number, signal?: AbortSignal }) => Promise<void>}
 */
export function buildRollupHandler({
  rollupRepository: repo,
  config,
  logger,
  now = () => new Date(),
  options,
}) {
  return async function handleRollup(message, context = {}) {
    const log = context.log ?? logger;
    if (message?.type !== REPORTING_MESSAGE_TYPES.ROLLUP_REQUESTED)
      throw new NonRetryableError("the rollup handler does not handle this message type", {
        reason: "invalid_range",
      });
    if (config?.reporting && config.reporting.enabled !== true) {
      log?.warn?.(
        { messageId: message.messageId },
        "reporting is disabled: the rollup message is ignored, nothing is written",
      );
      return;
    }
    const payload = message.payload ?? {};
    const tenantId = message.tenantId;
    // the envelope tenant is the only authority; a payload that names another one is a forged or misrouted message
    if (typeof tenantId !== "string" || payload.tenantId !== tenantId)
      throw new NonRetryableError("the payload tenant differs from the envelope tenant", {
        reason: "ownership_mismatch",
      });
    const tenant = await loadTenant(repo, tenantId);
    const deps = { repo, log, now, reporting: config?.reporting, options };
    const timeZone = tenant.timeZone;
    const today = localDayOf(now(), timeZone);

    let result;
    if (payload.mode === "incremental") {
      // an incremental for an earlier day (consumed after midnight) is that day's close; a later day does not exist yet
      const day = payload.day ?? today;
      if (!isDayString(day) || day > today)
        throw new NonRetryableError("invalid incremental day", { reason: "invalid_range" });
      result =
        day === today
          ? await runIncremental(deps, { tenantId, timeZone })
          : await runClose(deps, { tenantId, timeZone }, day);
    } else if (payload.mode === "close") {
      result = await runClose(deps, { tenantId, timeZone }, payload.day);
    } else if (payload.mode === "backfill") {
      if (!isDayString(payload.from) || !isDayString(payload.to) || payload.from > payload.to)
        throw new NonRetryableError("invalid backfill range", { reason: "invalid_range" });
      result = await runBackfill(deps, { tenantId, timeZone }, payload, context.signal);
    } else {
      throw new NonRetryableError("unknown rollup mode", { reason: "invalid_range" });
    }
    log?.info?.(
      { tenantId, mode: payload.mode, rowsWritten: result.rowsWritten, batches: result.batches },
      "reporting rollup finished",
    );
  };
}
