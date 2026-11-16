import { createExecutionRetentionRepository } from "@qmentisai/db";
import { NonRetryableError } from "@qmentisai/infra";

/**
 * The handler of `maintenance.executions.purge_requested` (docs/modules/executions/SPEC.md ER-17, §17.ac). It runs ONLY in the
 * scheduler worker, the platform worker that may look across tenants. A second gate refuses the job unless
 * `EXECUTION_RETENTION_PURGE_ENABLED=true` in THIS process (a message alone never enables a purge), and execution metadata is
 * deleted only when the message carries a period AND `EXECUTION_RETENTION_PURGE_METADATA=true`. The purge is idempotent and
 * batch-limited; the result is logged as COUNTS only.
 * @param {{ db: any, config: any }} deps
 * @returns {(message: any, context: { log: any }) => Promise<void>}
 */
export function createExecutionRetentionHandler({ db, config }) {
  const repository = createExecutionRetentionRepository({ db });
  return async (message, { log }) => {
    const retention = config?.execution?.retention;
    if (!retention?.purgeEnabled)
      throw new NonRetryableError("The execution retention purge is not enabled in this process.", {
        reason: "purge-disabled",
      });
    const { logRetentionDays, artifactRetentionDays, metadataRetentionMonths, batchSize } =
      message.payload;
    const counts = await repository.purgeExpired({
      logRetentionDays,
      artifactRetentionDays,
      metadataRetentionMonths: retention.purgeMetadata ? metadataRetentionMonths : null,
      batchSize,
    });
    log.info(
      { ...counts, logRetentionDays, artifactRetentionDays, metadataRetentionMonths },
      "Execution retention purge finished (counts only)",
    );
  };
}
