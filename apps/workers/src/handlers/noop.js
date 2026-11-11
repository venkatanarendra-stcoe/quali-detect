/**
 * Placeholder job handler: records that a validated job arrived and does nothing else.
 * Real handlers must verify that every referenced resource belongs to `envelope.tenantId`, be idempotent, and throw
 * `TransientError` / `NonRetryableError` (from @qmentisai/infra) to control retries.
 * @returns {(envelope: object, context: { log: any, attempt: number }) => Promise<void>}
 */
export function createNoopHandler() {
  return async (envelope, { log, attempt }) => {
    log.info({ attempt }, "Job received (no-op handler)");
  };
}
