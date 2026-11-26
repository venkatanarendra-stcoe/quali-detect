import { NonRetryableError } from "@qmentisai/infra";

/**
 * The dispatcher of the `reporting` worker (docs/modules/reporting-dashboards/SPEC.md 10). Part A0 owns this file and `main.js`; the parts only
 * fill their own handler factory (`rollup/index.js` Part A, `export/index.js` Part C) and never edit the dispatcher.
 *
 * `handlers` maps a message type (`reporting.rollup.requested`, `reporting.export.requested`) to `async (message, { log, attempt, signal })`.
 * The consumer has already validated the envelope AND the payload against the catalogue of `@qmentisai/contracts`, checked that the tenant
 * exists and may still be used, and claimed the message id (idempotency); a handler still loads everything by TENANT and id from the
 * database and ignores any tenant in the message body. A type without a handler (a part that is not built yet) is a
 * {@link NonRetryableError}: the message goes to the dead-letter queue, where it is preserved, instead of being acknowledged and lost.
 * @param {Record<string, ((message: any, context: any) => Promise<void>) | null | undefined>} handlers
 * @returns {(message: any, context: { log?: any, attempt?: number, signal?: AbortSignal }) => Promise<void>}
 */
export function createReportingDispatcher(handlers) {
  const table = new Map(Object.entries(handlers).filter(([, h]) => typeof h === "function"));
  return async (message, context) => {
    const handler = table.get(message?.type);
    if (!handler) {
      context?.log?.warn?.(
        { type: message?.type },
        "reporting worker: no handler for this message type (its part is not built yet)",
      );
      throw new NonRetryableError("reporting-handler-not-built");
    }
    return handler(message, context);
  };
}
