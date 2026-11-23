import { MESSAGE_TYPES } from "@qmentisai/contracts";
import { NonRetryableError, TransientError } from "@qmentisai/infra";
import { runAdvisory } from "./advise.js";
import { createConcurrencyLimiter, createTenantTokenBucket } from "./controls.js";

/**
 * The queue handler of the `findings-agent` worker for `finding.advisory.requested` (docs/modules/findings/SPEC.md 9.2, 9.3.1). It runs
 * after the envelope is validated and the idempotency claim; this handler re-validates the payload, then runs the advisory core.
 *
 *  - Advice only. Failure is silent for the workflow (FP-4): a model, provider, consent or cap failure becomes a stored advisory status;
 *    only an infrastructure error (the database) is thrown, so the queue retries it.
 *  - A rate-limited request is a {@link TransientError} (redelivered later with the retry tiers).
 *  - `finding.advisory.completed` is a realtime HINT published straight through `publishCompleted` (NOT through the outbox: the agent's
 *    database role cannot write it, SPEC 0.5 item 1). A failing hint is logged and swallowed.
 * @param {{
 *   repository: import("./advise.js").AgentRepositoryPort,
 *   llm: import("./advise.js").AdvisoryLlmPort,
 *   config: { findings: { agentMaxConcurrentCalls: number, agentTenantDailyCap: number } },
 *   rateLimiter?: { tryAcquire: (tenantId: string) => Promise<boolean> },
 *   publishCompleted?: (hint: { tenantId: string, workspaceId: string, findingId: string, advisoryId: string, status: string }) => Promise<void>,
 *   now?: () => Date,
 * }} deps
 * @returns {(message: any, context: { log: any, attempt?: number, signal?: AbortSignal }) => Promise<void>}
 */
export function createFindingsAgentHandler({
  repository,
  llm,
  config,
  rateLimiter = createTenantTokenBucket(),
  publishCompleted,
  now,
}) {
  const limiter = createConcurrencyLimiter(config.findings.agentMaxConcurrentCalls);
  const schema = MESSAGE_TYPES["finding.advisory.requested"].payload;
  return async (message, { log, signal }) => {
    if (message?.type !== "finding.advisory.requested")
      throw new NonRetryableError("unexpected-message-type");
    const parsed = schema.safeParse(message.payload);
    if (!parsed.success || typeof message.tenantId !== "string")
      throw new NonRetryableError("invalid-payload");
    const result = await runAdvisory({
      message: { tenantId: message.tenantId, payload: parsed.data },
      repository,
      llm,
      config,
      limiter,
      rateLimiter,
      now,
      signal,
      logger: log,
    });
    log?.info?.(
      { outcome: result.outcome, status: result.status, findingId: parsed.data.findingId },
      "Advisory request handled",
    );
    if (result.outcome === "rate_limited") throw new TransientError("advisory-rate-limited");
    if (result.outcome === "stored" && result.created !== false && publishCompleted) {
      try {
        await publishCompleted({
          tenantId: result.finding.tenantId,
          workspaceId: result.finding.workspaceId,
          findingId: result.finding.id,
          advisoryId: result.advisoryId,
          status: result.status,
        });
      } catch {
        log?.warn?.({ findingId: parsed.data.findingId }, "Advisory completed hint not published");
      }
    }
  };
}
