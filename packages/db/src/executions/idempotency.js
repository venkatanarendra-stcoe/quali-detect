import { createProcessedMessageStore } from "../processed-message-store.js";

const STEP = /^[a-z][a-z0-9_.:-]{0,63}$/;

/**
 * Key of one idempotent step of one execution in `processed_messages` (SPEC §6.4 layer (a)): stable across redeliveries and
 * across workers, so a duplicate wake-up never runs the step twice. `attempt` separates the attempts of a task.
 * @param {{ executionId: string, step: string, attempt?: number }} input
 * @returns {string}
 */
export function executionStepKey({ executionId, step, attempt }) {
  if (typeof executionId !== "string" || !/^[0-9a-f-]{36}$/i.test(executionId))
    throw new TypeError("executionId must be a UUID");
  if (!STEP.test(step)) throw new TypeError("step must be a short lower-case code");
  return Number.isInteger(attempt)
    ? `execution:${executionId}:${step}:${attempt}`
    : `execution:${executionId}:${step}`;
}

/**
 * Idempotency groundwork for the execution consumers (SPEC §6.4, B2): layer (a) is the `processed_messages` claim by message
 * (this helper); layer (b) is the execution claim itself (`claimQueued` compare-and-set and the lease epoch), which stays the
 * real protection because the claim's TTL is shorter than an execution (ERK-2). The orchestrator (part C) composes both.
 * Rows are tenant-scoped: the unique key is (tenantId, scope, key).
 * @param {{ db: any, processingTtlSeconds?: number }} deps Prisma client
 */
export function createExecutionIdempotency({ db, processingTtlSeconds = 900 }) {
  const store = createProcessedMessageStore({ db, processingTtlSeconds });
  return Object.freeze({
    /**
     * Runs `fn` at most once per (tenant, scope, key) across redeliveries: a finished step is skipped (`done`), a step that
     * another delivery is running is left to it (`processing`), a step that failed is released so a retry can run it.
     * @template T
     * @param {{ tenantId: string, scope: string, key: string, messageId?: string }} claim `tenantId` is the TRUSTED tenant (from the verified execution row), never from the message.
     * @param {() => Promise<T>} fn
     * @returns {Promise<{ ran: true, result: T } | { ran: false, state: "done" | "processing" }>}
     */
    async runOnce(claim, fn) {
      if (!claim.tenantId) throw new TypeError("tenantId is required");
      const state = await store.begin(claim);
      if (state !== "new") return { ran: false, state };
      let result;
      try {
        result = await fn();
      } catch (error) {
        await store.release(claim);
        throw error;
      }
      await store.complete(claim);
      return { ran: true, result };
    },
  });
}
