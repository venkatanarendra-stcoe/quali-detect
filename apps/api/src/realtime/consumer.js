import { QUEUE_NAMES } from "@qmentisai/contracts";
import { NonRetryableError, createConsumer } from "@qmentisai/infra";
import { USABLE_TENANT_STATUSES } from "@qmentisai/shared";
import { buildFindingHint, isFindingHintType } from "./findings.js";
import { buildHint } from "./hints.js";

/**
 * The `realtime` queue consumer (docs/modules/executions/SPEC.md §9.4). It runs in the API process because the sockets live
 * there (no Redis adapter, single instance). Per message the shared consumer already validates the strict contract
 * (`parseMessage`), claims idempotency in `processed_messages` (a duplicate delivery is skipped, so a hint is emitted once) and
 * dead-letters non-retryable failures. This module adds the two realtime-specific steps:
 *  - `verify`: the tenant of the message must exist and be usable, and the execution (and task) it names must exist IN THAT
 *    TENANT with exactly the workspace and pipeline the payload states. The tenantId of a message is only a claim.
 *  - `handler`: the rooms are built from the DATABASE row, never from message fields, then the hint is emitted.
 */

/** @typedef {{ tenantId: string, workspaceId: string, executionId: string, pipelineId: string }} HintTarget */

/**
 * @param {{ repository: ReturnType<typeof import("./repository.js").createRealtimeRepository> }} deps
 */
export function createHintResolver({ repository }) {
  /** @type {WeakMap<object, HintTarget | { tenantId: string, workspaceId: string, findingId: string }>} */
  const resolved = new WeakMap();
  const reject = (reason) =>
    new NonRetryableError("The message does not belong to the tenant.", { reason });
  return Object.freeze({
    /** Consumer `verify` hook. @param {any} message */
    async verify(message) {
      const tenant = await repository.findTenant(message.tenantId);
      if (!tenant || !USABLE_TENANT_STATUSES.includes(tenant.status))
        throw reject("tenant-not-usable");
      const { payload } = message;
      if (isFindingHintType(message.type)) {
        // the findings room (SPEC findings 9.5): the finding must exist IN THE MESSAGE'S TENANT with the workspace the payload states
        const finding = await repository.findFinding({
          tenantId: message.tenantId,
          id: payload.findingId,
        });
        if (!finding || finding.workspaceId !== payload.workspaceId)
          throw reject("resource-not-in-tenant");
        resolved.set(message, {
          tenantId: finding.tenantId,
          workspaceId: finding.workspaceId,
          findingId: finding.id,
        });
        return;
      }
      const execution = await repository.findExecution({
        tenantId: message.tenantId,
        id: payload.executionId,
      });
      if (!execution) throw reject("resource-not-in-tenant");
      if (payload.workspaceId !== undefined && payload.workspaceId !== execution.workspaceId)
        throw reject("resource-not-in-tenant");
      if (payload.pipelineId !== undefined && payload.pipelineId !== execution.pipelineId)
        throw reject("resource-not-in-tenant");
      if (payload.taskId !== undefined) {
        const task = await repository.findTask({
          tenantId: message.tenantId,
          executionId: execution.id,
          id: payload.taskId,
        });
        if (!task || (payload.scanType !== undefined && payload.scanType !== task.scanType))
          throw reject("resource-not-in-tenant");
      }
      resolved.set(message, {
        tenantId: execution.tenantId,
        workspaceId: execution.workspaceId,
        executionId: execution.id,
        pipelineId: execution.pipelineId,
      });
    },
    /** @param {any} message @returns {HintTarget | undefined} */
    targetOf: (message) => resolved.get(message),
  });
}

/**
 * @param {{ resolver: ReturnType<typeof createHintResolver>, realtime: { emit: (hint: { event: string, rooms: string[], payload: object }) => void } }} deps
 */
export function createHintHandler({ resolver, realtime }) {
  return async function handleHint(message) {
    const target = resolver.targetOf(message);
    if (!target)
      throw new NonRetryableError("The message was not verified.", { reason: "unverified" });
    const hint = isFindingHintType(message.type)
      ? buildFindingHint(message, /** @type {any} */ (target))
      : buildHint(message, /** @type {HintTarget} */ (target));
    if (hint) realtime.emit(hint);
  };
}

/**
 * @param {{
 *   connection: any, repository: ReturnType<typeof import("./repository.js").createRealtimeRepository>,
 *   realtime: { emit: Function }, idempotency: any, logger: any, prefetch?: number, retryPolicy?: object,
 * }} deps
 */
export function createRealtimeConsumer({
  connection,
  repository,
  realtime,
  idempotency,
  logger,
  prefetch = 20,
  retryPolicy,
}) {
  const resolver = createHintResolver({ repository });
  return createConsumer({
    connection,
    queue: QUEUE_NAMES.REALTIME,
    verify: (message) => resolver.verify(message),
    handler: createHintHandler({ resolver, realtime }),
    idempotency,
    logger,
    prefetch,
    retryPolicy,
    requireTenant: true,
  });
}
