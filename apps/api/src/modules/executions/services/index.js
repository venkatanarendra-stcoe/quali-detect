import { ERROR_CODES, QUEUE_NAMES, createEventEnvelope } from "@qmentisai/contracts";
import { EntitlementError, QUOTA_KEYS } from "@qmentisai/db";
import {
  cancelModeOf,
  cancelRouteOf,
  computeEffectiveState,
  isRetryableExecutionStatus,
  manualRunBlockOf,
  retryIdempotencyKey,
} from "@qmentisai/shared";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import {
  AppError,
  ConflictError,
  NotFoundError,
  ValidationError,
} from "../../../errors/app-error.js";
import { isUniqueViolation } from "../../../lib/http.js";
import {
  IN_FLIGHT_STATUSES,
  QUOTA_PERIOD,
  REASONS,
  RETRY_GATE_REASONS,
} from "../constants/index.js";
import { toExecutionActionDto } from "../mappers/index.js";

/**
 * Cancel and retry of an execution (docs/modules/executions/SPEC.md part D, ER-14, ER-18 to ER-23). The route (part G) has
 * already authorized the caller in the execution's workspace (`execution.cancel` / `execution.run`); here live the business
 * rules, every change audited and every message written in the SAME transaction as the change:
 *
 * - `cancel`: a `queued` execution is cancelled at once by compare-and-set with its quota unit released exactly once; a
 *   `preparing`/`running` one only RECORDS the request (mode from the configuration SNAPSHOT, never from the client) and the
 *   lease holder honours it; a finished one is `409 already_finished`, `blocked`/`skipped` `409 not_cancellable`. A second or
 *   concurrent request changes nothing.
 * - `retry`: a NEW `queued` execution with the same snapshot (version id and hash), the pinned original commit, the same trust
 *   and trigger context, `retry_of_execution_id` set, one fresh quota unit, `pipeline.execution.requested` through the outbox.
 *   It re-validates tenant, pipeline, repository and workspace NOW (a retry never bypasses a gate), and an `Idempotency-Key`
 *   makes a repeated call return the same new execution.
 *
 * Both load the execution by tenant AND id: another tenant's execution is a `404`, indistinguishable from a missing one.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createExecutionsRepository>,
 *   audit: any, outbox: any, entitlements: any,
 *   config: { cancelGraceSeconds: number, abortGraceSeconds: number, retryChainMax: number },
 * }} deps
 */
export function createExecutionService({
  repository,
  audit,
  outbox,
  entitlements,
  config: settings,
}) {
  const entry = (actor, action, execution, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "execution",
    targetId: execution.id,
    workspaceId: execution.workspaceId,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  const conflict = (message, reason) => new ConflictError(message, { details: { reason } });
  const base = (actor, execution, messageId) => ({
    messageId,
    schemaVersion: 1,
    tenantId: actor.tenantId,
    workspaceId: execution.workspaceId,
    repositoryId: execution.repositoryId,
    pipelineId: execution.pipelineId,
    executionId: execution.id,
    correlationId: actor.requestId,
    initiator: { type: "user", id: actor.userId },
    subject: { type: "execution", id: execution.id },
  });
  const load = async (actor, ref, tx) => {
    const execution = await repository.findExecution({ tenantId: actor.tenantId, id: ref.id }, tx);
    // another tenant's or a missing execution is the same 404; a workspace that does not match the route's is too
    if (!execution || (ref.workspaceId && execution.workspaceId !== ref.workspaceId))
      throw new NotFoundError();
    return execution;
  };

  async function cancelOnce(actor, ref) {
    return repository.transaction(async (tx) => {
      const execution = await load(actor, ref, tx);
      const route = cancelRouteOf(execution.status);
      if (route === "not_cancellable")
        throw conflict(
          "This execution was never started and cannot be cancelled.",
          REASONS.NOT_CANCELLABLE,
        );
      if (route === "already_finished")
        throw conflict("This execution has already finished.", REASONS.ALREADY_FINISHED);
      if (route === "cancel_now") {
        const done = await repository.cancelQueued(
          {
            tenantId: actor.tenantId,
            executionId: execution.id,
            reason: "user_cancelled",
            actor: { type: "user", userId: actor.userId },
            correlationId: actor.requestId,
            eventDetails: { reason: "user_cancelled" },
          },
          tx,
        );
        if (!done.cancelled) return { again: true }; // a claim or another cancel won: look at the row again
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.EXECUTION_CANCEL_REQUESTED, execution, {
            metadata: { executionId: execution.id, fromStatus: "queued", mode: "immediate" },
          }),
          { tx },
        );
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.EXECUTION_CANCELLED, execution, {
            metadata: {
              executionId: execution.id,
              pipelineId: execution.pipelineId,
              from: "queued",
              to: "cancelled",
              reason: "user_cancelled",
              quotaReleased: done.quotaReleased,
            },
          }),
          { tx },
        );
        await outbox.enqueue(tx, {
          queue: QUEUE_NAMES.REALTIME,
          message: createEventEnvelope({
            ...base(actor, execution, `execution-status-${execution.id}-${done.statusRev}`),
            type: "pipeline.execution.status_changed",
            payload: {
              executionId: execution.id,
              workspaceId: execution.workspaceId,
              pipelineId: execution.pipelineId,
              status: "cancelled",
              rev: done.statusRev,
            },
          }),
        });
        const fresh = await repository.findExecution(
          { tenantId: actor.tenantId, id: execution.id },
          tx,
        );
        return { result: { outcome: "cancelled", execution: toExecutionActionDto(fresh) } };
      }
      // preparing / running: record the request, nothing else (ER-18). The mode is the SNAPSHOT's, never the client's (ER-19).
      const version = await repository.findSnapshot(
        {
          tenantId: actor.tenantId,
          pipelineId: execution.pipelineId,
          id: execution.configVersionId,
        },
        tx,
      );
      const mode = cancelModeOf(version?.config);
      const done = await repository.requestCancel(
        {
          tenantId: actor.tenantId,
          executionId: execution.id,
          userId: actor.userId,
          mode,
          graceSeconds:
            mode === "graceful" ? settings.cancelGraceSeconds : settings.abortGraceSeconds,
          correlationId: actor.requestId,
        },
        tx,
      );
      if (!done.recorded) {
        // already requested (idempotent: same state, no second event, nothing moved) or it finished meanwhile
        const current = await repository.findExecution(
          { tenantId: actor.tenantId, id: execution.id },
          tx,
        );
        if (
          current &&
          cancelRouteOf(current.status) === "record_request" &&
          current.cancelRequestedAt
        )
          return {
            result: {
              outcome: "cancel_requested",
              alreadyRequested: true,
              execution: toExecutionActionDto(current),
            },
          };
        return { again: true };
      }
      await audit.tenant.record(
        entry(actor, AUDIT_ACTIONS.EXECUTION_CANCEL_REQUESTED, execution, {
          metadata: {
            executionId: execution.id,
            pipelineId: execution.pipelineId,
            status: done.status,
            mode,
          },
        }),
        { tx },
      );
      await outbox.enqueue(tx, {
        queue: QUEUE_NAMES.PIPELINE,
        message: createEventEnvelope({
          ...base(actor, execution, `execution-cancel-requested-${execution.id}`),
          type: "pipeline.execution.cancel_requested",
          payload: {
            executionId: execution.id,
            pipelineId: execution.pipelineId,
            requestedAt: done.cancelRequestedAt.toISOString(),
            mode,
          },
        }),
      });
      const fresh = await repository.findExecution(
        { tenantId: actor.tenantId, id: execution.id },
        tx,
      );
      return {
        result: {
          outcome: "cancel_requested",
          alreadyRequested: false,
          execution: toExecutionActionDto(fresh),
        },
      };
    });
  }

  return Object.freeze({
    /**
     * Cancel (ER-18 to ER-20). `outcome: "cancelled"` (a queued execution, HTTP 200) or `"cancel_requested"` (an active one,
     * HTTP 202; `alreadyRequested` on a repeated or concurrent call). Throws `NotFoundError` (hidden or absent) and
     * `ConflictError` with `details.reason` `already_finished` / `not_cancellable`.
     * @param {{ tenantId: string, userId: string, requestId?: string, ip?: string }} actor
     * @param {{ id: string, workspaceId?: string }} ref
     * @returns {Promise<{ outcome: "cancelled" | "cancel_requested", alreadyRequested?: boolean, execution: any }>}
     */
    async cancel(actor, ref) {
      // a lost compare-and-set (a claim or another cancel won) re-reads the row and answers by its new state
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const outcome = await cancelOnce(actor, ref);
        if (outcome.result) return outcome.result;
      }
      throw conflict("The execution is changing; try again.", REASONS.ALREADY_FINISHED);
    },

    /**
     * Retry (ER-21 to ER-23): a new execution from a terminal one. `idempotencyKey` is the validated `Idempotency-Key`
     * header; the stored key is `retry:<userId>:<header>`. A denial rolls everything back and a gate or quota refusal is
     * audited as `execution.retry_denied` OUTSIDE that transaction.
     * @param {{ tenantId: string, userId: string, requestId?: string, ip?: string, tenantStatus?: string | null }} actor
     * @param {{ id: string, workspaceId?: string }} ref
     * @param {string} idempotencyKey
     * @returns {Promise<{ execution: any, replayed: boolean }>}
     */
    async retry(actor, ref, idempotencyKey) {
      if (typeof idempotencyKey !== "string" || !/^[\x21-\x7e]{1,200}$/.test(idempotencyKey))
        throw new ValidationError(
          [
            {
              path: "Idempotency-Key",
              code: "required",
              message: "Send an Idempotency-Key header of 1 to 200 printable characters.",
            },
          ],
          { source: "headers" },
        );
      const key = retryIdempotencyKey(actor.userId, idempotencyKey);
      let original = null;
      let replayed = false;
      let row;
      try {
        row = await repository.transaction(async (tx) => {
          original = await load(actor, ref, tx);
          await repository.lockPipeline(
            { tenantId: actor.tenantId, pipelineId: original.pipelineId },
            tx,
          );
          const replay = await repository.findExecutionByKey(
            { tenantId: actor.tenantId, pipelineId: original.pipelineId, idempotencyKey: key },
            tx,
          );
          if (replay) {
            // the key names ONE retry: the same key for another execution is a conflict, never a silent other result
            if (replay.retryOfExecutionId !== original.id)
              throw new AppError(
                ERROR_CODES.IDEMPOTENCY_CONFLICT,
                "This Idempotency-Key was used for another request.",
              );
            replayed = true;
            return replay;
          }
          if (!isRetryableExecutionStatus(original.status))
            throw conflict(
              "Only an execution that did not succeed and has finished can be retried.",
              REASONS.NOT_RETRYABLE_STATUS,
            );
          // gates, NOW (a retry never bypasses them): tenant, pipeline, repository, workspace
          const pipeline = await repository.findPipelineContext(
            {
              tenantId: actor.tenantId,
              workspaceId: original.workspaceId,
              repositoryId: original.repositoryId,
              pipelineId: original.pipelineId,
            },
            tx,
          );
          if (!pipeline || pipeline.deletedAt)
            throw conflict("The pipeline was deleted.", REASONS.PIPELINE_DELETED);
          const state = computeEffectiveState({
            tenantStatus: pipeline.tenant.status,
            workspaceStatus: pipeline.workspace.status,
            repositoryStatus: pipeline.repository.status,
            repositoryEnabled: pipeline.repository.enabled,
            pipelineEnabled: pipeline.enabled,
            pipelineDeletedAt: pipeline.deletedAt,
          });
          if (state === "tenant_unavailable")
            throw new AppError(ERROR_CODES.TENANT_SUSPENDED, "This tenant is not active.");
          const blocked = manualRunBlockOf(state);
          if (blocked)
            throw conflict("The pipeline cannot run right now.", REASONS[blocked.toUpperCase()]);
          const depth = await repository.retryDepth(
            {
              tenantId: actor.tenantId,
              pipelineId: original.pipelineId,
              executionId: original.id,
              limit: settings.retryChainMax,
            },
            tx,
          );
          if (depth + 1 > settings.retryChainMax)
            throw conflict(
              "This execution has been retried too many times in a row.",
              REASONS.RETRY_CHAIN_LIMIT,
            );
          const version = await repository.findSnapshot(
            {
              tenantId: actor.tenantId,
              pipelineId: original.pipelineId,
              id: original.configVersionId,
            },
            tx,
          );
          if (!version) throw new NotFoundError();
          const group = original.concurrencyGroup;
          const policy = version.config?.execution?.concurrency ?? {};
          const fields = {
            tenantId: actor.tenantId,
            workspaceId: original.workspaceId,
            repositoryId: original.repositoryId,
            pipelineId: original.pipelineId,
            // the SAME snapshot, never the pipeline's current configuration (reproducible, EXEC-022)
            configVersionId: original.configVersionId,
            configVersion: original.configVersion,
            configHash: original.configHash,
            triggerType: original.triggerType,
            triggerKey: original.triggerKey,
            scmEventId: original.scmEventId,
            scmDeliveryId: original.scmDeliveryId,
            scmEventKind: original.scmEventKind,
            scheduleSlot: original.scheduleSlot,
            requestedByUserId: actor.userId,
            retryOfExecutionId: original.id,
            refType: original.refType,
            refName: original.refName,
            baseRef: original.baseRef,
            pullRequestNumber: original.pullRequestNumber,
            // the PINNED original commit (null only if the original failed before pinning: then it is pinned again)
            commitSha: original.commitSha,
            baseSha: original.baseSha,
            scanKind: original.scanKind,
            scanKindReason: "retry",
            // a fork stays untrusted_fork: a retry never raises trust
            trust: original.trust,
            concurrencyGroup: group,
            idempotencyKey: key,
            correlationId: actor.requestId,
          };
          const skip = async (reason) => {
            const skipped = await repository.createExecution(
              { ...fields, status: "skipped", statusReason: reason },
              tx,
            );
            await audit.tenant.record(
              entry(actor, AUDIT_ACTIONS.EXECUTION_SKIPPED, skipped, {
                metadata: { executionId: skipped.id, reason, retryOfExecutionId: original.id },
              }),
              { tx },
            );
            return skipped;
          };
          if (policy.policy === "skip") {
            const busy = await repository.countExecutions(
              {
                tenantId: actor.tenantId,
                pipelineId: original.pipelineId,
                statuses: [...IN_FLIGHT_STATUSES],
                concurrencyGroup: group,
              },
              tx,
            );
            if (busy > 0) return skip("concurrency_skip");
          } else if (policy.policy === "queue") {
            const queued = await repository.countExecutions(
              { tenantId: actor.tenantId, pipelineId: original.pipelineId, statuses: ["queued"] },
              tx,
            );
            if (queued >= (policy.maxQueued ?? 0)) return skip("queue_full");
          } else {
            const superseded = await repository.cancelQueuedInGroup(
              {
                tenantId: actor.tenantId,
                pipelineId: original.pipelineId,
                concurrencyGroup: group,
                reason: "superseded",
              },
              tx,
            );
            for (const old of superseded)
              await audit.tenant.record(
                entry(actor, AUDIT_ACTIONS.EXECUTION_CANCELLED_SUPERSEDED, original, {
                  metadata: { executionId: old.id, triggerType: original.triggerType },
                }),
                { tx },
              );
          }
          // a FRESH quota unit, in this transaction: a refusal (quota, entitlement) rolls everything back
          const period = QUOTA_PERIOD();
          await entitlements.consumeQuota(
            {
              tenantId: actor.tenantId,
              quotaKey: QUOTA_KEYS.SCANS_MONTHLY,
              amount: 1,
              periodKey: period,
            },
            tx,
          );
          const created = await repository.createExecution(
            { ...fields, status: "queued", quotaPeriod: period, quotaConsumed: 1 },
            tx,
          );
          await repository.recordEvent(
            {
              tenantId: actor.tenantId,
              executionId: created.id,
              type: "retry_requested",
              reason: "retry",
              actor: { type: "user", userId: actor.userId },
              correlationId: actor.requestId,
              details: { retryOfExecutionId: original.id },
            },
            tx,
          );
          await outbox.enqueue(tx, {
            queue: QUEUE_NAMES.PIPELINE,
            message: createEventEnvelope({
              ...base(actor, created, `execution-requested-${created.id}`),
              type: "pipeline.execution.requested",
              payload: {
                executionId: created.id,
                pipelineId: created.pipelineId,
                repositoryId: created.repositoryId,
                workspaceId: created.workspaceId,
                configVersion: created.configVersion,
                configHash: created.configHash,
                triggerType: created.triggerType,
                triggerKey: created.triggerKey,
                refType: created.refType,
                refName: created.refName,
                commitSha: created.commitSha,
                pullRequestNumber: created.pullRequestNumber,
                scanKind: created.scanKind,
                scanKindReason: created.scanKindReason,
                trust: created.trust,
              },
            }),
          });
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.EXECUTION_RETRY_REQUESTED, created, {
              metadata: {
                executionId: created.id,
                retryOfExecutionId: original.id,
                version: created.configVersion,
                configHash: created.configHash,
                trust: created.trust,
                scanKind: created.scanKind,
              },
            }),
            { tx },
          );
          return created;
        });
      } catch (error) {
        const reason = original ? denialReason(error) : null;
        if (reason)
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.EXECUTION_RETRY_DENIED, original, {
              metadata: { executionId: original.id, reason },
            }),
          );
        else if (original && isUniqueViolation(error)) {
          // the same Idempotency-Key raced past the replay lookup: the winner's row is the answer
          const winner = await repository.findExecutionByKey({
            tenantId: actor.tenantId,
            pipelineId: original.pipelineId,
            idempotencyKey: key,
          });
          if (winner?.retryOfExecutionId === original.id)
            return { execution: toExecutionActionDto(winner), replayed: true };
        }
        throw error;
      }
      return { execution: toExecutionActionDto(row), replayed };
    },

    /** Records the denial of a cancel on an execution the caller can see but may not cancel (route policy). Nothing for a 404. */
    async recordCancelPermissionDenied(actor, ref) {
      const execution = await repository.findExecution({ tenantId: actor.tenantId, id: ref.id });
      if (!execution) return;
      await audit.tenant.record(
        entry(actor, AUDIT_ACTIONS.EXECUTION_CANCEL_DENIED, execution, {
          metadata: { executionId: execution.id, reason: REASONS.PERMISSION_DENIED },
        }),
      );
    },

    /** Records the denial of a retry on an execution the caller can see but may not retry (route policy). Nothing for a 404. */
    async recordRetryPermissionDenied(actor, ref) {
      const execution = await repository.findExecution({ tenantId: actor.tenantId, id: ref.id });
      if (!execution) return;
      await audit.tenant.record(
        entry(actor, AUDIT_ACTIONS.EXECUTION_RETRY_DENIED, execution, {
          metadata: { executionId: execution.id, reason: REASONS.PERMISSION_DENIED },
        }),
      );
    },
  });
}

/** The audited reason of a refused retry, or null when the error is not a denial. @param {unknown} error */
function denialReason(error) {
  if (error instanceof ConflictError && RETRY_GATE_REASONS.includes(error.details?.reason))
    return error.details.reason;
  if (error instanceof EntitlementError)
    return error.code === "QUOTA_EXCEEDED" ? REASONS.QUOTA_EXCEEDED : REASONS.ENTITLEMENT_REQUIRED;
  return null;
}
