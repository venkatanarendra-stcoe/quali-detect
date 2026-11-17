import { createEventEnvelope, createJobEnvelope, QUEUE_NAMES } from "@qmentisai/contracts";
import { createOutboxRepository } from "@qmentisai/db";
import { assertNoCredentials, createOutbox } from "@qmentisai/infra";

const SAFE_ID = /^[A-Za-z0-9._-]{1,128}$/;
const safeId = (value, fallback) =>
  typeof value === "string" && SAFE_ID.test(value) ? value : fallback;

/**
 * The producer side of the orchestrator's messages (docs/modules/executions/SPEC.md §9.1): every message is built from the
 * trusted rows, validated against the catalog by the outbox (producer-side), checked for credentials and written through the
 * TRANSACTION of the state change (ADR-011). `trust` decides the scan queue: `untrusted_fork` tasks go to `scan-untrusted`.
 * @param {{ db: any }} deps
 */
export function createMessageProducer({ db }) {
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
  const initiator = { type: "system", id: "execution-orchestrator" };

  const base = (exec, messageId, correlationId) => ({
    messageId,
    schemaVersion: 1,
    tenantId: exec.tenantId,
    workspaceId: exec.workspaceId,
    repositoryId: exec.repositoryId,
    pipelineId: exec.pipelineId,
    executionId: exec.id,
    correlationId: safeId(correlationId ?? exec.correlationId, messageId),
    initiator,
  });
  async function send(tx, queue, message) {
    assertNoCredentials(message, `${message.type} message`);
    await outbox.enqueue(tx, { queue, message });
  }

  return Object.freeze({
    /** Hint for Socket.IO: ids, status and revision only. */
    statusChanged: (tx, exec, status, rev, correlationId) =>
      send(
        tx,
        QUEUE_NAMES.REALTIME,
        createEventEnvelope({
          ...base(exec, `execution-status-${exec.id}-${rev}`, correlationId),
          type: "pipeline.execution.status_changed",
          subject: { type: "execution", id: exec.id },
          payload: {
            executionId: exec.id,
            workspaceId: exec.workspaceId,
            pipelineId: exec.pipelineId,
            status,
            rev,
          },
        }),
      ),
    /** Hint for Socket.IO (SPEC scan-decisioning 8): the decision was recorded. Ids and the revision only, never model text. */
    decisionCompleted: (tx, exec, rev, correlationId) =>
      send(
        tx,
        QUEUE_NAMES.REALTIME,
        createEventEnvelope({
          ...base(exec, `execution-decision-${exec.id}`, correlationId),
          type: "pipeline.execution.decision_completed",
          subject: { type: "execution", id: exec.id },
          payload: {
            executionId: exec.id,
            workspaceId: exec.workspaceId,
            pipelineId: exec.pipelineId,
            rev,
          },
        }),
      ),
    started: (tx, exec, { startedAt, taskCount }, correlationId) =>
      send(
        tx,
        QUEUE_NAMES.REALTIME,
        createEventEnvelope({
          ...base(exec, `execution-started-${exec.id}`, correlationId),
          type: "pipeline.execution.started",
          subject: { type: "execution", id: exec.id },
          payload: {
            executionId: exec.id,
            pipelineId: exec.pipelineId,
            repositoryId: exec.repositoryId,
            workspaceId: exec.workspaceId,
            startedAt: startedAt.toISOString(),
            taskCount,
          },
        }),
      ),
    /** THE single terminal event (CF-4). `payload` is built by the caller from the trusted rows. */
    completed: (tx, exec, payload, correlationId) =>
      send(
        tx,
        QUEUE_NAMES.REALTIME,
        createEventEnvelope({
          ...base(exec, `execution-completed-${exec.id}`, correlationId),
          type: "pipeline.execution.completed",
          subject: { type: "execution", id: exec.id },
          payload,
        }),
      ),
    taskRequested: (tx, exec, task, { trust, deadlineAt }, correlationId) => {
      const messageId = `scan-task-requested-${task.id}-${task.attempt}`;
      return send(
        tx,
        trust === "untrusted_fork" ? QUEUE_NAMES.SCAN_UNTRUSTED : QUEUE_NAMES.SCAN,
        createJobEnvelope({
          ...base(exec, messageId, correlationId),
          type: "scan.task.requested",
          taskId: task.id,
          idempotencyKey: messageId,
          payload: {
            executionId: exec.id,
            taskId: task.id,
            scanType: task.scanType,
            attempt: task.attempt,
            pipelineId: exec.pipelineId,
            repositoryId: exec.repositoryId,
            workspaceId: exec.workspaceId,
            trust,
            deadlineAt: deadlineAt ? deadlineAt.toISOString() : null,
          },
        }),
      );
    },
    taskCompleted: (tx, exec, { taskId, scanType, attempt, status, resultId }, correlationId) =>
      send(
        tx,
        QUEUE_NAMES.PIPELINE,
        createEventEnvelope({
          ...base(exec, `scan-task-completed-${taskId}-${attempt}`, correlationId),
          type: "scan.task.completed",
          subject: { type: "scan_task", id: taskId },
          payload: { executionId: exec.id, taskId, scanType, attempt, status, resultId },
        }),
      ),
    taskStatusChanged: (tx, exec, { taskId, scanType, status, rev }, correlationId) =>
      send(
        tx,
        QUEUE_NAMES.REALTIME,
        createEventEnvelope({
          ...base(exec, `scan-task-status-${taskId}-${rev}`, correlationId),
          type: "scan.task.status_changed",
          subject: { type: "scan_task", id: taskId },
          payload: {
            executionId: exec.id,
            taskId,
            workspaceId: exec.workspaceId,
            scanType,
            status,
            rev,
          },
        }),
      ),
  });
}
