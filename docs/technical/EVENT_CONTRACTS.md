# QmentisAI Event and Message Contracts

## Purpose

Define stable, versioned contracts for events exchanged between API modules, workers and integration adapters.

## Common envelope

Jobs and events share one envelope family (`@qmentisai/contracts`, see `docs/architecture/WORKER_ARCHITECTURE.md`). An event:

```json
{
  "envelopeVersion": 1,
  "kind": "event",
  "messageId": "unique-message-id",
  "type": "organization.workspace.created",
  "schemaVersion": 1,
  "occurredAt": "2026-01-01T00:00:00.000Z",
  "tenantId": "tenant-id",
  "workspaceId": "workspace-id",
  "correlationId": "correlation-id",
  "initiator": { "type": "user", "id": "user-id" },
  "subject": { "type": "workspace", "id": "workspace-id" },
  "payload": { "workspaceId": "workspace-id", "name": "Payments", "ownerUserId": "user-id" }
}
```

A job has `"kind": "job"`, no `subject`, and optional `taskId` and `idempotencyKey`. Optional context ids (`repositoryId`, `pipelineId`, `executionId`) may be omitted when they do not apply. Each `type` is registered in the message catalog (`message-types.js`) with its kind, current `schemaVersion` and payload schema.

## Event naming

Use domain-qualified names, for example:
- `repository.webhook.received`
- `pipeline.execution.requested`
- `pipeline.execution.started`
- `pipeline.execution.completed`
- `scan.task.requested`
- `scan.task.completed`
- `finding.created`
- `finding.status.changed`
- `security.review.requested`
- `security.approval.completed`
- `usage.recorded`

## Contract requirements

- Include schema version.
- Validate every message at producer and consumer boundaries.
- Make handlers idempotent.
- Preserve correlation IDs.
- Carry tenant/resource context.
- Do not include raw credentials or secret values.
- Define retryability and dead-letter behavior.
- Document compatibility when fields change.

## Reliability

Database state changes that must reliably result in a message use the transactional outbox (`outbox.enqueue(tx, ...)` in the same transaction; the relay publishes with publisher confirms; ADR-011). Delivery is at-least-once, so every consumer is idempotent (`processed_messages`). Do not assume a database write and a RabbitMQ publish are atomic.
