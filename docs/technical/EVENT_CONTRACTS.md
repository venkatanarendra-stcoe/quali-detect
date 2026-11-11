# QmentisAI Event and Message Contracts

## Purpose

Define stable, versioned contracts for events exchanged between API modules, workers and integration adapters.

## Common envelope

```json
{
  "messageId": "unique-message-id",
  "eventType": "pipeline.execution.requested",
  "schemaVersion": 1,
  "occurredAt": "2026-01-01T00:00:00.000Z",
  "tenantId": "tenant-id",
  "workspaceId": "workspace-id",
  "repositoryId": "repository-id",
  "pipelineId": "pipeline-id",
  "executionId": "execution-id",
  "correlationId": "correlation-id",
  "actor": {
    "type": "USER",
    "id": "actor-id"
  },
  "payload": {}
}
```

Fields that do not apply to an event may be omitted, but the schema must explicitly define required fields for each event type.

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

Use a transactional outbox or another documented reliable publication strategy when database state changes must reliably result in a message. Do not assume a database write and RabbitMQ publish are atomic.
