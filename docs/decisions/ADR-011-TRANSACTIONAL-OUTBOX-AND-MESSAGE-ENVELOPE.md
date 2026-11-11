# ADR-011: One message envelope family, transactional outbox, idempotent consumers

- **Status:** Accepted and implemented (2026-11-11, on the product owner's instruction)
- **Relates to:** `docs/architecture/WORKER_ARCHITECTURE.md`, `docs/technical/EVENT_CONTRACTS.md`, ADR-003 (tenant isolation), ADR-009 (no credentials in messages)

## Context

Two envelopes existed in `@qmentisai/contracts` (a job envelope used by the publisher and consumer, and an unused domain-event envelope with different field names). A state change and the RabbitMQ publish that announces it were not atomic, and consumer idempotency lived only in Redis with a TTL.

## Decision

1. **One schema family**: a shared base (`messageId`, `type`, `schemaVersion`, `tenantId`, `correlationId`, `occurredAt`, `initiator`, plus `envelopeVersion` and optional context ids) with a **job** extension and an **event** extension (`kind` discriminator). A message-type catalog gives each type its kind, payload schema and `schemaVersion`; producers and consumers validate against it.
2. **Transactional outbox**: `outbox_messages` rows are written in the producer's database transaction; a **relay** publishes them with publisher confirms, claiming rows with `FOR UPDATE SKIP LOCKED` so several relays are safe. Delivery is at-least-once.
3. **Idempotent consumers**: `processed_messages`, unique per (tenant, consumer, idempotency key = `idempotencyKey` or `messageId`), replaces Redis as the default store; Redis remains a fallback for workers without a database.
4. **Ownership re-validation** before the handler: tenant usable, envelope `workspaceId` and the type-specific resource belong to the tenant; mismatches are non-retryable.
5. **First real flow**: `organization.workspace.created` is enqueued inside the workspace-creation transaction and handled by the notification worker.

Retry tiers and the dead-letter topology are unchanged.

## Consequences

- Wire format change: `eventType` became `type`, `createdAt` became `occurredAt`, `kind` and `envelopeVersion` are required. Nothing else published messages yet, so no migration of in-flight messages was needed.
- The relay holds row locks (one database transaction) while publishing a batch; a failed publish stops the batch early so a broker outage does not hold the transaction open.
- Sent outbox rows and completed `processed_messages` rows accumulate until a purge job exists (Open).
- Workers that verify ownership need `DATABASE_URL`.

## Live verification (2026-11-11)

Real processes (API, outbox relay, notification worker) against RabbitMQ 4 (throwaway container) and PostgreSQL 18, 23 of 23 scenario checks passed:

| Scenario | Result |
|---|---|
| Publish and consume end to end | A workspace created through the API produced a pending outbox row; the relay sent it (confirmed) and marked it `sent`; the notification worker logged it and wrote a `done` row in `processed_messages` |
| Duplicate delivery | The same `messageId` published 3 times: the handler ran once, 2 deliveries logged as skipped |
| Transient failure | Failed twice then succeeded: handler attempts 1, 2, 3 with backoff; a failure that never recovered ran 4 times, then went to the DLQ (`max-attempts-exceeded`) |
| Non-retryable | Went straight to the DLQ with its reason header (`invalid-configuration`); unknown type -> `unknown-type` |
| Ownership | A nonexistent workspace and a workspace of another tenant were refused before the handler (`resource-not-in-tenant`) |
| Several relays | 3 relay instances, 150 outbox rows: all sent, the worker handled 150 distinct messages, none twice, none needed a retry |
| Broker outage | With the broker stopped the API still created workspaces; the row stayed pending (`ECONNREFUSED` recorded, attempts counted); the relay stayed alive; the consumer exited as designed; after the broker returned the relay published by itself and the restarted worker consumed it exactly once |
| Broker restart | 3 persistent messages stayed in the durable queue across a broker restart and were consumed once each |

Not covered: a relay killed between publish and mark (covered in effect by the duplicate-delivery scenario), very long outages (dead after 100 attempts, default), DLQ replay tooling, load. The scenarios are a scratch harness, not part of the repository or the security suite; tenant isolation of outbox rows is not yet a security-suite check.
