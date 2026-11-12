# QmentisAI Worker Architecture

## Purpose

Workers handle asynchronous and long-running work outside the API request lifecycle.

## Initial worker types

| Worker | Responsibilities |
|---|---|
| Pipeline | Execution orchestration and state transitions |
| Analysis | Repository change and dependency analysis |
| Scan | Scan engine task execution and result ingestion |
| Notification | Email and external notifications |
| Usage | Usage metering and aggregation |
| Scheduler | Scheduled pipeline triggers (the due-schedule handler) and platform maintenance jobs |

## Message envelope (one schema family)

Jobs and domain events share one versioned envelope, defined in `@qmentisai/contracts` (`messages.js`). Both producers and consumers validate every message (`parseMessage`: envelope, then the catalogued payload schema for known types, `message-types.js`).

**Shared base:** `envelopeVersion` (1), `messageId`, `type` (`domain.entity.action`), `schemaVersion` (version of that type's payload), `tenantId`, `correlationId`, optional `causationId`, `occurredAt`, `initiator` (`{ type, id }`), optional context ids (`workspaceId`, `repositoryId`, `pipelineId`, `executionId`) and `payload`.

**Extensions** (discriminated by `kind`):
- **job** (`kind: "job"`): a command for a worker queue; adds optional `taskId` and `idempotencyKey`.
- **event** (`kind: "event"`): a fact that happened; adds a required `subject` (`{ type, id }`, the aggregate it is about).

The previous job envelope (`eventType`, `createdAt`) and the unused domain-event envelope (`eventType`, `actor`) are replaced by this family (`type`, `occurredAt`, `initiator`). Payloads never contain credentials; they carry a `secretRef` (ADR-009).

## Transactional outbox (ADR-011)

State changes that must produce a message write it to `outbox_messages` **in the same database transaction** (`outbox.enqueue(tx, { queue, message })`). Columns: `tenantId`, `messageId`, `type`, `queue`, `payload` (the full envelope), `status` (`pending`, `sent`, `dead`), `attempts`, `availableAt`, `lastError`, `createdAt`, `sentAt`; unique on (`messageId`, `queue`), so fan-out is one row per queue.

The **outbox relay** (`apps/workers`, `start:outbox`) claims due rows with `SELECT ... FOR UPDATE SKIP LOCKED`, publishes each with a **publisher confirm** and marks the batch sent in the same transaction. Any number of relay instances can run at once: each takes different rows and none waits for another. Failures reschedule the row with bounded exponential backoff and jitter; an envelope that can never be valid is marked `dead` immediately, and rows are marked `dead` after `OUTBOX_MAX_ATTEMPTS` (default 100). A broker outage does not stop the relay: rows stay pending and publishing resumes by itself when the broker is back. If a relay dies after publishing but before marking, the row is published again: delivery is **at-least-once**, consumers deduplicate.

## Scheduled maintenance (scheduler worker)

The scheduler worker consumes the `scheduler` queue and, while running, enqueues `maintenance.sessions.purge_requested` through the outbox every `SCHEDULER_SESSION_PURGE_INTERVAL_SECONDS` (default 1 h, also at startup). The messageId is derived from the time bucket and the outbox is unique per (messageId, queue), so several scheduler instances produce one job. The handler deletes tenant and platform sessions that expired, or were revoked, more than `SCHEDULER_SESSION_RETENTION_SECONDS` (default 24 h) ago; it is naturally idempotent because platform-level messages (catalog scope `platform`) carry no tenant to key an idempotency claim on.

## Pipeline schedules (scheduler worker, docs/modules/pipelines-triggers/SPEC.md §6.4, part E)

The scheduler worker also ticks every `PIPELINE_SCHEDULE_TICK_SECONDS` (default 60, also at startup) and enqueues the platform job `pipeline.schedules.due_requested` (payload `{ bucket }`, no tenant) to the `scheduler` queue through `enqueuePlatformJob`; the messageId `pipeline-schedules-due-<bucket>` and the unique `(messageId, queue)` make several scheduler instances produce one job. The scheduler's consumer (`createSchedulerHandler`) dispatches that type to `apps/workers/src/scheduler/schedules.js`. The job is naturally idempotent: a repeat finds the triggers already advanced.

The handler repeats, up to `PIPELINE_SCHEDULE_BATCH` times (100) per job: peek the next due `pipeline_triggers` row (`type = schedule AND enabled AND next_fire_at <= now`, the partial due-schedule index; tenants that already used `PIPELINE_SCHEDULE_MAX_PER_TENANT_PER_TICK` (10) in this run are excluded, so one tenant cannot starve the others) and handle it in its OWN transaction: advisory lock on the pipeline (`pipeline:<tenant>:<id>`, the same key as the pipelines API, the trigger router and the manual run, always taken before the row lock) -> claim the row with `FOR UPDATE SKIP LOCKED` scoped by tenant, workspace, repository, pipeline and id -> re-validate everything from the database (tenant usable, workspace active, repository present in the tenant and workspace, `active` and enabled, pipeline live and enabled, the trigger still present, enabled and unchanged in the CURRENT configuration version) -> create the request through the shared writer (`apps/workers/src/pipeline/execution-request.js`, the same concurrency policy, quota, rows, audit entries and `pipeline.execution.requested` outbox message as the SCM router) or record why nothing is created -> advance `next_fire_at` in the same transaction. The tenant of everything after the claim is the claimed row's, never a message field. The unique `(tenant, pipeline, schedule_slot)` is the backstop against a double fire. One trigger's failure is logged and retried at the next tick and never stops the batch. A policy or blocking state (repository not active or disabled, workspace archived, pipeline disabled) also writes one trigger decision row per trigger and slot (source type `schedule_slot`, SPEC §5.9b, §7.8) next to the counter. The fire time of a slot is the slot plus `hash(triggerId + slot) mod PIPELINE_SCHEDULE_JITTER_SECONDS` (300). Missed-run policy (`skip` = fire only when on time; **Recommended — default applied**, owner accepted 2026-11-13), DST rules and the platform limits (`PIPELINE_SCHEDULE_MAX_LATENESS_SECONDS` 21600, `PIPELINE_SCHEDULE_ON_TIME_GRACE_SECONDS` 120, `PIPELINE_SCHEDULE_JITTER_SECONDS` 300, tick, batch, per-tenant share) are in the SPEC §5.6 and §16; all are configuration placeholders in `apps/workers/src/config.js`.

## Queues and bindings

Each queue has the derived topology above (`qmentis.<q>`, `qmentis.<q>.retry.<n>`, `qmentis.<q>.dlq`). Queues fed from the SCM topic exchange `qmentis.scm.events` (the webhook transaction writes ONE outbox row; RabbitMQ copies it to every bound queue) add bindings that the consumer declares on start:

| Queue | Worker | Bindings on `qmentis.scm.events` | Handler |
|---|---|---|---|
| `scm`, `analysis`, `scan`, `notification`, `usage`, `scheduler`, `pipeline` | their worker | none (direct queue) | as built; `pipeline` is a no-op until the execution module |
| `scm-events` | `scm` (additional consumer) | `scm.github.#` | repository and installation state (push and pull-request events are acknowledged) |
| `pipeline-triggers` | `pipeline` (additional consumer) | `scm.github.push`, `scm.github.pull_request` | the trigger router (`apps/workers/src/pipeline/router.js`, docs/modules/pipelines-triggers/SPEC.md §6.2): ownership-verified, one transaction per matching pipeline, idempotent by `(scm event, pipeline)` |

The `pipeline` worker needs `DATABASE_URL` (ownership verification and the router); a queue only receives events published after its binding exists.

## Consumer pipeline

Per message: parse and validate (`invalid-envelope`, `unknown-type`, `invalid-payload`, `unsupported-version` go straight to the dead-letter queue) -> require `tenantId` -> **ownership verification** -> **idempotency claim** -> handler -> acknowledge.

- **Ownership verification** (`verify`, re-validated against the database before anything runs): the tenant exists and is usable (not suspended or deactivated), a `workspaceId` in the envelope belongs to the tenant, and the type-specific resource check passes (`apps/workers/src/ownership`). A mismatch is non-retryable (`tenant-not-usable`, `resource-not-in-tenant`).
- **Idempotency**: the `processed_messages` table, unique on (`tenantId`, `consumer`, `idempotencyKey`) where the key is the job's `idempotencyKey` or the `messageId`. A second delivery of a completed message is skipped; a concurrent delivery is retried later; a claim abandoned by a crashed worker is reclaimed after `WORKER_CLAIM_TTL_SECONDS`. The Redis store remains as a fallback when a worker has no database.
- **Retry tiers and DLQ** (unchanged): exchanges `qmentis.jobs`, `qmentis.retry`, `qmentis.dlx`; per queue a main queue, `retry.<n>` tiers with TTL equal to the backoff ceiling, and a `.dlq`. Transient failures are republished to the next tier; non-retryable failures and exhausted retries go to the DLQ with `x-failure-reason`.
- A consumer whose broker connection drops exits so that the supervisor restarts it; the relay does not.

## Retry classification

Automatically retry transient network, service, rate-limit and infrastructure failures with bounded exponential backoff and jitter.

Do not automatically retry invalid credentials, invalid configuration, unsupported targets or permission-denied failures without remediation.

## Cancellation and recovery

Persist cancellation requests and execution state. Support configured immediate or graceful cancellation where the operation permits it. On worker restart, recover eligible queued or interrupted work without duplicating side effects.
