# @qmentisai/workers

Independent worker processes (ADR-002): `pipeline`, `analysis`, `scan`, `notification`, `usage`, `scheduler`. Specs: `docs/architecture/WORKER_ARCHITECTURE.md`.

```bash
pnpm --filter @qmentisai/workers start:pipeline   # or dev:pipeline (watch); one process per worker
```

Each worker (`src/<worker>/index.js`, entry `main.js`) calls `runWorker`, which: validates env (`src/config.js`, fail fast), connects Redis and RabbitMQ, starts a consumer from `@qmentisai/infra` on its queue (`QUEUE_NAMES` in `@qmentisai/contracts`) with the **no-op handler** (`src/handlers/noop.js`), and shuts down gracefully on SIGINT/SIGTERM (stop consuming, finish in-flight jobs up to `WORKER_SHUTDOWN_TIMEOUT_MS`, close connections; a second signal exits at once). A lost broker connection exits the process so a supervisor can restart it.

Message handling rules: messages are validated with the job envelope; failures are classified (transient -> retried with exponential backoff and jitter, up to `WORKER_MAX_ATTEMPTS`; non-retryable -> dead-letter queue `qmentis.<queue>.dlq`); delivery is at-least-once with an idempotency claim per `idempotencyKey ?? messageId`. Handlers must verify that referenced resources belong to `envelope.tenantId` (a tenant id in a message is not authority).
