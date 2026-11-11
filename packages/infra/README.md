# @qmentisai/infra

Server-only infrastructure abstractions shared by `apps/api` and `apps/workers` (kept out of `@qmentisai/shared`, which the browser apps import). Added in Phase 2 part 2; it was not in the Phase 1 package list.

## Redis (`src/redis`)

- `createRedisClient`, `pingRedis`, `closeRedis`.
- `createCache`: tenant-scoped JSON cache. Every call takes `{ tenantId, namespace, id }`; the key comes from `@qmentisai/shared` `buildCacheKey`, which throws without a valid `tenantId`. TTL is mandatory (default 300 s). `invalidateNamespace` only touches one tenant's namespace.
- `createLockManager`: `acquire`/`withLock` (tenant), `acquirePlatform`; owner-token lease on one Redis (not Redlock).
- `createRateLimiter`: atomic fixed window; `consume` (tenant) and `consumeGlobal` (pre-authentication). Subjects are hashed.

## RabbitMQ (`src/rabbitmq`)

- `createRabbitConnection` (bounded connect retries, reconnect on demand), `createPublisher`, `createConsumer`, `createRedisIdempotencyStore`.
- Messages use `jobEnvelopeSchema` from `@qmentisai/contracts`; invalid messages are never published or processed.
- Retry: `classifyError` (transient vs non-retryable; unknown = non-retryable by default), `computeBackoffDelay` (exponential, capped, equal/full jitter). Retries go through per-attempt TTL queues; terminal failures go to `qmentis.<queue>.dlq` with `x-failure-reason`. Topology is documented in `topology.js`.
- Idempotency: `idempotencyKey ?? messageId`, tenant-scoped; at-least-once delivery, so handlers must still be idempotent.

Never log connection URLs; they can contain credentials. The key builders live in `packages/shared/src/keys.js`.
