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

## Scan sandbox (`src/sandbox`)

Scan-layer container abstraction (docs/modules/scan-engines/SPEC.md part A, ADR-014; the only place a container runtime is reached). Not wired into the scan worker yet.

- `SandboxRuntime` interface (`run`, `kill`, `remove`, `health`, `listByLabel`); drivers `createCliSandboxRuntime` (a Docker-compatible CLI, `docker` or `podman` by configuration, through `execFile` with no shell; it never mounts or requires the runtime socket and does not assume a rootful runtime) and `FakeSandboxRuntime` (tests).
- `RunSpec` + `validateRunSpec` (no field can weaken the sandbox; the image is `repository@sha256:<digest>` only), pure `buildRunArgs` and the independent audit `findRunArgsProblems` / `assertRunArgsSafe`, `createJanitor` (orphans by label), `createSandboxRunner` (kill then remove for a whole attempt), `createCapacityGate`.
- `validateSandboxConfig` (fail fast). UNVERIFIED: that a real runtime applies the generated flags, rootless operation and uid mapping (ENG-L01, ENG-L18).
