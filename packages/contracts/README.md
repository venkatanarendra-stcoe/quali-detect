# @qmentisai/contracts

Zod schemas and contracts shared by API, workers and frontends.

- `envelope.js`: event envelope and API response envelope schemas, as documented in `docs/technical/EVENT_CONTRACTS.md` and `API_STANDARDS.md`.
- `errors.js`: stable error codes (only `RESOURCE_NOT_FOUND` is documented so far).

- `job-envelope.js`: `jobEnvelopeSchema` / `createJobEnvelope` for worker messages (docs/architecture/WORKER_ARCHITECTURE.md). Note: `docs/technical/EVENT_CONTRACTS.md` describes a similar envelope with `occurredAt`/`actor`; reconcile when event contracts are specified.
- `queues.js`: `QUEUE_NAMES` (one queue per worker).

Skeleton: per-event payload schemas and request schemas arrive with their module specifications.
