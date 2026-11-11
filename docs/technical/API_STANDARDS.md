# QmentisAI API Standards

## Route convention

Use versioned REST endpoints under `/api/v1`.

Tenant examples:
- `/api/v1/workspaces`
- `/api/v1/repositories`
- `/api/v1/pipelines`
- `/api/v1/executions`
- `/api/v1/scans`
- `/api/v1/findings`
- `/api/v1/security-reviews`
- `/api/v1/approvals`
- `/api/v1/remediation`
- `/api/v1/integrations`
- `/api/v1/policies`

Platform examples:
- `/api/v1/platform/tenants`
- `/api/v1/platform/plans`
- `/api/v1/platform/subscriptions`
- `/api/v1/platform/licenses`
- `/api/v1/platform/entitlements`
- `/api/v1/platform/usage`

## Request rules

- Validate params, query and body with Zod.
- Authenticate before protected operations.
- Establish trusted tenant context.
- Authorize the action and resource.
- Check entitlement/quota for metered operations.
- Apply pagination to collection endpoints.
- Define filtering and sorting explicitly.
- Use idempotency keys for operations where duplicate submission could cause side effects.

## Response convention

Success example:

```json
{
  "success": true,
  "data": {
    "id": "resource-id"
  },
  "meta": {
    "correlationId": "correlation-id"
  }
}
```

Error example:

```json
{
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found."
  },
  "meta": {
    "correlationId": "correlation-id"
  }
}
```

## Error rules

Use stable machine-readable error codes. Do not expose stack traces, SQL details, provider secrets or internal implementation details.

## Documentation

Maintain OpenAPI documentation alongside route schemas. Document authentication, permissions, request validation, response structures and error cases.

## Contract baseline and transport independence

The API contract is independent of the HTTP framework (ADR-007). The Fastify-era contract is frozen in `docs/api/` as the reference; `pnpm contract:snapshot` writes the Express twins (`openapi-express.json`, `contract-express.*`) and `pnpm contract:parity` diffs them (`parity-report.md`):

- `openapi-fastify-baseline.json`: the OpenAPI document exactly as served.
- `contract-fastify-baseline.json` and `.md`: one record per operation (method, path, audience, permission and its scope, success status, documented error statuses, **transport** error codes (exact) and **domain** error codes (a per-module superset), response envelope and `data` shape).
- Regenerate with `pnpm contract:snapshot`; the script fails if an OpenAPI operation cannot be matched to a route source. A contract change is reviewed as a diff of these files.

Rules the Express migration must preserve:

- Same paths under `/api/v1` (platform under `/api/v1/platform`), statuses, envelopes, cookie names/paths/flags and stable error codes.
- **Authentication precedes validation (ADR-007, changed from the Fastify era):** an unauthenticated caller gets `401` regardless of input, and an unusable tenant `403`, before input is validated; invalid input then answers `400 VALIDATION_FAILED` before authorization (`403`/`404`) is decided. Public routes (login) validate first. Changing this order needs an ADR.
- A route without a declared audience must refuse to register; platform routes only under `/api/v1/platform/`.
- A workspace the caller cannot see answers `404` with a body identical to a missing one; a visible resource without permission answers `403` (see `docs/AUTHORIZATION.md` §5.9). `pnpm test:security` (ADR-008) enforces this.

Known gap against the request rules above: `Idempotency-Key` is not implemented yet (duplicates rely on unique constraints and return `409`).

## HTTP edge (Express 5, 2026-11-11)

- **Headers and CORS:** `helmet` on every response. CORS only for the configured origins (`CORS_ALLOWED_ORIGINS`: the tenant-web and Root Console origins, exact `scheme://host[:port]`, no wildcard, validated at startup); credentials are allowed only for those origins. A request from another origin gets no CORS headers, and an unsafe request carrying an unknown `Origin` is refused with `403` (CSRF check).
- **Proxy and bodies:** `TRUST_PROXY` (default off; a hop count or addresses, never `true`). `REQUEST_BODY_LIMIT_BYTES` (413). A request body must be `application/json`; anything else is `415 UNSUPPORTED_MEDIA_TYPE`.
- **Rate limits (Redis-backed, `RATE_LIMIT_*`):** a global per-IP limit, plus per-route profiles with their own counter per route: `auth` (public sign-in endpoints, per IP, strict), `write` (authenticated create/side-effect endpoints, per tenant + user), `webhook` (per IP, ready for provider webhooks). A refusal is `429 RATE_LIMITED` with `RateLimit` and `Retry-After` headers. Sign-in endpoints also have the progressive per-account throttle (ADR-010).
- **Idempotency-Key:** optional header on POST endpoints that create resources or trigger side effects. Keys are scoped by tenant + user + route and stored in Redis for `IDEMPOTENCY_TTL_SECONDS` (default 24 h). Same key and same request: the stored 2xx response is replayed (`Idempotent-Replayed: true`). Same key with a different request, or while the first is still running: `409 IDEMPOTENCY_CONFLICT` (`details.reason`: `different_request` or `in_progress`). Failed requests are not stored.
