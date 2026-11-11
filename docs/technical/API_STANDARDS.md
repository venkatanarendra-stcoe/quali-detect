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
