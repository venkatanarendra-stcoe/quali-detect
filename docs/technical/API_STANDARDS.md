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
