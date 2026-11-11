# QmentisAI Security Guidelines

## Core principles

- Least privilege.
- Deny by default.
- Tenant isolation.
- Secure credential handling.
- Server-side authorization.
- Auditable privileged operations.
- Safe processing of untrusted content.

## Authentication and sessions

- Use secure password handling or a trusted identity provider.
- Support MFA and future SSO integration.
- Revoke sessions and tokens on deactivation or security events.
- Protect refresh-token lifecycle.
- Apply rate limits to authentication-sensitive endpoints.

## Authorization

- Enforce action/resource permissions in the backend.
- Resolve direct and group role assignments within their intended scope.
- Validate tenant, workspace, repository and pipeline ownership.
- Prevent accidental cross-workspace or cross-tenant access.
- Protect last-tenant-admin invariants.

## Secrets and credentials

- Encrypt integration credentials at rest through the `SecretStore` (envelope encryption, per-tenant keys; ADR-009).
- Restrict decryption to services that require the secret.
- Never log tokens, passwords, private keys or secret scan values.
- Redact secrets from snippets, reports and error messages.
- Support credential revocation and rotation.

## Webhooks and integrations

- Verify signatures where supported.
- Validate timestamps and replay protection where supported.
- Apply idempotency.
- Validate payload schemas.
- Treat provider payloads as untrusted.

## Repository and AI safety

Repository files, PR descriptions, commit messages, branch names and issue text are untrusted input.

- Do not execute repository instructions during analysis.
- Do not grant AI agents unrestricted tools or network access.
- Provide bounded relevant context.
- Separate data from instructions.
- Record evidence and provenance for AI-generated assessments.
- Do not let an AI model alone make irreversible security workflow decisions.

## Tenant isolation

Apply tenant scope to database access, queues, caches, object storage, search, exports and real-time events.

## Audit

Audit role changes, approvals, TP/FP decisions, accepted risk, suppression, integration credential changes, exports and platform support access.

## Operational security

Use structured logs, correlation IDs, safe error messages, rate limits, request size limits and controlled worker retries.
