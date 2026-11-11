# QmentisAI Implementation Plan

## Guiding approach

Build foundational capabilities before implementing the full product modules. Work in vertical slices and preserve agreed architecture.

## Phase 1 — Repository foundation

- Create pnpm monorepo.
- Configure Turborepo.
- Establish JavaScript ES Module conventions.
- Configure ESLint and Prettier.
- Create shared package skeletons.
- Add project documentation.

## Phase 2 — Backend foundation

- Backend application bootstrap (built on Fastify; transport replaced by Express 5 per ADR-007, migration pending).
- Configuration validation.
- Centralized logging and error handling.
- Prisma and PostgreSQL connection.
- Redis abstraction.
- RabbitMQ abstraction.
- API versioning and OpenAPI.
- Shared event and validation contracts.

## Phase 3 — Identity and tenant foundations

- Authentication and sessions.
- Tenant context.
- Users and groups.
- Roles and permissions.
- Workspace membership.
- Authorization policies.
- Audit logging.
- Subscription and entitlement checks.

## Phase 4 — Frontend foundations

- Tenant React/Vite application.
- Root Console React/Vite application.
- Tailwind CSS and shadcn/ui.
- Shared design tokens.
- Routing, layouts and navigation.
- Authentication integration.
- API client and permission-aware UI.

## Phase 5 — Organization and engineering

- Tenant and workspace management.
- Repository connections.
- Pipeline configuration.
- Trigger management.
- Execution records and controls.
- Worker orchestration.

## Phase 6 — Analysis and scanning

- Repository context.
- Incremental/full analysis rules.
- Dependency context.
- Scan engine registry.
- SCA, SBOM, SAST and Secret Scanning.
- Manual DAST and Asset Discovery workflows.

## Phase 7 — Findings and security workflow

- Pipeline-scoped finding identity.
- Fingerprinting and recurrence.
- Evidence and risk assessment.
- Review and TP/FP decisions.
- Lead approvals.
- Developer assignment and remediation.
- Verification and lifecycle updates.

## Phase 8 — Governance and platform capabilities

- Policies.
- Reports and dashboards.
- Notifications.
- Integrations expansion.
- Subscription, entitlements and quotas.
- Usage metering.
- Platform monitoring and support.

## Scope note

This is a recommended sequence, not a commitment to implement every listed capability in one release. Commercial values, quotas, risk weights, SLA values and concurrency limits remain configurable/open until approved.
