# QmentisAI Database Design Principles

## Database

PostgreSQL with Prisma ORM.

## Initial database strategy

Use one PostgreSQL database initially with logical separation between platform and tenant domains. Do not create separate databases for Root Console and Tenant Application in the initial version unless a documented decision changes this.

## Main entity groups

### Platform
- tenants
- subscription_plans
- plan_versions
- tenant_subscriptions
- license_grants
- entitlement_catalog
- plan_entitlements
- tenant_entitlements
- quota_definitions
- tenant_quotas
- usage_events
- usage_ledger
- usage_aggregates
- subscription_history
- platform_audit_logs

### Identity and organization
- users
- groups
- group_members
- roles
- permissions
- role_permissions
- user_role_assignments
- group_role_assignments
- workspace_members
- sessions
- api_keys
- organizations
- workspaces

### Engineering
- repositories
- repository_integrations
- pipelines
- pipeline_triggers
- scan_configurations
- pipeline_executions
- scan_tasks
- scan_results
- execution_events

#### Pipelines and executions (modeled, `pipelines.prisma`; SPEC `docs/modules/pipelines-triggers/SPEC.md` §7)
- `pipelines` (soft delete, name unique per repository among non-deleted), `pipeline_config_versions` (immutable, consecutive numbers, enforced by triggers), `pipeline_triggers` (projection of the current version, schedule fields for the scheduler), `executions` (minimum model; only status, reason and a one-time commit SHA change after insert), `pipeline_trigger_decisions` (insert-only policy-skip rows).
- Every child carries `(tenant_id, workspace_id, repository_id, pipeline_id)` and a composite foreign key to `pipelines`, which in turn has composite keys to `workspaces` and `repositories` (`repositories` has unique `(tenant_id, workspace_id, id)`), so the database rejects any cross-tenant, cross-workspace or cross-repository link. All foreign keys are `ON DELETE RESTRICT`; history is never cascaded. `scm_event_id` on executions and decisions has no foreign key (scm_events retention is undecided).
- Migration `20261112120000_pipelines_triggers_executions` adds partial indexes, CHECK constraints and immutability triggers by hand; the security suite checks them (`PIPDB-001..014`).

### Findings and workflow
- findings
- finding_versions
- finding_evidence
- finding_comments
- finding_assignments
- finding_reviews
- finding_approvals
- finding_status_history
- finding_sla
- finding_audit_logs
- suppression_records
- accepted_risk_records
- remediation_records
- verification_records

These are logical entity candidates, not a final Prisma schema. Resolve exact cardinalities, constraints and lifecycle fields in detailed module design.

## Data modeling rules

- Use stable primary keys.
- Include created/updated timestamps where appropriate.
- Use explicit tenant ownership on tenant-owned records.
- Index tenant and parent-resource lookup paths.
- Enforce uniqueness constraints for provider identities and pipeline-scoped fingerprints where applicable.
- Use transactions for multi-step state transitions.
- Preserve immutable audit and lifecycle history.
- Avoid storing large report artifacts in hot relational tables; use object storage abstraction.

## Finding identity rule

Finding identities are independent per pipeline. A similar vulnerability in two pipelines creates two finding records. Workspace dashboards may aggregate views but must not merge identity or lifecycle state.

## Prisma conventions

- Centralize schema and migrations.
- Keep database queries in repository modules.
- Do not expose Prisma models directly as public API contracts.
- Map database records to response DTOs.
- Validate tenant ownership on all relationship traversals.

## Implementation status

Platform (tenants, plans, entitlements, quotas, platform users/roles, platform audit log) and identity/organization (global users with tenant memberships, groups, roles, permissions, assignments, workspaces, workspace members, sessions, audit logs) are modeled in `packages/db/prisma/schema/`; see `packages/db/README.md` for conventions (composite tenant foreign keys, `scopeKey`, CHECK constraints) and deviations. The pipelines, versions, triggers, executions and trigger-decision tables are modeled (see above); scan tasks, results, events and the findings tables are not modeled yet.
