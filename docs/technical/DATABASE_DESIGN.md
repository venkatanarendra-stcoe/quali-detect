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
- `pipelines` (soft delete, name unique per repository among non-deleted), `pipeline_config_versions` (immutable, consecutive numbers, enforced by triggers), `pipeline_triggers` (projection of the current version, schedule fields for the scheduler), `executions` (minimum model; only status, reason and a one-time commit SHA change after insert), `pipeline_trigger_decisions` (insert-only policy-skip rows with a source type `scm_event` | `schedule_slot` | `manual` and exactly the matching key, unique per source key by partial unique indexes).
- Every child carries `(tenant_id, workspace_id, repository_id, pipeline_id)` and a composite foreign key to `pipelines`, which in turn has composite keys to `workspaces` and `repositories` (`repositories` has unique `(tenant_id, workspace_id, id)`), so the database rejects any cross-tenant, cross-workspace or cross-repository link. All foreign keys are `ON DELETE RESTRICT`; history is never cascaded. `scm_event_id` on executions and decisions has no foreign key (scm_events retention is undecided).
- Migration `20261112120000_pipelines_triggers_executions` adds partial indexes, CHECK constraints and immutability triggers by hand; the security suite checks them (`PIPDB-001..014`).

### Findings and workflow (modeled, `findings.prisma`, migration `20261123100000_findings_core`; SPEC `docs/modules/findings/SPEC.md` 7, as built `docs/modules/findings/AS_BUILT_A0.md` 3)

**14 tables**, all with `tenant_id` NOT NULL and part of the primary key (a table with an `id` has the key `(tenant_id, id)`, so a lookup by id alone cannot be written; Prisma needs `tenantId_id`):
- `findings` (the identity and the current state: status, severity and the tool severity, assignee, pointers to the open review and exception, SLA columns, counters, `rev`), `finding_evidence` (the redacted evidence copy with its own retention), `finding_status_history` (one row per creation, status change and assignee change), `finding_reviews`, `finding_exceptions` (accepted risk and suppression), `finding_approvals` (one decision per review and per exception), `finding_assignments`, `remediation_records`, `verification_records`, `finding_comments`, `finding_ai_advisories` (the false-positive advisory, one row per input hash), `finding_sla_targets` (per-tenant overrides of the SLA hours), `finding_pipeline_state` (per-pipeline ingestion watermark and resolution markers), `finding_ingestions` (one row per execution and scan type; failed rows excluded from the uniqueness so a retry can succeed).
- The earlier candidates `finding_versions`, `finding_sla`, `finding_audit_logs`, `suppression_records` and `accepted_risk_records` were not built: versions are the history rows, the audit trail is the platform `audit_logs` (action `finding.*`), and suppression and accepted risk are the two kinds of `finding_exceptions`.

**Composite tenant keys.** Every child carries `(tenant_id, workspace_id, repository_id, pipeline_id, finding_id)` and a composite foreign key to `findings`, which carries composite keys to `pipelines`, `repositories` and `workspaces`; all `ON DELETE RESTRICT`. The database therefore refuses a row whose tenant, workspace, repository or pipeline differs from its finding (check `FNDA0-12`). There is **no foreign key** to `executions`, `scan_results`, `scan_result_items`, `scan_tasks` or `scan_tool_runs` (soft uuid references, revalidated by the worker) and none to users (plain uuids, the precedent of `execution_events.actor_user_id`; history must survive a membership change). The pointers from `findings` to the open review and exception are `DEFERRABLE INITIALLY DEFERRED` because the requests point back.

**Enums and CHECKs.** Postgres enums for status (declaration order is the shared constant), severity (critical first, which is the keyset order), scan type, kind, confidence, anchor kind and origin trust; the small vocabularies (review decision and state, exception kind and state, approval decision, remediation kind, verification outcome, ingestion status, advisory status) are `TEXT` with CHECK constraints, so adding a value is a one-line CHECK change. Credential-shaped text is refused by CHECK on the free-text columns.

**Immutable history, enforced by triggers.** UPDATE and TRUNCATE are refused on the history, approval, remediation, verification, comment, advisory and ingestion tables; DELETE only inside the four SECURITY DEFINER purge functions (`qm_findings_purge_*`, setting `qm.purge`, not scheduled yet). Guarded single advances: `finding_reviews.state`, `finding_assignments.ended_at`, the `finding_exceptions` state machine; `finding_pipeline_state` markers never decrease. On `findings`: the identifying columns are immutable, `rev` rises by exactly one on every update, the status change must be allowed by `finding_transition_allowed(from, to, actor)` (generated from the shared `FINDING_TRANSITIONS`, compared pair by pair by check `FNDA0-10`; the actor kind is the transaction setting `qm.finding_actor_type`, which **fails closed to `user`**), and a deferred constraint trigger demands a history row for every creation, status change and assignee change at commit. A recurrence or an SLA mark raises `rev` without a history row by design. A trigger on `finding_approvals` refuses an approval by any reviewer or exception requester of the same finding (the third layer of segregation of duties).

**The restricted advisory role.** The migration creates the NOLOGIN group role `qm_fp_agent` with exactly four grants: SELECT on the view `fp_agent_findings`, SELECT and INSERT on `finding_ai_advisories`, SELECT on `tenant_llm_settings`. The view **excludes secret findings** and carries no title, fingerprint, user id, rationale, comment, link or commit, and a trigger refuses an advisory row for a secret finding; `packages/db/scripts/provision-fp-agent-login.js` creates the LOGIN role. The agent can therefore never read or write finding state (checks `FNDA0-14`, `FPA-I01`). `tenant_llm_settings` gained `code_snippet_consent` (a CHECK makes it imply `external_consent`).

**Indexes.** Partial indexes for the open set (severity, SLA, assignee, pipeline and type, exception expiry); unique per tenant, pipeline and fingerprint; one pending and one approved exception per finding, one pending review per finding. Measured on 100,000 findings: list and detail inside the targets (`AS_BUILT_A1.md` 5).

### Reporting (derived and operational, `reporting.prisma`, migration `20261126100000_reporting_core`; SPEC `docs/modules/reporting-dashboards/SPEC.md` 8, as built `AS_BUILT_A0.md` 3)

Seven tables: four sparse daily rollup tables (`report_daily_findings`, `_executions`, `_decisions`, `_sbom`; tenant-local `day`, composite foreign key to `(tenant_id, workspace_id, repository_id, pipeline_id)`, `ON DELETE CASCADE`: derived data is disposable and rebuilt from the sources), `report_rollup_runs`, `report_exports` (server-built `object_key`), and `tenant_reporting_settings` (the tenant time zone, no row means `UTC`). Ten `report_*_v` views (seven in the core migration, three added by `20261126110000_reporting_views_amendment`: `report_repositories_v`, `report_pipelines_v`, `report_sla_targets_v`; as built `AS_BUILT_AM.md`) are the ONLY way the reporting roles read sources (no evidence, rationale, comment, advisory reasoning, justification or e-mail); two NOLOGIN roles, `qm_reporting` (worker: select on the views, insert and update on the report tables) and `qm_reporting_ro` (API: select only, read-only transactions, 5 s timeout), have no grant on any source table; rebuild and retention go through two `SECURITY DEFINER` functions.

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

**As built (fingerprint version 1, owner decision OD-6):** the identity is `fp1:` + the SHA-256 of the pipeline id, the scan type, the rule (or the canonical advisory id for a vulnerability), a location (the path; for a vulnerability the package without version plus the declaring manifest) and a content key (the normalized focus lines of the evidence, or empty), with an ordinal `occ` to separate identical occurrences. **Line numbers never enter it** and there is **no fuzzy matching**: a rename or move is "fixed plus new", an accepted known limitation. For a secret only the platform-masked line may enter it; the stored preview, the value length and any value-derived datum never do. A unique index on `(tenant, pipeline, fingerprint)` makes one pipeline hold one finding per identity; a `correlation_key` (never part of the identity, never equal across tenants) links the same item across pipelines for display only.

## Prisma conventions

- Centralize schema and migrations.
- Keep database queries in repository modules.
- Do not expose Prisma models directly as public API contracts.
- Map database records to response DTOs.
- Validate tenant ownership on all relationship traversals.

## Implementation status

Platform (tenants, plans, entitlements, quotas, platform users/roles, platform audit log) and identity/organization (global users with tenant memberships, groups, roles, permissions, assignments, workspaces, workspace members, sessions, audit logs) are modeled in `packages/db/prisma/schema/`; see `packages/db/README.md` for conventions (composite tenant foreign keys, `scopeKey`, CHECK constraints) and deviations. The pipelines, versions, triggers, executions and trigger-decision tables are modeled (see above); scan tasks, results, events and the findings tables are modeled too (see `packages/db/prisma/schema/` and, for the findings tables, the section above).
