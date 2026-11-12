# QmentisAI Open Decisions Register

This document tracks decisions that must not be guessed by AI coding tools.

| Topic | Current position | Status / next action |
|---|---|---|
| Commercial plan names and pricing | Not finalized | Business decision |
| Quota values by plan | Not finalized | Business decision |
| Hard/soft quota and overage policy | Design options documented | Confirm product policy |
| SLA defaults and escalation | Configurable proposal | Confirm operational defaults |
| Risk-scoring weights | Not finalized | Security/product decision |
| Execution concurrency limits | Proposed configurable limits | Capacity decision |
| Queue timeout and missed schedule behavior | Needs final specification | Product/engineering decision |
| Scan engine vendors | Adapter architecture recommended | Select providers |
| Built-in vs external scan engines | Hybrid proposed | Confirm implementation boundary |
| AI provider/model selection | Provider-independent abstraction recommended | Select initial providers |
| Object storage provider | Abstraction required | Select implementation |
| Billing/invoicing integration | Not finalized | Commercial decision |
| SSO providers and protocols | Requirements include SSO | Confirm supported protocols |
| Data retention periods | Not finalized | Compliance/business decision |
| Retention window after which a deactivated tenant becomes terminal (AUTHORIZATION Q25) | Implemented as `TENANT_DEACTIVATION_RETENTION_SECONDS` with a **provisional placeholder of 30 days**; the owner has not set the real value. Data handling at expiry (purge, crypto-shredding) stays Open; no purge job exists | Set the value with the Compliance decision |
| Final progressive-throttling values (AUTHORIZATION Q24, ADR-010) | Defaults implemented and configurable (`AUTH_THROTTLE_*`); the owner has not set final values | Keep the ADR-010 defaults until decided |
| Delivery of the throttle-cap notification to the account owner (e-mail); administrative reset of a throttled account | The event reaches the notification worker through the outbox, which only logs it; no delivery channel and no reset action | Deliver through the outbox when it exists; add a reset to the support tooling later |
| Real plans, prices and quota values (the seed ships one placeholder plan: workspaces 25, users 100, scans 100 per month); whether a tenant provisioned without a plan should get a default | Placeholders in the seed; configurable through plan data | Decide with the commercial model; keep fail-closed for tenants without a subscription |
| Retention of sent `outbox_messages` and completed `processed_messages` rows (purge helpers exist, nothing schedules them); tooling to inspect and replay dead-letter queues and dead outbox rows | Not decided; the tables grow until a purge job exists | Purge sent/done rows older than a retention period decided with the Compliance decision; an operator command for requeueing dead rows |
| Outbox relay wake-up | Polling every `OUTBOX_POLL_INTERVAL_MS` (default 1 s) vs PostgreSQL LISTEN/NOTIFY | Keep polling until latency matters |
| Credential storage details (ADR-009 *Open* table) | KMS vs Vault adapter, resolve auditing, crypto-shredding, **the DEK/master-key re-encryption job (deferred on purpose)** | See ADR-009 |
| Exact AI coding-tool event capabilities | Provider-specific | Verify before implementing each adapter |
| ~~OpenAPI generation, middleware libraries and hardening for Express~~ | Decided by the owner with the migration (zod-to-openapi, cookie-parser, cors, pino-http, helmet, rate limit, trust proxy): see ADR-007 | Resolved |
| Reasons for replacing Fastify (ADR-007) | Not stated with the instruction | Owner to record in the ADR |
| ~~Manager visibility of Workspace Integrations (wireframe §4.4 vs Admin-only `integration.view`)~~ | Decided by the owner 2026-11-11: workspace-scope `workspace_integration.view` (Admin, Manager, Lead, Dev Lead) and `.manage` (Admin, Manager), routing only; organization connect/disconnect stays `integration.manage` (AUTHORIZATION Q26) | Resolved |
| Repositories + GitHub: remaining Open after the module close (2026-11-12; SPEC §15, §17.7, §18.4) | **Open:** repository transfer behavior against real GitHub (Q22; needs a second account); non-admin organization-member rejection against real GitHub (needs a second account; stub-covered by SCM-013/030); GHES, GitLab and Bitbucket (Q20); cross-workspace repository sharing (Q26); temporary pause of a workspace link (Q27); notification persistence and delivery channel (log-only today); also still open and smaller: workspace-admin visibility of installation delivery history (Q29), per-tenant fairness on the shared `scm-events` consumer (Q23), `GET /repositories/{id}` for lighter sync (Q24), redelivery from the GitHub UI (not performed). **Closed:** Q25 (REST redelivery keeps the GUID), rename half of Q22/D6 (ids survive a rename), restore rule (§18.7), Q28 (tenant setting). **Deferred work, not decisions (SPEC §16.3):** revoked/suspended status with date and reason everywhere; prompt reconciliation on installation-repository changes; live verification of "Use an existing installation" | Owner to decide / verify with a second account |

## Rule

When an open decision blocks implementation, present options, trade-offs and a recommendation. Do not silently convert an assumption into a product requirement.
