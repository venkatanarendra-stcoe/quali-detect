# Product Requirements Overview

## 1. Product goals

QmentisAI should provide a unified security engineering workflow connecting code changes, security scans, findings, review decisions, approvals and remediation.

## 2. Product boundaries

### In scope
- Multi-tenant platform with Root Console and Tenant Application.
- Tenant/workspace/repository/pipeline hierarchy.
- Source-control integrations.
- AI coding-tool integration framework.
- Automated SCA, SBOM, SAST and Secret Scanning.
- Manual DAST and Asset Discovery.
- Pipeline execution orchestration.
- Pipeline-specific finding identity and lifecycle.
- Human review, lead approval and developer remediation.
- Subscription entitlements, quotas and usage controls.
- Dashboards, reports, notifications and audit.

### Not assumed as finalized
- Commercial plan names, prices and quota values.
- Risk-scoring weights.
- Exact SLA defaults.
- Exact concurrency limits.
- Final scan-engine vendors.
- Complete list of AI coding-tool event capabilities.
- Final billing/invoicing provider.
- Deployment topology.

## 3. Functional areas

| Area | Capabilities |
|---|---|
| Identity | Authentication, users, groups, roles, permissions, sessions, MFA/SSO |
| Organization | Tenant, workspace and membership management |
| Repositories | Provider connections, repository metadata, branches, commits, PRs, webhooks |
| Pipelines | Configuration, triggers, scan selection, execution controls, history |
| Scanning | Scan templates, engines, progress, logs, results, exports |
| Findings | Fingerprints, evidence, risk, status, recurrence, suppression, accepted risk |
| Security workflow | Review, TP/FP decisions, approvals, assignments, remediation, verification |
| Integrations | Source control, AI coding tools, ticketing, collaboration, security tools |
| Governance | Policies, audit, data governance |
| Reporting | Dashboards, analytics, exports |
| Communication | In-app/email and optional external notifications |
| Platform | Tenants, plans, subscriptions, licenses, entitlements, quotas, usage |

## 4. Non-functional requirements

- Strong tenant isolation.
- Backend-enforced authorization.
- Secure credential handling and redaction.
- Idempotent webhook and job processing.
- Durable execution state.
- Retry and recovery for transient failures.
- Observability through structured logs, metrics and traces.
- Extensible integration and scan-engine contracts.
- Data retention, export and deletion controls.
- Secure handling of untrusted repository and webhook content.

## 5. Requirement status

Each detailed requirement must be labeled:
- Confirmed
- Recommended
- Open
- Deferred

Do not convert a recommendation into a confirmed requirement without an explicit decision.
