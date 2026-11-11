# QmentisAI Project Context

## Product summary

QmentisAI is an AI-Native Security Engineering Workflow platform. It connects source repositories, development workflows, security scanning, finding intelligence, human security review, approvals and developer remediation in a tenant-aware platform.

It is a security engineering workflow product, not a general-purpose chatbot.

## Applications

### Root Console

Platform administration, including:
- Tenant provisioning and lifecycle.
- Plans, subscriptions, licenses and entitlements.
- Feature availability and quotas.
- Platform administrators and support users.
- Global integration catalog and feature flags.
- Platform monitoring, usage and audit.
- Authorized support diagnostics.

### Tenant Application

Tenant security engineering workflows, including:
- Workspaces, repositories and pipelines.
- Source-control and AI coding-tool integrations.
- Pipeline execution and scan history.
- SCA, SBOM, SAST and Secret Scanning.
- Manual DAST and Asset Discovery.
- Findings, evidence, reviews, approvals and remediation.
- Policies, dashboards, reports, notifications and audit.

## Tenant hierarchy

Tenant / Organization
  -> Workspaces
    -> Repositories
      -> Pipelines
        -> Executions
          -> Scan tasks and results
          -> Pipeline-specific findings

A repository may have multiple pipelines. Each pipeline has independent triggers, scan configuration, execution history and finding identity.

## Primary users and roles

Built-in tenant roles:
- Admin
- Manager
- Lead
- Security Analyst
- Dev Lead
- Developer
- Guest / Viewer

Platform Super Admin is managed in Root Console, not as an ordinary tenant role.

Authorization uses built-in roles, tenant-defined custom roles and workspace-specific assignments. Group membership alone does not grant permissions; role assignments to groups do.

## Source-control and development integrations

Source control:
- GitHub
- GitLab
- Bitbucket

AI coding tools under consideration:
- Cursor
- Claude Code
- Codex
- Kiro

Other proposed integrations include Jira, Linear, Confluence, Slack, Microsoft Teams, security scanners, cloud providers and secrets managers. Provider capabilities and delivery mechanisms must be verified per adapter; do not assume all providers expose identical webhooks or hooks.

## Initial scan scope

Automated:
- SCA
- SBOM
- SAST
- Secret Scanning

Manual only in the initial scope:
- DAST
- Asset Discovery

A hybrid built-in and external scan-engine model is a recommended architecture direction, not a fully finalized product decision.

## Core workflow

1. Tenant configures workspace, repository, pipeline and integrations.
2. A webhook, manual request or schedule creates a normalized event.
3. Event routing matches pipeline trigger rules.
4. Repository analysis prepares bounded change and dependency context.
5. Scan decisioning determines applicable scan work.
6. Scan engines execute.
7. Findings are normalized, correlated and validated.
8. Security Team reviews findings and records TP/FP decisions.
9. Security Lead approves or rejects decisions.
10. Approved true positives are assigned to developers.
11. Developers remediate.
12. A later scan verifies remediation and updates finding lifecycle.

## Product principles

- Tenant isolation is mandatory at every data and processing boundary.
- Pipeline finding identities remain independent.
- AI output is advisory evidence; human decisions remain explicit workflow events.
- No finding is marked fixed merely because it is absent from an incomplete or incremental scan.
- Security-sensitive actions are authorized and audited server-side.
- Integrations and scan engines must be extensible.
