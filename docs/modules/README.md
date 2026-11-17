# Module Specifications

Create one folder per business module. Use `../technical/MODULE_SPECIFICATION_TEMPLATE.md` as the starting point.

Suggested module specification order:

1. Identity and authentication.
2. Tenant and workspace management.
3. Roles, permissions and groups.
4. Subscription and entitlements.
5. Repository integrations.
6. Pipeline configuration and triggers.
7. Pipeline execution and concurrency.
8. Repository and dependency analysis.
9. Scan orchestration and engine adapters.
10. Finding intelligence and lifecycle.
11. Security review and approvals.
12. Remediation and verification.
13. Policies and governance.
14. Notifications and comments.
15. Dashboards and reporting.
16. Root Console administration.

Specifications written so far (folders in this directory): `access-management`, `repositories-github`, `pipelines-triggers`, `user-preferences` (per-user interface preferences such as the accent colour; not part of the order above), `executions` (items 7 and 9 of the order above: pipeline execution lifecycle and scan orchestration, with T-28 and T-29 and the pipeline Executions tab; **Approved, 2026-11-16**, nothing implemented; T-30 manual DAST/Asset Discovery scans are out of it and belong to a separate manual-scan module later).

`scan-decisioning` (the Analysis and Scan Decisioning stage, workflow steps 4 and 5, inserted into the Executions `preparing` state; deterministic floor plus an optional LLM agent that can only add scans; with `SCREENS.md` for the T-29 section; **Approved 2026-11-17**, implementation in parts A to G; the LLM layer is ADR-013, Approved).

Do not create empty specifications for every module in advance. Complete each specification before implementing that module.
