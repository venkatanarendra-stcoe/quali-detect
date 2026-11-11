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
| Notification to the account owner when the throttle cap is reached; administrative reset of a throttled account | Event emitted as a log only (no outbox); no reset action | Deliver through the outbox when it exists; add a reset to the support tooling later |
| Credential storage details (ADR-009 *Open* table) | KMS vs Vault adapter, resolve auditing, DEK rotation schedule, crypto-shredding | See ADR-009 |
| Exact AI coding-tool event capabilities | Provider-specific | Verify before implementing each adapter |
| ~~OpenAPI generation, middleware libraries and hardening for Express~~ | Decided by the owner with the migration (zod-to-openapi, cookie-parser, cors, pino-http, helmet, rate limit, trust proxy): see ADR-007 | Resolved |
| Reasons for replacing Fastify (ADR-007) | Not stated with the instruction | Owner to record in the ADR |

## Rule

When an open decision blocks implementation, present options, trade-offs and a recommendation. Do not silently convert an assumption into a product requirement.
