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
| Exact AI coding-tool event capabilities | Provider-specific | Verify before implementing each adapter |
| ~~OpenAPI generation, middleware libraries and hardening for Express~~ | Decided by the owner with the migration (zod-to-openapi, cookie-parser, cors, pino-http, helmet, rate limit, trust proxy): see ADR-007 | Resolved |
| Reasons for replacing Fastify (ADR-007) | Not stated with the instruction | Owner to record in the ADR |

## Rule

When an open decision blocks implementation, present options, trade-offs and a recommendation. Do not silently convert an assumption into a product requirement.
