# ADR-013: LLM provider abstraction (LLMProvider, adapters, framework choice)

- **Status:** **Accepted, as built (2026-11-18)**; approved 2026-11-17 by the product owner. Live-verified on 2026-11-18: only the local Ollama adapter (`gpt-oss:20b`, through a counting proxy) and `LLM_PROVIDER=none`; the stand-in addition path is in scan-decisioning SPEC 17.i. **The real-vendor adapters (Anthropic, OpenAI) are NOT verified live** (LT-11 deferred; their tool-result format is an open pre-production item in `docs/decisions/OPEN_DECISIONS.md`), and no real model has yet made an addition on its own. Original status line follows.
- **Approved:** (2026-11-17, product owner). The choices are recorded in "Decisions (owner, 2026-11-17)" below. Part B (the `LLMProvider` layer, the three adapters, the deployment configuration, the platform-secret names and the consent gate) and part D (the harness, section 3) are implemented (see "As built, part B" and "As built, part D" below).
- **Date:** 2026-11-17
- **Decision owners:** Product owner (decision); Claude Code (proposal)
- **Relation to existing documents:** the open item "AI provider/model selection: provider-independent abstraction recommended" in `docs/decisions/OPEN_DECISIONS.md`; ADR-001 (JavaScript only), ADR-002 (modular monolith and separate workers), ADR-009 (SecretStore and PlatformSecretProvider), ADR-011 (envelopes); `docs/technical/SECURITY_GUIDELINES.md` "Repository and AI safety".

## Context

Two features need a language model: the scan **decision agent** (`docs/modules/scan-decisioning/SPEC.md`: adds scan types to a deterministic floor) and, later, the **false-positive / advisory agent** of the Findings module. Both are optional enhancements that must work with **no model at all**, both read **bounded, untrusted** repository-derived data, and both must run against whatever the customer allows: a local model (Ollama) for data that must not leave the deployment, or a hosted provider (Anthropic, OpenAI). We need one provider-independent layer so the callers do not depend on any vendor, secrets are handled once and correctly, and the agent harness (bounded tool-calling loop, validation, timeouts) is written once.

The stack rules apply: JavaScript ES Modules only, no separate service language, Zod at boundaries, pinned and justified dependencies, secrets only through the secret store, no secret in a log, message or URL.

## Decision (proposed)

### 1. An `LLMProvider` interface in `packages/infra` (server-only)

```js
/**
 * @typedef {{ id: "ollama" | "anthropic" | "openai", model: string }} LLMProviderInfo
 * @typedef {{ name: string, description: string, inputSchema: object }} LLMTool        // JSON Schema for the tool input
 * @typedef {{ role: "user" | "assistant", content: string }} LLMMessage
 * @typedef {{ name: string, input: unknown }} LLMToolCall
 * @typedef {{ text: string, toolCalls: LLMToolCall[], stopReason: string,
 *             usage: { inputTokens: number, outputTokens: number } }} LLMResult
 * @typedef {{ info: LLMProviderInfo,
 *             complete(request: { system: string, messages: LLMMessage[], tools?: LLMTool[],
 *                                 maxOutputTokens: number, temperature?: number, signal: AbortSignal }): Promise<LLMResult> }} LLMProvider
 */
```

- **One non-streaming call shape** (system prompt, messages, tools, bounded output). Provider differences (Anthropic tool use, OpenAI function/tool calls, Ollama chat tools) live **inside the adapters**; callers see `toolCalls` only. A tool result turn is a `user` message of a documented shape so the loop is provider-neutral.
- The caller owns the `AbortSignal` (timeout and cancel). An adapter never retries on its own beyond one bounded retry for a transport reset; the harness decides.
- `resolveLLMProvider({ purpose, tenantId })` returns a provider or **`null`**. **A provider may be absent**: `null` is a normal, supported result and callers must continue without a model.
- Adapters: `ollama` (local HTTP API), `anthropic` (Messages API), `openai` (chat completions with tools). Adding another vendor is a new adapter file plus a registry entry; no caller change.
- Output of the adapter is **never trusted**: callers validate with Zod (the decision agent's schema is in its SPEC).

### 2. Configuration and secrets (the consent row is decided, see Decisions above)

| Level | Where | Contents |
|---|---|---|
| Deployment (v1) | environment, validated by Zod at startup | `LLM_PROVIDER` (`none` default, `ollama`, `anthropic`, `openai`), `LLM_MODEL`, `LLM_OLLAMA_BASE_URL`, timeouts and concurrency caps. **No default model name is baked in code.** |
| Provider API keys | `PlatformSecretProvider` names `llm.anthropic.api_key`, `llm.openai.api_key` (ADR-009 section on platform secrets); never in the database in v1 | read at call time, never cached in logs or errors |
| Tenant provider or key (**Open**, later) | tenant settings plus the tenant `SecretStore` | a tenant-chosen provider, model or key; not in v1 |
| Data-egress consent (**decided**) | table `tenant_llm_settings` (`external_consent`, audited) | an external provider (Anthropic, OpenAI) is used for a tenant only if the deployment configures it and the tenant consented that repository-derived metadata (file paths, never contents) is sent; a local Ollama needs none |

Rules: keys are never logged (the existing redaction paths cover the field names), never in a message, event, DTO or error text, never in a URL; the Ollama base URL is deployment configuration, **never tenant-supplied in v1** (SSRF); outbound calls go only to the configured host over TLS for hosted providers; a startup check refuses a hosted provider without its key, and `LLM_PROVIDER=none` or an unresolvable provider means "absent".

### 3. The agent harness (shared by both features)

A small module `packages/infra/src/llm/harness.js` (Recommended): a bounded loop with at most N provider calls, an overall timeout, bounded output tokens, a fixed system prompt that states that the user data is **data**, only the tools the caller offers, strict Zod validation of the final output, and a typed result `{ status, value?, usage, provider }` where `status` is one of `ok`, `timeout`, `error`, `invalid_output`, `aborted`. It never throws for a model failure; callers map the status to their fallback. No tool is ever given file, network or shell access by the harness.

### 4. Framework approach (**the owner's decision**)

| Option | What it is | For | Against |
|---|---|---|---|
| **A. In-house bounded loop over `LLMProvider` (Recommended)** | about a few hundred lines in `packages/infra/src/llm`: interface, three `fetch`-based adapters (no vendor SDK), the harness | the decision agent is one tool and at most three turns; no new framework dependency or churn; full control of egress, timeouts, redaction and secrets; easy to test with a stub provider; fits ADR-001/002; the Findings agent can reuse it | we maintain three small request/response mappers and must follow vendor API changes; no ready-made graph or memory features (not needed now) |
| B. `langgraphjs` (LangGraph for JavaScript) in the same process | graph/state-machine orchestration with checkpointing | useful if agents become multi-step with branching, human-in-the-loop and durable state | a large dependency tree (LangChain core and provider packages), fast-moving APIs, more supply-chain surface for a one-tool loop; its checkpointing would duplicate our execution/lease persistence; the agent would be harder to bound and to audit |
| C. Vercel AI SDK (`ai` and provider packages) | JS provider abstraction and tool loop | ready adapters and tool calling | a dependency set per provider; its abstractions still need our bounds, redaction and secret handling; version churn |
| D. A separate Python service (for example LangGraph in Python) | out-of-process agent service | rich ecosystem | **Rejected**: violates ADR-001 (JavaScript only) and ADR-002 (no new deployable), adds a network hop, a second runtime and a second place where secrets and tenant context must be enforced |

**Decided: A for v1 (owner, 2026-11-17).** Re-evaluate B or C only if the Findings agent becomes genuinely multi-step with durable state and branching; the `LLMProvider` interface is the seam that would let them be adopted behind it without touching callers. **NO separate Python service in any case.**

Dependency note if A is chosen: **no new dependency** (Node's `fetch`, existing Zod). If C or official vendor SDKs are chosen instead, each package is pinned and justified in the PR as `docs/technical/CODING_STANDARDS.md` requires.

### 5. Usage and cost

Each call returns token usage; the caller stores it in its own record (the decision record has `agent_usage`). A platform-level **concurrency cap** and per-call limits are settings. Usage metering to the usage worker and any quota for model calls are **Open** (commercial plan decisions).

## Decisions (owner, 2026-11-17)

1. **Framework: option A.** An in-house bounded tool-calling loop over `LLMProvider` with `fetch`-based adapters. **No new dependency**: no langgraphjs, no Vercel AI SDK, no vendor SDK, and no Python service.
2. **Providers:** the interface with adapters for local **Ollama**, **Anthropic** and **OpenAI**.
3. **Configuration:** deployment-level provider in v1 (`LLM_PROVIDER`, `LLM_MODEL`, `LLM_OLLAMA_BASE_URL`); keys through the platform secret provider (`llm.anthropic.api_key`, `llm.openai.api_key`) and, for any future tenant key, the tenant SecretStore; never logged. No default model name in code.
4. **Data-egress consent (decided):** an external provider (Anthropic, OpenAI) is **disabled for a tenant until an explicit, audited tenant consent setting is on**. A local Ollama is allowed by default. Without consent the caller runs without a model (floor-only for scan decisioning). The consent is stored in `tenant_llm_settings` (SPEC scan-decisioning 7.2a), changed through an audited route, and **enforced inside `resolveLLMProvider({ purpose, tenantId })`**, which returns `null` for an external provider without consent, so no caller can bypass it. A security-suite check (`DEC-S10`) proves an external provider is never called without consent.
5. **Bounds for the first caller:** 20 s and 3 turns (scan decisioning).

## As built, part B (2026-11-17)

Implemented in `packages/infra/src/llm/` (server-only, exported from `@qmentisai/infra`); details and what is not verified are in `docs/modules/scan-decisioning/SPEC.md` section 17.b.

- **Return shape of `resolveLLMProvider` (refines section 1 and decision 4).** The text above says the function "returns `null`". As built it returns `{ provider, status }`, a `Promise<{ provider: LLMProvider | null, status: "ok" | "not_configured" | "consent_required" | "key_missing" }>`, so a caller can record WHY there is no model (agent status `not_configured` or `consent_required`) without a second lookup. `provider === null` is still the only "no model" signal. The call is `resolveLLMProvider({ purpose, tenantId, config, secrets, consent, fetchImpl?, logger? })`: `consent.isExternalAllowed(tenantId)` is injected (backed by `tenant_llm_settings`, loaded by tenant id only) and is called INSIDE the function before any adapter exists; an external provider is also re-checked immediately before every request, so a consent turned off while a provider object is held, or while a call waits for a concurrency slot, still stops the request.
- **Errors.** `LLMError` with the codes `timeout`, `aborted`, `transport`, `http_status`, `invalid_response`, `not_configured`; it never carries headers, keys, prompts or response bodies.
- **Configuration reader.** `readLLMConfig(env, { production })` uses plain validation (like `readGitHubAppConfig`) because `packages/infra` has no Zod dependency and ADR-013 allows no new dependency; Zod stays at the API boundaries. Problems name the variable and the rule, never a value. The API validates the variables at startup through it; the workers will in the part that wires the agent.
- **Keys.** Platform secret names `llm.anthropic.api_key` and `llm.openai.api_key` (environment variables `LLM_ANTHROPIC_API_KEY`, `LLM_OPENAI_API_KEY`, or the `_FILE` variants, development only); a missing key resolves to `key_missing`. The startup check for a worker that will call a provider is the exported `missingLLMKeyProblems`; the API does not call the model and does not need a key.
- **Tool results** go back as one `user` message built by `toolResultMessage(name, output)`.
- **Concurrency cap.** A per-process semaphore (`LLM_MAX_CONCURRENT_CALLS`) wraps `complete`; waiting honours the caller's `AbortSignal`.
- **Harness (section 3).** Not part of part B; built in part D (below).

## As built, part D (2026-11-17)

`packages/infra/src/llm/harness.js` exports `runBoundedToolLoop`; details in `docs/modules/scan-decisioning/SPEC.md` section 17.d. It matches section 3 with these deviations and refinements:

- **Validation is a callback, not Zod.** Section 3 says "strict Zod validation of the final output". `packages/infra` has no Zod dependency and none is added, so the harness takes `validate({ toolCalls, text }) => { ok: true, value } | { ok: false }`; the caller (the decision agent in `apps/workers`) owns the strict Zod schema. A refusal, any verdict other than exactly `ok: true`, or a throw is `invalid_output` and the whole output is discarded.
- **Result shape.** `{ status, value?, text, usage: { inputTokens, outputTokens, latencyMs, turns }, provider: { id, model } | null }`, `status` in `ok | timeout | error | invalid_output | aborted`. A provider answer the adapter cannot parse maps to `invalid_output`.
- **Loop.** One shared timeout (combined with the caller's `AbortSignal`) for all turns, at most `maxTurns` calls, temperature 0; the tool calls of all turns are collected; after a turn with tool calls the harness replies with `toolResultMessage("tool_calls", { recorded: n })`. It offers only the tools the caller passes and never executes a tool.
- **Logging.** An injected logger receives status, provider, model, turns, token counts and latency only; never the data, the system prompt, the model's text or a tool input; errors are reduced to a code.

## Alternatives considered

1. Call a single vendor directly from each feature: rejected, locks the product to one vendor and duplicates secret and bounds handling.
2. Put prompts and model calls in the API process: rejected for the decision agent (it runs in the pipeline worker under the execution lease); the layer lives in `packages/infra` so API and workers can both use it, but long calls belong in workers.
3. Persist prompts and responses for audit: rejected for v1 (data volume and secret risk); store the validated structured output, provider, model and usage.

## Rationale

The layer is small, optional and security-critical. A thin owned interface keeps the secret handling, egress, bounds and tenant rules in one reviewed place, keeps the product working with no model, and leaves the door open to a heavier framework behind the same seam if a later feature needs it.

## Consequences

### Positive
- No vendor lock-in; local-only deployments are possible; one place for keys, bounds and validation; trivial stub provider for the security suite; the Findings agent starts from a working, reviewed layer.

### Negative / trade-offs
- We maintain three request mappers and track vendor API changes; no off-the-shelf multi-agent features; the consent and tenant-override design is still to be decided.

## Security and operational impact

- Keys only through the secret store, never logged; redaction paths cover the key field names; no secret in an error message.
- Model output is untrusted: strict validation, size caps, plain-text rendering, provenance (provider and model) shown to users.
- Egress only to the configured host; the Ollama URL is deployment configuration; tenant-supplied URLs are not allowed in v1.
- Repository-derived data (paths, never contents or patches in v1) is sent to an external provider only for a tenant with the explicit, audited consent; the gate is inside `resolveLLMProvider`.
- No tenant, user, workspace or repository identifiers or names in a provider request; no cross-tenant response cache or conversation state.
- Failures never fail the caller's workflow: `null` provider, timeout, error and invalid output are normal results with a documented fallback.
- Security-suite coverage for the properties above is proposed in `docs/modules/scan-decisioning/SPEC.md` 14.1 (ADR-008 scope extension needs the owner's approval).

## Related documents

- `docs/modules/scan-decisioning/SPEC.md`, `docs/modules/scan-decisioning/SCREENS.md`
- `docs/decisions/ADR-009-INTEGRATION-CREDENTIAL-STORAGE.md`, `docs/decisions/ADR-011-TRANSACTIONAL-OUTBOX-AND-MESSAGE-ENVELOPE.md`, `docs/decisions/ADR-001-JAVASCRIPT.md`, `docs/decisions/ADR-002-MODULAR-MONOLITH.md`
- `docs/technical/SECURITY_GUIDELINES.md`, `docs/decisions/OPEN_DECISIONS.md`
