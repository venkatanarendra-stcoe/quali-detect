# Module specification: Scan decisioning (Analysis and Scan Decisioning, workflow steps 4 and 5)

**Status:** **Approved (2026-11-17)** by the owner, with the decisions in the next section ("Decisions applied at approval"). Implementation follows the parts of section 16, one commit per part. Parts A and B are implemented (sections 17.a and 17.b); parts C to G are not. Written from the owner brief of 2026-11-17 (the hybrid design below), the closed Executions module (`docs/modules/executions/SPEC.md`, section 17.ai) and the documents named in section 13. Labels follow the repository rule: **Confirmed** = stated by the owner in the 2026-11-17 brief or already Confirmed elsewhere; **Recommended** = my proposal, not binding; **Open** = needs the owner. Nothing Recommended or Open is promoted.

Module order position: items 8 and 9 of `docs/modules/README.md` (repository analysis and scan orchestration), the part that sits **between the source fetch and the start of the scans**. The false-positive / AI advisory agent is **not** in this module (Findings module, section 2).

## Decisions taken from the owner brief (2026-11-17, Confirmed)

| Id | Decision |
|---|---|
| D1 | **Decision = deterministic floor + an LLM agent that can only expand.** The deterministic floor guarantees safety; the model adds. The system is fully functional with no model |
| D2 | **Where:** inside the execution's `preparing` state, after the source fetch and before the tasks are created. Only the **decided** tasks are created. The configuration stops being the direct source of tasks and becomes an input of the decision |
| D3 | **Change detection** is deterministic. Repository content is untrusted **data**, never executed. Incremental runs get a changed-file list (push `before` to `after`; same-repository PR and fork PR `base` to `head`) from the GitHub compare or pull-request-files API using the **installation token fetched outside any scan**; **full runs skip the diff**. A verification spike (push, same-repository PR, fork PR, on a private base repository) is required |
| D4 | **Floor** = mandatory scan set from file-change rules **intersected with the pipeline's enabled scan types**. Full run: floor = all enabled. Incremental: manifests to SCA and SBOM, code to SAST, Secrets by default on **any** change (configurable). **Nothing downstream can reduce the floor** |
| D5 | **Agent** (optional): multi-provider through an `LLMProvider` interface (ADR-013 proposal); each scan is a **tool call**; context is bounded and untrusted (diff summary and file list, never raw secrets, never treated as instructions). It may **add** enabled scan types that are not in the floor, with a reason. It can **never remove** a floor scan and **never add a type the pipeline has not enabled**. Output is validated with Zod |
| D6 | **Resilience:** the call is bounded by a timeout; on timeout, error, invalid output or **no provider configured** the execution proceeds with the **floor only**, and that is logged |
| D7 | **Final task set = floor union agent additions**, all inside the enabled types. Unsupported engines behave as today (`unsupported` task, SPEC executions §17.ab). A scan type that is not selected is **not a failure** |
| D8 | The decision is recorded in an event `decision_completed` (the brief wrote `decision.completed`; existing event types are snake case, for example `task_unsupported`) carrying the floor set, the agent-added set, a reasoning summary (no raw repository content, no secrets), and provider and model |
| D9 | **Lease reclaim does not re-run the agent.** The decision record is persisted and reused (deterministic resume, no second model cost) |
| D10 | Full and incremental behaviour, `untrusted_fork` behaviour and unsupported-engine behaviour of the Executions module stay intact |
| D11 | Security: untrusted bounded context; prompt-injection resistant because the floor guarantees no reduction; no crossing of tenant or workspace; records and diffs carry no credentials; provider keys only through the secret store |
| D12 | Screen: T-29 gets an **"Analysis and decision"** section: change summary, floor versus agent-added per scan type with reasons, provider and model used, and a note when it fell back to floor-only |
| D13 | The FP / AI advisory agent stays **out of scope** (Findings module) but **reuses the `LLMProvider` of ADR-013** |

## Decisions applied at approval (Confirmed, owner, 2026-11-17)

| Id | Decision | Effect on this spec |
|---|---|---|
| AP-1 | All flagged design choices approved: fail-closed diff, no agent call when the floor already holds every enabled type, `interrupted` and floor-only on reclaim, whole-output-or-nothing, paths only, one transaction, the decision embedded in `GET /executions/{id}` | sections 5.1 to 5.7, 8 |
| AP-2 | **Secrets rule:** default `any_change`, configurable to `strict`. Names replace the earlier proposal `candidate_files`. `strict` is defined in 5.3 (my reading of the brief; the definition is isolated in one constant and one table row so it is cheap to change on review) | 5.3, OQ-2 |
| AP-3 | **Zero-scan:** the execution ends `succeeded` with the reason `no_applicable_scans`; `resolutionEligible` is forced `false`; the quota unit is **refunded** (no scan started); the `status_reason` CHECK constraint is updated to allow this one reason on `succeeded` | 5.6, FT-4, DEC-013, DEC-S09 |
| AP-4 | **ADR-013 approved:** in-house bounded tool-calling loop, `fetch` adapters (Ollama, Anthropic, OpenAI), **no new dependency** (no langgraphjs, no Vercel AI SDK, no Python service); keys through the SecretStore / platform secret provider, never logged | ADR-013 |
| AP-5 | **Agent bounds:** 20 s overall, 3 turns. **Fork pull requests are floor-only in v1** (`skipped_fork` is a rule, not an option). Not called when the floor already holds every enabled type | 5.4, AG-1, AG-4 |
| AP-6 | **Data-egress consent:** an external provider (Anthropic, OpenAI) is disabled for a tenant until an **explicit, audited tenant consent setting** is on; a local Ollama is allowed by default; without consent the tenant runs floor-only (or Ollama-only if the deployment provider is Ollama). A security check proves an external provider is never called for a tenant without consent | 5.4 AG-9, 7.5, 11 SD-6, 14.1 `DEC-S10` |
| AP-7 | **ADR-008 scope is extended** for `DEC-S01..S09` (and `DEC-S10`, `DEC-S11`); the floor file-to-scan rules are exercised in the module's **live test** (feature behaviour, not the suite) | 14.1, 16 part G |

Open by the owner's list at the time of writing (section 15; AP-2 to AP-6 above resolved most of them): diff source (spike), Secrets rule (strict versus safe), zero-scan outcome, LLM framework (ADR-013), whether to call the agent for trivial changes (cost), per-tenant provider configuration, agent timeout value.

## 1. Purpose

Today the orchestrator creates one scan task for **every enabled scan type** of the pipeline snapshot (SPEC executions ER-11). That is safe but wasteful for an incremental run (a documentation-only change starts SAST and SCA) and it cannot adapt to what changed. This module decides **which of the enabled scans the run needs**, while keeping one guarantee that no model can weaken: **a deterministic floor of scans that always runs**. The model can only add to it.

## 2. Scope

### In scope
- Change detection for incremental executions (changed-file list and a bounded change summary), fail-closed.
- The deterministic floor (rules, shared pure function, platform setting for the Secrets rule).
- The agent harness (bounded context, one tool, bounded turns, timeout, Zod validation) on top of ADR-013's `LLMProvider`.
- The decision record, the `decision_completed` event, lease-safe persistence and reuse.
- The `preparing` integration (task creation from the decision) and the aggregation consequences.
- API: the execution detail DTO gains a `decision` object. T-29 section "Analysis and decision".
- Security-suite additions for the safety properties (section 14.1, ADR-008 scope extension Recommended).

### Out of scope
- **The FP / AI advisory agent** (Findings module, advisory only, bounded and untrusted context). It reuses ADR-013.
- Reading file contents or patch hunks for the agent (v1 sends paths and counts only; Open, section 15).
- Real scan engines, DAST, Asset Discovery, manual scans (T-30).
- Per-pipeline editor controls for the decision (Open, section 15); v1 uses platform settings.
- Billing or quota for model usage beyond a usage record (Open).

## 3. Actors and permissions

| Actor | What | Permission |
|---|---|---|
| Pipeline worker (system) | Runs the decision inside `preparing` under the execution lease | none (system); re-validates tenant, workspace, repository, pipeline on every load |
| Tenant user | Reads the decision on T-29 | `execution.view` at workspace scope (the existing key; **no new permission key**) |
| Platform operator | Sets the provider, model, limits and the Secrets rule (deployment configuration) | deployment access; not an application permission |

Rules: a user without `execution.view`, or in another tenant or workspace, gets the same `404` as for the execution itself (AUTHORIZATION 404/403 rule). The decision is never readable apart from its execution. **Recommended.**

## 4. Functional requirements

| Id | Requirement | Priority | Label |
|---|---|---|---|
| DEC-001 | Every execution that reaches `preparing` gets exactly one decision record before its tasks are created (full runs included: floor = all enabled, no diff, no agent call) | Must | Confirmed (D2, D3) |
| DEC-002 | The floor is computed by a deterministic pure function of (scan kind, changed files, enabled types, Secrets rule, exclusions). No model, network or clock input | Must | Confirmed (D4) |
| DEC-003 | The final task set is a subset of the enabled types and a superset of the floor; no downstream step (agent, validation, fallback) can remove a floor type | Must | Confirmed (D4, D5) |
| DEC-004 | The agent can add only types that are enabled and not in the floor; any other output makes the **whole** agent output invalid and the run continues with the floor | Must | Confirmed (D5, D6) |
| DEC-005 | The agent call is bounded (timeout, turns, tokens, output size) and optional; every failure mode ends in "floor only" with the reason recorded | Must | Confirmed (D6) |
| DEC-006 | With no provider configured, or when no type could be added (the floor already holds every enabled type), the agent is **not called** | Must | Confirmed (D6); the second half **Recommended** (follows from D5) |
| DEC-007 | The decision is persisted once, immutably, with the floor, the additions, the reasons, the diff facts, provider and model and the agent status | Must | Confirmed (D8) |
| DEC-008 | A reclaim of the lease reuses the persisted decision; if the previous holder died while the agent call was in flight, the new holder does **not** call the agent again (agent status `interrupted`, floor only) | Must | Confirmed (D9); the `interrupted` detail **Recommended** |
| DEC-009 | Change detection failing, truncated or unavailable makes the floor **all enabled types** (fail closed); the scan kind of the execution is not changed | Must | Recommended |
| DEC-010 | The decision never receives, stores or sends credentials, file contents, patch text, commit messages, PR titles or user data | Must | Confirmed (D11) |
| DEC-011 | `untrusted_fork` executions: the diff uses the installation token outside the scan; the scan context is unchanged (no credentials); the agent is **never called** for forks in v1 (`skipped_fork`) | Must | Confirmed (D10, AP-5) |
| DEC-012 | The execution detail DTO carries the decision; T-29 renders it (section 10) | Must | Confirmed (D12) |
| DEC-013 | The zero-scan outcome (nothing applicable) is `succeeded` / `no_applicable_scans`, quota refunded once, `resolutionEligible = false` (section 5.6) | Must | Confirmed (AP-3) |

## 5. Business rules

### 5.1 Decision flow (inside `preparing`)

```mermaid
sequenceDiagram
  participant W as pipeline worker (lease holder)
  participant D as PostgreSQL
  participant G as GitHub API
  participant L as LLMProvider (optional)
  W->>D: lease held, status preparing, source fetched and extracted (SPEC executions 6.3)
  W->>D: decision record exists for this execution? yes: reuse (skip to task creation)
  W->>D: no record, decision_started event present? yes: previous holder died mid-call, agent_status interrupted, floor only
  W->>D: otherwise insert event decision_started (fenced by the lease epoch)
  alt scan_kind = full
    Note over W: no diff; floor = all enabled types
  else incremental
    W->>G: changed files (compare or PR files) with the installation token, in memory only
    W->>W: classify files, apply exclusions, compute the floor
  end
  opt a provider is configured AND enabled types exist that are not in the floor
    W->>L: bounded untrusted context + one tool per addable scan type
    L-->>W: tool calls (scanType, reason) or nothing
    W->>W: Zod-validate; invalid or out-of-set output is discarded as a whole
  end
  W->>D: ONE transaction: insert scan_decisions, event decision_completed, create the DECIDED tasks, status running, events, audit, outbox
```

Order guarantee (Recommended): the decision record, the `decision_completed` event, the task rows and the `preparing -> running` transition are written in **one transaction** fenced by the lease epoch, so there is never a decision without its tasks or tasks without their decision. The fetch, the diff and the model call happen **before** that transaction and hold no database transaction open.

### 5.2 Change detection (D3; mechanics Recommended, source Open)

| Rule | Text |
|---|---|
| CD-1 | Only for `scan_kind = incremental`. The base is `executions.base_sha` (push `before`, PR base) and the head is the pinned `commit_sha`. Both are already stored by the router and the fetch step |
| CD-2 | Source (**settled by the part A spike, 17.a**): the GitHub **compare** API for pushes and same-repository PRs, the **pull-request files** API for PRs (including fork PRs, where the head lives in another repository). Whether both work on a **private base repository** with the App's current permissions (Metadata, Contents, Pull requests: read; repositories-github SPEC D5), their pagination and file limits, and how a new branch (`before` all zeros), a force push (unreachable `before`) and a tag push behave must be **verified live before implementation** |
| CD-3 | The token is the same repository-scoped installation token minted by the fetch step, used in the worker, in memory only, **never** in the scan context, a message, a log, an event or the decision record |
| CD-4 | Fetched per file: path, previous path (rename), status (`added`, `modified`, `removed`, `renamed`, `copied`, `changed`), additions and deletions counts. **The patch text is discarded at the adapter** and never stored or sent anywhere |
| CD-5 | Bounds: compare lists at most **300** files (documented and enforced by GitHub, 17.a): 300 or more means truncated; pull-request files are read at most 30 pages of 100 (3000); at most `SCAN_DECISION_MAX_CHANGED_FILES` (Recommended 3000) files and `SCAN_DECISION_MAX_PAGES` API pages. Over a bound, or any API error, empty or unparsable answer, or a base that is not reachable: `diff_status = truncated` or `unavailable` and the floor becomes **all enabled** (DEC-009). Never a partial list treated as complete |
| CD-6 | The snapshot's `exclusions.paths` are applied to the list. If every changed file is excluded the changed set is empty (zero-scan case, section 5.6) |
| CD-7 | Repository content, file names, branch names and every string from the API are **untrusted data**: validated by Zod, length-capped, control characters stripped, never executed, never interpolated into an instruction |

### 5.3 The deterministic floor (D4; the rule table is Recommended and reviewable)

File classes (by path, no content read): **manifest** (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `pom.xml`, `build.gradle*`, `Gemfile`, `Gemfile.lock`, `composer.json`, `composer.lock`, `*.csproj`, `packages.config`), **code** (known source extensions: `js jsx ts tsx mjs cjs py java kt go rs rb php cs c h cpp hpp swift scala sh sql ...`), **config** (`json yaml yml toml ini env properties tf` and dotfiles), **docs** (`md rst txt adoc`), **other** (everything else, including binaries and unknown extensions).

| Rule | Adds to the floor | When (incremental) |
|---|---|---|
| FL-1 | `sbom`, `sca` | any manifest file changed, **in any status** (a removed dependency file changes the inventory) |
| FL-2 | `sast` | any **code** file added, modified or renamed (a removed code file alone does not add SAST) |
| FL-3 | `secrets` | Secrets rule `any_change` (**default**): at least one file added, modified or renamed, of any class. Rule `strict`: at least one changed file of **any status, removals included** (a removal-only change is not a zero-scan case for Secrets) |
| FL-4 | all enabled types | change detection failed, truncated or unavailable (DEC-009) |
| FL-5 | (full run) all enabled types | `scan_kind = full`, no diff, no agent call needed |
| FL-6 | nothing | the changed set is empty (after exclusions): zero-scan case |

Then **floor = rules intersected with the enabled types**. A rule that names a type the pipeline has not enabled adds nothing. The catalog order `sbom, sca, sast, secrets` is kept for the task ordinals.

The two Secrets modes are `any_change` (default) and `strict` (AP-2). The owner's words were "default any_change, configurable to strict"; `strict` is defined here as the **wider** mode (removals count too) and this definition is the one thing to confirm on review. Setting: `SCAN_DECISION_SECRETS_RULE` (platform, default `any_change`).

### 5.4 The agent (D5, D6; harness Recommended)

| Rule | Text |
|---|---|
| AG-1 | **Called only if** a provider resolves AND at least one enabled type is outside the floor AND the execution is not an `untrusted_fork` AND the tenant has the consent the provider needs (AG-9). Otherwise agent status is `not_configured`, `nothing_to_add`, `skipped_fork` or `consent_required`. (`skipped_trivial` is not used in v1: the only trivial-change rule is `nothing_to_add`) |
| AG-2 | Context (one JSON object, passed as **data**, with a fixed system prompt that says so): scan kind and reason, the enabled-not-in-floor types, the floor types with their rule ids, counts by file class, counts by status, total additions and deletions, and up to `SCAN_DECISION_CONTEXT_PATHS` (Recommended 100) changed paths, each length-capped and passed through the credential-shape redaction. **Never**: file contents, patches, commit messages, PR titles or bodies, branch names of forks, author names, tokens, tenant, user or workspace names or ids |
| AG-3 | Tools: one tool `request_scan({ scanType, reason })` per **addable** type (enabled and not in the floor). The agent has **no other tool**: no repository read, no network, no shell. A call to a name outside the offered tools is invalid output |
| AG-4 | Loop (Recommended): at most `SCAN_DECISION_MAX_TURNS` (**3, Confirmed AP-5**) provider calls, temperature 0 where the provider supports it, `max_output_tokens` bounded, one overall timeout `SCAN_DECISION_AGENT_TIMEOUT_SECONDS` (**20 s, Confirmed AP-5**, platform setting) bound to an `AbortSignal` that a cancel request also fires |
| AG-5 | Validation (Zod, strict): `additions[]` of `{ scanType in the addable set, reason: string 1..300 }`, unique types, plus an optional `summary` string up to 1000 chars; unknown keys, a type outside the addable set, a duplicate, an over-long string or non-text output make the **entire** output invalid. It is never partially applied (a partially trusted answer from an injected prompt is not trusted) |
| AG-6 | Accepted reasons and summary are model-written **untrusted text**: redacted for credential shapes, stripped of control characters, stored as plain text, rendered as text only (never HTML or Markdown), labelled with the provider and model |
| AG-7 | The raw prompt and raw response are **not stored** (Recommended; retention of prompts is Open). Stored: the validated structured output, provider id, model, token usage, latency, agent status |
| AG-9 | **Consent gate (AP-6).** Before any provider call the worker resolves the tenant's consent from the database (`tenant_llm_settings`, loaded by tenant id, never from a message). Provider kinds: `ollama` = local, needs no consent; `anthropic` and `openai` = external, need `externalConsent = true`. No consent for an external provider: **no call** is made, agent status `consent_required`, floor only. The gate lives in the provider resolution (`resolveLLMProvider`), not only in the caller, so no other caller can bypass it |
| AG-8 | Prompt-injection posture: the worst a hostile file name or any injected instruction can do is add a scan the pipeline already enabled (cost), or fail validation (floor only). It cannot remove a floor scan, add a disabled type, change the scan kind, read other data or call anything else. Safety does not depend on the model behaving |

Agent status values: `not_configured`, `nothing_to_add`, `consent_required`, `skipped_fork`, `ok` (output valid, zero or more additions), `timeout`, `error` (provider failure or abort), `invalid_output`, `interrupted` (DEC-008), `cancelled` (the execution was cancelled during the call). All but `ok` mean **floor only**.

### 5.5 Final task set and the Executions rules it touches (D7, D10)

| Rule | Text |
|---|---|
| FT-1 | `final = floor union validated additions`, restricted to the enabled types, ordered by the catalog |
| FT-2 | Tasks are created **only for `final`** (amends SPEC executions ER-11, which creates one per enabled type). A type in `final` without an engine becomes an `unsupported` task as today (SPEC executions §17.ab). A type **not** in `final` has **no task row**; it appears on T-29 from the decision record as "Not selected" with its reason |
| FT-3 | Aggregation (SPEC executions 5.4) is computed over the **created** tasks. A run whose enabled types are not all in `final` is **not** `partial` for that reason: not selected is not a failure. `resolutionEligible` is unchanged in practice: a full run's floor is every enabled type, and incremental runs are never eligible |
| FT-4 | Quota: unchanged (one unit per execution, taken at request time) **except** the zero-scan case, where the unit is refunded once (5.6) |
| FT-5 | The scan context, queues (`scan` versus `scan-untrusted`) and credentials rules of SPEC executions ER-5 and ER-7 are unchanged; the decision adds nothing to a task message |
| FT-6 | The `ordinal` of a task is its catalog position. Gaps are expected (for example SAST without SBOM). Whether a database constraint assumes contiguous ordinals is **to verify in part B** |

### 5.6 The zero-scan outcome (DEC-013, **decided: AP-3**)

When `final` is empty (an empty or fully excluded change set, or a floor of nothing and no additions) no task exists and **no scan started**. The execution ends **`succeeded`** with the status reason **`no_applicable_scans`**, `taskCounts` all zero, `resolutionEligible = false` (forced, whatever the scan kind), one `decision_completed` event, and the quota unit **refunded exactly once** (the same compare-and-set release as the other pre-scan endings, SPEC executions ER-26 / "failed before fetch"). Implementation notes (part E): (a) the migration updates the `executions_status_reason_check` so that `succeeded` may carry this one reason (the check today requires a reason for exactly the statuses blocked, skipped, cancelled, failed, partial and timed out), and the DTO, T-28 chip text and filters show "Succeeded: no scan applied"; (b) the path is `preparing -> running -> succeeded` inside the one transaction (two events, the same lease epoch) unless the database guard already allows `preparing -> succeeded`, to be verified in part E; no state-machine change is made without a contradiction report; (c) the completed event carries `resolutionEligible: false`.

### 5.7 Reclaim and resume (D9)

1. `scan_decisions` row exists for the execution: reuse it, write nothing new, create the tasks from `final_types` (a reclaim in `preparing` after the commit of the decision transaction cannot happen, because that transaction also moves to `running`; this branch covers a retry of the transaction itself).
2. No row, `decision_started` event exists, no `decision_completed`: the previous holder died before it could commit. The new holder **recomputes the floor** (deterministic: the same SHAs give the same list; the diff call is cheap and has no model cost), does **not** call the agent (`agent_status = interrupted`), and commits.
3. Neither exists: run the full flow.
4. A reclaim after `running` never reaches the decision (tasks already exist; SPEC executions 6.4).
5. A zombie holder (lost lease) cannot write: the transaction is fenced by `lease_epoch`, as for tasks.

### 5.8 Cancel, timeout, retry

- Cancel while `preparing`: the `AbortSignal` ends diff and agent calls; the execution cancels as today (quota refunded once for preparing, SPEC executions 5.6). No decision record is written.
- The decision time counts toward the execution's `preparing` time; the lease heartbeat keeps running during the call. The agent timeout must stay below the lease TTL (platform validation, as for the heartbeat rule).
- Retry (SPEC executions 5.7): a retry is a **new** execution and makes its **own** decision (the changed set of the pinned SHAs is the same, so the floor is the same; the agent may differ). Reusing the original's decision for a retry is Open (Recommended: no, keep executions independent).

## 6. Workflows

Section 5.1 is the decision workflow. The execution state machine is unchanged (no new status): `preparing` simply contains the steps fetch, extract, **decide**, then the combined "create decided tasks, move to running" transaction.

## 7. Data model

### 7.1 Existing tables relied on
`executions` (`scan_kind`, `scan_kind_reason`, `base_sha`, `commit_sha`, `trust`, `config_version_id`, `lease_epoch`), `pipeline_config_versions` (enabled types, exclusions), `scan_tasks`, `execution_events` (type `text`, `details jsonb`, insert-only, written under the lease), `audit_logs`. Verified in the Executions module (SPEC executions §17).

### 7.2 New table `scan_decisions` (Recommended)

One row per execution, insert-once. Composite tenant-safe foreign key `(tenant_id, workspace_id, repository_id, pipeline_id, execution_id)` to `executions`, unique `(tenant_id, execution_id)`, immutable by trigger (as `scan_results`), written only inside the lease-fenced task-creation transaction.

| Column | Meaning |
|---|---|
| `schema_version` | 1 |
| `scan_kind`, `trust` | copied from the execution at decision time |
| `diff_source` | `none` (full run), `github_compare`, `github_pull_files`, `unavailable` |
| `diff_status` | `not_needed`, `complete`, `truncated`, `unavailable` |
| `changed_total`, `change_summary` (jsonb) | counts by class and status, additions, deletions, up to N sample paths per class, **no patch text**; redacted |
| `secrets_rule` | `any_change` or `strict` |
| `floor` (jsonb) | `[{ scanType, ruleIds[] }]` |
| `agent_status` | the values of 5.4 |
| `agent_provider`, `agent_model` | text, null when no call was made |
| `agent_additions` (jsonb) | `[{ scanType, reason }]` validated |
| `agent_summary` | text up to 1000, redacted |
| `agent_usage` (jsonb) | input and output tokens, latency ms, turns |
| `final_types` (jsonb) | the decided types in catalog order |
| `not_selected` (jsonb) | `[{ scanType, reason }]` for enabled types not in `final` (reasons are stable codes such as `no_matching_changes`) |
| `decided_at` | timestamp |

DB-level guards (Recommended): `final_types` contains every `floor` type; every `agent_additions` type is absent from `floor`; strict lengths; credential-shape CHECK on the text columns (as for `execution_logs`).

### 7.2a New table `tenant_llm_settings` (Recommended, part B)

One row per tenant (created on first change; absence means no consent). Columns: `tenant_id` (primary key and foreign key, `ON DELETE RESTRICT`), `external_consent` boolean default false, `updated_by_user_id`, `updated_at`, `consent_changed_at`. Read by tenant id only. Changed through `PUT /settings/ai` (permission `tenant_settings.manage`, the existing key; read with `tenant_settings.view`), in one transaction with an **audit entry** (`tenant.llm_consent_changed`, actor, previous and new value, no other data). Every change, on or off, is audited. A tenant with the setting off or absent never has an external provider called (AG-9). A new tenant-owned route family: ADR-008 checks `DEC-S11` (section 14.1).

### 7.3 Events
`execution_events`: `decision_started` (marker, empty details) and `decision_completed` (details: `floor`, `added`, `final`, `agentStatus`, `provider`, `model`, `summary`, `diffStatus`, `changedTotal`). No raw repository content, no secrets, no prompts. Bounded size.

### 7.4 Retention
The decision record lives and dies with its execution (same 13-month metadata retention as `executions`). Nothing in it is source code.

## 8. API contract

No new endpoint. **`GET /executions/{id}`** gains `decision`: `null` for executions without a record (created before this module, or not yet decided), otherwise `{ scanKind, diff { source, status, changedTotal, summary { byClass, byStatus, additions, deletions, samples } }, secretsRule, scanTypes: [{ scanType, state: "required" | "added" | "not_selected" | "not_enabled", ruleIds, reason, taskId }], agent { status, provider, model, summary, usage { inputTokens, outputTokens, latencyMs } }, decidedAt }`. DTO mapper, no Prisma model, no tenant id, no internal columns. Same permission, tenant and workspace scoping and `404` rules as the detail. The contract snapshot is regenerated and reviewed (`pnpm contract:snapshot`, parity). **Recommended.**

Realtime: a hint type `pipeline.execution.decision_completed` (ids only, to the existing room) so T-29 refetches without waiting for the next status hint. **Recommended.**

## 9. Events and asynchronous work

No new queue. Existing job and event envelopes (ADR-011) are unchanged. New hint message type above, registered in `packages/contracts/src/message-types.js` with a strict schema and an ownership check in its consumer (as the other execution hints). The decision runs inside the existing `pipeline.execution.requested` handler.

## 10. Frontend requirements

T-29 gets the section described in `SCREENS.md` of this module. The execution list (T-28) is unchanged. Navigation is unchanged (no new item).

## 11. Security and privacy

| Id | Rule |
|---|---|
| SD-1 | **Untrusted data.** Repository file names and every API string are data. They are validated, capped, redacted and passed to the model only inside a JSON data field under a fixed system prompt (SECURITY_GUIDELINES "Separate data from instructions", Confirmed) |
| SD-2 | **The model never decides alone.** It can only add scans the pipeline enabled; the floor is computed without it. No irreversible workflow decision is delegated to a model (SECURITY_GUIDELINES, Confirmed) |
| SD-3 | **Bounded tools.** One tool per addable type, no read, no network, no shell (SECURITY_GUIDELINES "Do not grant AI agents unrestricted tools", Confirmed) |
| SD-4 | **No credentials anywhere.** The installation token exists only in the diff call; it is not in the context, the prompt, the provider request, the record, an event, a log, a message or an error. Provider keys come only from the secret store (ADR-009, ADR-013) and are never logged |
| SD-5 | **Tenant isolation.** The decision loads the execution by tenant, workspace, repository and pipeline; the provider request carries no tenant, user, workspace or repository identifiers or names; no model memory, conversation state or response cache is shared between tenants or executions; the record and event carry the composite tenant keys |
| SD-6 | **Data egress consent (Confirmed, AP-6).** File paths of a private repository leave the deployment when an external provider (Anthropic, OpenAI) is used. An external provider is used for a tenant only if the deployment configures it **and** the tenant has an explicit, audited consent (7.2a); a local Ollama needs no consent. Without consent: floor only |
| SD-7 | **Cost abuse.** Fork pull requests and many small pushes can multiply model calls. Bounds: skip when nothing is addable, a per-process concurrency cap `SCAN_DECISION_MAX_CONCURRENT_CALLS`, the timeout, and the Open rule for forks and trivial changes |
| SD-8 | **Provenance.** Model output is shown with provider and model and labelled as model-written (SECURITY_GUIDELINES "Record evidence and provenance", Confirmed) |
| SD-9 | **SSRF.** The Ollama base URL is deployment configuration, never tenant-supplied, in v1 (ADR-013) |
| SD-10 | **Logs.** Logs carry ids, statuses, counts and durations, never prompts, responses, paths lists, or tokens |

## 12. Observability

Per decision: duration of the diff and the agent call, agent status counts, provider and model, tokens in and out, floor size, additions count, fallback reasons. Structured logs by ids only (SD-10). Metrics names are Recommended and follow the existing worker logging; no metrics stack is added in this module.

## 13. Dependencies

Internal: Executions (the `preparing` state, tasks, aggregation, events, T-29), Pipelines and triggers (enabled types, exclusions, scan kind), Repositories and GitHub (installation token, App permissions), ADR-009 (SecretStore, PlatformSecretProvider), ADR-011 (envelopes), ADR-013 (LLMProvider, Proposed), access-management (`execution.view`). External: GitHub REST API (compare, pull-request files), the configured LLM provider (optional). Hand-over: the Findings FP agent reuses ADR-013 and the harness patterns of section 5.4.

## 14. Acceptance criteria

- [ ] With no provider configured, every execution decides by the floor alone, runs, and shows "assistant not used" on T-29.
- [ ] A full run's tasks equal the pre-module behaviour (all enabled types).
- [ ] An incremental docs-only change runs only the types its floor requires (Secrets per the configured rule).
- [ ] The agent can add an enabled type and cannot remove a floor type or add a disabled one, whatever it returns.
- [ ] Timeout, provider error, invalid output, no provider, a cancel during the call: floor only, run continues (or cancels), reason recorded.
- [ ] Change detection failure, truncation or an unreachable base runs the full floor.
- [ ] A lease reclaim never makes a second model call for the same execution; resume is deterministic.
- [ ] Fork PR: no credential reaches the scan context, the model request or the record; the queue is `scan-untrusted`.
- [ ] Unsupported engines still produce `unsupported` tasks; a not-selected type is not a failure and does not make the run `partial`.
- [ ] The zero-scan outcome behaves as decided (section 5.6).
- [ ] T-29 shows the section for every state in `SCREENS.md`; the DTO leaks nothing internal.
- [ ] The checks of 14.1 pass in `pnpm test:security`; ADR-008, the suite README, OpenAPI, the contract snapshot, `PROGRESS_TRACKER.md` and the Executions SPEC are updated.
- [ ] The verification spike of section 16 was run on a private base repository.

### 14.1 Security-suite additions (Confirmed, AP-7: ADR-008 scope extended, area 17)

Scope stays the safety properties, not the rule table: a mapping of changed files to scan types is feature behaviour and is verified by review and the live test, not by the suite. Prefix `DEC-` (HTTP and worker behaviour), `DECDB-` (database integrity, in process), continuing `DAL-`.

| Id | Property |
|---|---|
| DEC-S01 | **Floor is never reduced.** With a hostile provider stub that returns removals, unknown keys, disabled types, duplicates, over-long text, tool names outside the offered set, text instead of tool calls, and instruction-like content, the final set always contains the floor and only enabled types |
| DEC-S02 | **Only enabled types.** An addition outside the addable set invalidates the whole output; no partial application |
| DEC-S03 | **Fail-safe.** Provider absent, timeout, error, invalid output, abort: tasks are created from the floor, the execution is not failed because of the model |
| DEC-S04 | **No credentials in any surface.** The provider request captured by the stub, the decision record, the event, the DTO, the logs and the audit contain no token, `Authorization` value or secret-store value, in trusted and fork runs; the diff call is the only user of the token |
| DEC-S05 | **No second call on reclaim.** After a forced lease reclaim, with a decision record and with only a `decision_started` marker, the provider stub is called zero additional times and the task set is identical |
| DEC-S06 | **Tenant scope.** The decision loads and stores by tenant and the composite keys; another tenant's decision is a `404` over HTTP; the provider request holds no tenant, workspace, repository or user identifiers; no cross-tenant cache |
| DEC-S07 | **Fail closed on change detection.** A failing, truncated or unreachable diff yields the all-enabled floor |
| DEC-S08 | **Atomicity.** Decision row, event and tasks are one unit under a forced failure; a zombie holder writes none |
| DEC-S09 | **Zero-scan:** `succeeded` / `no_applicable_scans`, the quota unit refunded exactly once (also under concurrent reclaim and cancel), `resolutionEligible = false`, no task created |
| DEC-S10 | **Consent gate.** An external provider is never called for a tenant without consent (setting absent, off, or turned off between runs), for any caller of `resolveLLMProvider`; a local provider needs none; the stub records zero calls; turning consent on and off is audited |
| DEC-S11 | **Consent route family** (`GET/PUT /settings/ai`): tenant isolation, `404`/`403` by permission, no cross-tenant read or write, audit atomic with the change |
| DECDB-01 | Immutability and the table guards of 7.2; `DAL-` entries for every new repository function (the suite's "every function has a check" rule) |

## 15. Open questions and how the approval settled them

| Id | Question | Recommendation |
|---|---|---|
| OQ-1 | **Diff source** (GitHub compare versus pull-request files versus a base archive diff), limits, new branch, force push, tag, private base, fork PR | **Settled by the part A spike (17.a):** compare for pushes (300-file cap), pull-request files for all PRs including forks (3000-file cap), failures and 404 map to the full floor |
| OQ-2 | **Secrets rule** | **Decided (AP-2):** default `any_change`, configurable to `strict` (definition in 5.3; confirm on review) |
| OQ-3 | **Zero-scan outcome** | **Decided (AP-3):** option A with the quota unit **refunded** |
| OQ-4 | **LLM framework** | **Decided (AP-4, ADR-013 Approved):** in-house loop, `fetch` adapters, no new dependency |
| OQ-5 | **Call the agent for trivial changes?** | **Decided (AP-5):** skip only when the floor already holds every enabled type; no other trivial-change rule in v1 |
| OQ-6 | **Per-tenant provider configuration** | Deployment-level provider in v1; the per-tenant **consent** is built (AP-6); a tenant-chosen provider or key stays later (ADR-013) |
| OQ-7 | **Agent timeout value** | **Decided (AP-5):** 20 s, 3 turns, platform settings |
| OQ-8 | Agent for **fork PRs** | **Decided (AP-5):** floor only in v1 |
| OQ-9 | Patch hunks or file excerpts for the agent | No in v1 (secrets, cost, injection surface); revisit only with a redaction design |
| OQ-10 | Prompt and response retention | Not stored; structured output only |
| OQ-11 | Per-pipeline controls (agent on or off, Secrets rule) in the pipeline editor | Later, as an additive optional field of the strict pipeline configuration schema; a pipelines-module change |
| OQ-12 | Does a retry reuse the original's decision? | No, a new execution decides again |
| OQ-13 | Usage metering or quota for model calls | A usage record only in v1; quota later with the commercial plan decisions |
| OQ-14 | ADR-008 scope extension for section 14.1 | **Decided (AP-7):** approved as area 17 coverage |

## 16. Implementation notes (plan, Recommended)

Parts, one commit each, all gates after each, report per part:
- **A. Spike (no code in the product; DONE 2026-11-17, section 17.a):** verify compare and PR-files on a private base repository for push, same-repository PR and fork PR with the installation token and the current App permissions; record limits, pagination, new branch, force push; confirm the fork PR path. Update OQ-1.
- **B. Floor and records:** shared pure floor function and classifier in `@qmentisai/shared`; migration for `scan_decisions` and its guards; repository functions with tenant scope; DTO mapper; contract snapshot.
- **C. Change detection adapter:** in `packages/infra` GitHub client (new methods, patch discarded), bounds, fail-closed mapping.
- **D. Orchestrator integration:** the `preparing` flow of section 5.1, the one-transaction task creation from `final`, reclaim rules, zero-scan outcome per decision, `decision_started/completed` events, the hint message.
- **E. LLM layer and agent harness:** after ADR-013 is decided: `LLMProvider` in `packages/infra`, adapters, the harness, Zod schemas, redaction, limits, hostile-stub tests in the suite scope of 14.1.
- **F. API and T-29:** detail DTO, the "Analysis and decision" section.
- **G. Suite (`DEC-S01..S11`, ADR-008 area 17), mutation sweep over the new tenant-scoped functions, live test** that also exercises the floor file-to-scan rules (package.json-only, source-only, docs-only, mixed, removal-only, fork PR, no-provider, consent off and on) (private base repository, push, same-repository PR, fork PR, no-provider, provider timeout, reclaim during decision), results recorded in the tracker.

Verification items for part B: ordinal gaps in `scan_tasks`; whether the `executions` CHECK on `status_reason` needs the zero-scan amendment; the exact home of `SCAN_DECISION_*` settings (worker config schema, same pattern as `EXECUTION_*`).

## Related documents
`docs/modules/executions/SPEC.md` (5.3, 5.4, 6.3, 6.4, 17.ab, 17.ai), `docs/modules/pipelines-triggers/SPEC.md` (scan kind, exclusions, fork policy), `docs/modules/repositories-github/SPEC.md` (App permissions), `docs/decisions/ADR-009-INTEGRATION-CREDENTIAL-STORAGE.md`, `docs/decisions/ADR-013-LLM-PROVIDER-ABSTRACTION.md` (Proposed), `docs/technical/SECURITY_GUIDELINES.md` (Repository and AI safety), `docs/decisions/OPEN_DECISIONS.md`.

## 17. What I verified (built facts and spikes relied on)

### 17.a Part A spike: changed-file list from the GitHub API on a PRIVATE base repository (2026-11-17)

Run against `STCOE-TESTING/qm-test-2-renamed` (private) with an installation token minted for the one repository, in the agent's process only (no token printed or stored), from the executions of the live test (push before and after, same-repository PR #4, fork PR #5). The calls and their answers:

| # | Call | Result |
|---|---|---|
| 1 | token mint with `contents: read`, `pull_requests: read`, `metadata: read` | `201`, the three permissions granted, repository selection `selected`; the App already holds all three |
| 2 | `GET /repos/{r}/compare/{before}...{after}` (latest push) | `200`, `status ahead`, 1 file `modified package.json +2/-1`; keys `sha, filename, status, additions, deletions, changes, blob_url, raw_url, contents_url, patch` (**`patch` is present**: the adapter must discard it); no `Link` header when the list fits one page |
| 3 | same with `per_page=1&page=1` | `200`, the file list is still returned whole on page 1 (files are not paginated by `per_page`); a `rel="first"` Link only |
| 4 | `GET /repos/{r}/pulls/4/files?per_page=100` (same-repository PR) | `200`, 1 file `modified package.json +3/-1`; no Link header for one page; `page=2` is `200` with an empty list and a `rel="prev"/"last"/"first"` Link |
| 5 | `GET /repos/{r}/compare/{base}...{head}` for PR #4 | `200`, same single file as the PR-files call |
| 6 | `GET /repos/{r}/pulls/5/files?per_page=100` (**fork PR**) | `200`, 1 file `added package.json +33/-0`, from the **base** repository with the base installation token |
| 7 | `GET /repos/{r}/compare/{base_sha}...{fork_head_sha}` on the **base** repository | `200`, `status diverged`, ahead 1, behind 6, the same 1 file: a fork head SHA is addressable inside the base repository's network (consistent with the Executions spike, SPEC executions 17.x) |
| 8 | compare with `before` = 40 zeros (**new branch**) | **`404 Not Found`** |
| 9 | compare with an unreachable `before` (random SHA, **force push**) | **`404 Not Found`** |
| 10 | compare of a SHA with itself | `200`, `identical`, 0 files (an empty-commit push) |
| 11 | PR files with a token holding **only `contents: read`** | **`403 Resource not accessible by integration`** |
| 12 | compare with a token holding only `contents: read` | `200` |
| 13 | rate limit | the installation token starts at 5000 per hour (`x-ratelimit-remaining 4998` after the mint and first call); the spike used 14 calls |

Documentation read (quotes from the pages; page 2 only through a model-extracted summary of the unread tail, so its limits are **unverified verbatim**):
- `https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28#compare-two-commits` (verbatim): "The list of changed files is only shown on the first page of results, and it includes up to 300 changed files for the entire comparison."; "limited to 250 commits" when called without paging; `per_page` "max 100", default 30; basehead "BASE...HEAD", and "USERNAME:BASE...USERNAME:HEAD" for refs in a fork of the same network; `patch`: "Diffs with binary data will have no patch property." The page states no token permission and does not say what happens to files beyond 300.
- `https://docs.github.com/en/rest/pulls/pulls?apiVersion=2022-11-28#list-pull-requests-files` (summary only): "Responses include a maximum of 3000 files."; `per_page` default 30, max 100; status values `added, removed, modified, renamed, copied, changed, unchanged`; `previous_filename` optional. The Pull requests permission is not stated on the page; the live `403` in row 11 shows it is required.

**Conclusions (design unchanged; two numbers corrected):**
1. **Source (settles OQ-1):** pushes use **compare** (`contents: read`); pull requests, **same-repository and fork alike**, use **pull-request files** (`pull_requests: read`, paginated, base repository, base installation token). Both work on a private base repository with the permissions the App already has. No new App permission is needed.
2. **The compare file list is capped at 300**, not 3000 as CD-5 assumed. Rule: if a compare answer holds **300 or more files**, treat the list as **truncated** (fail closed, all enabled types). The pull-request files list is read page by page (`per_page=100`, at most 30 pages = the documented 3000); a full 3000 means truncated. `SCAN_DECISION_MAX_CHANGED_FILES` stays a bound below these.
3. **New branch (`before` all zeros), force push (unreachable `before`) and any `404`/`403`/`5xx`** are not errors of the run: they map to `diff_status unavailable` and the **full floor** (DEC-009). No attempt is made to guess a merge base in v1.
4. An **empty change** (`identical`, 0 files, or all files excluded) is the zero-scan case (5.6).
5. Manual and scheduled executions that are `incremental` have no `base_sha`: `unavailable`, full floor. Full runs never call the API.
6. The `patch` property is returned on every file: the adapter keeps only `filename`, `previous_filename`, `status`, `additions`, `deletions` and drops the rest in the same function that parses the response, before anything is logged or stored.
7. Not tested (stays a risk until the live test of part G): a PR or compare with more than 300 files, a binary or renamed file, a deleted fork, a rate-limit `403`/`429`.

### 17.b Part B as built: LLM layer, deployment configuration, consent gate and `GET/PUT /settings/ai` (2026-11-17)

Part B of section 16 is the LLM layer and the consent (it follows the "Floor and records" bullet only in the plan's lettering; the parts keep their letters). What exists after this commit, and nothing of parts C to G:

**Files.** `packages/infra/src/llm/` (`types.js` contract, `LLMError`, `assertLLMProvider`, `toolResultMessage`, `PROVIDER_KIND`; `http.js` shared `fetch` POST with the combined abort and timeout and the one bounded retry; `ollama.js`, `anthropic.js`, `openai.js`; `config.js` `readLLMConfig` and `missingLLMKeyProblems`; `resolve.js` `resolveLLMProvider` and the concurrency limiter; `index.js`), exported from `@qmentisai/infra`. Platform secret names in `packages/infra/src/scm/platform-secrets.js`. Redaction paths in `packages/infra/src/logging.js` and the credential shape `sk-` / `sk-ant-` in `credential-guard.js`. Table `tenant_llm_settings` (`packages/db/prisma/schema/llm.prisma`, migration `20261117130000_tenant_llm_settings`, **not applied to the development database by this work**), repository `createTenantLlmSettingsRepository` and `createLlmConsentGate` in `packages/db/src/llm-settings.js`. API module `apps/api/src/modules/tenant-ai-settings` (module kit layout), audit action `tenant.llm_consent_changed`, `LLM_*` variables read by the API configuration, `.env.example` of the API and the workers, contract snapshot and an accepted-parity entry. Suite: `apps/api/test/security/helpers/llm-consent-checks.js`, `DAL-299..301` in `direct-repos.js`.

**Decisions made while building (all inside the approved ADR-013 and AP-1..AP-7):**
1. `resolveLLMProvider` returns `{ provider, status }` (`ok`, `not_configured`, `consent_required`, `key_missing`), not a bare `null` (ADR-013 as-built note). The consent is an injected port `consent.isExternalAllowed(tenantId)`, backed by the repository (tenant id only). No adapter object exists before the check.
2. An external provider **re-checks the consent immediately before every request** (after any wait for a concurrency slot), so a held provider object cannot outlive a revoked consent; a refused request raises `LLMError` `not_configured`. This goes beyond the minimum of AG-9 and costs one primary-key read per model call.
3. **Audit only real changes.** Writing the value that is already set is accepted (200, idempotent), writes nothing and creates no audit entry; the first `true` on a tenant with no row is a change from the implicit `false`. A `false` on a tenant with no row is a no-op and creates no row. The previous value is exact because the write takes a per-tenant advisory lock (`llm-settings:<tenant>`) inside the transaction.
4. The audit entry is `tenant.llm_consent_changed` (actor user, target `tenant_llm_settings` / the tenant, `metadata: { previous, new }` only), written in the same transaction through the same helper as the other modules.
5. `readLLMConfig` is plain validation (like `readGitHubAppConfig`) because `packages/infra` has no Zod dependency and ADR-013 forbids a new one; the API calls it from `loadConfig` and fails startup with names-only problems. A hosted provider without its key is **not** a startup problem of the API (the API never calls the model); resolution returns `key_missing`, and `missingLLMKeyProblems` is the startup check the workers will use. Defaults: `LLM_PROVIDER=none`, no default model, `LLM_REQUEST_TIMEOUT_SECONDS=30`, `LLM_MAX_CONCURRENT_CALLS=4`, Ollama `http://127.0.0.1:11434`, hosted `https://api.anthropic.com` / `https://api.openai.com`; base URLs are refused with credentials, a query or a fragment, and hosted ones must be https in production.
6. The tool-result turn is one `user` message `Tool result for "<name>": <json>` (`toolResultMessage`); the adapters send plain text messages only, so no vendor tool-call ids are carried.
7. `GET`/`PUT /api/v1/settings/ai` use the existing keys `tenant_settings.view` / `tenant_settings.manage` (confirmed in `packages/shared/src/permissions.js` and `docs/AUTHORIZATION.md`; held by the Admin bundle only). The DTO is `{ externalConsent, assistant: { configured, providerKind }, updatedAt, consentChangedAt }`; `providerKind` is derived from the API-side `LLM_PROVIDER` (`local` for Ollama, `external` for Anthropic and OpenAI, `null` for none) and the DTO never carries the model, a URL or a key. A read creates no row.
8. Retry: one retry only on a transport reset (`ECONNRESET`, `EPIPE`, `UND_ERR_SOCKET`), none on an HTTP status, none after the caller's signal fired; redirects are refused (`redirect: "error"`).

**Suite (ADR-008 amended, count 708 to 727).** `DEC-S10a..f` and `DEC-S11a..j` (the ids of 14.1 split into lettered checks) and `DAL-299..301`. The full run after this work: 746 tests passed (727 checks, controls and the integrity test). **Mini mutation sweep** (SECURITY_SUITE_ONLY, mutate in place with backups, restore, diff against the pristine copies): 14 mutants, 14 killed, 0 survived: consent check removed from the resolver (`DEC-S10a`), per-request re-check removed (`DEC-S10a`), consent gate ignoring the tenant id (`DEC-S10a..d`), local/external classification inverted (`DEC-S10a`, `DEC-S10b`, `DEC-S11d`), audit removed (`DEC-S11e`, `DEC-S11i`, `DEC-S11j`), PUT permission check removed (`DEC-S11f`), tenant predicate removed from `getExternalConsent` (`DAL-299`, `DEC-S10a..d`), key placed on the error object (`DEC-S10d`), key placed in the URL (`DEC-S10a`, `DEC-S10c`), key sent in a second header (`DEC-S10c`), `.strict()` removed from the body schema (`DEC-S11g`, `DEC-S11h`), extra data in the audit metadata (`DEC-S11e`), audit written outside the transaction (`DEC-S11i`), GET permission check removed (`DEC-S11f`).

**What is NOT verified.** The adapters have **never been called against the real vendors**: their request and response mappings follow the vendors' documented Messages / chat completions / `/api/chat` shapes and are exercised only against local stubs that answer in those shapes. Model names, `max_completion_tokens` (OpenAI) versus older models, `temperature` support per model, tool-call behavior of any real model, rate-limit and error bodies of the vendors and a real Ollama server are unverified; the live test of part G is where they are first exercised. The platform-secret path was exercised only with the environment provider (development); production refuses it until a KMS/Vault provider exists, so an external provider cannot be used in production yet. The harness (ADR-013 section 3), the worker configuration of `LLM_*`, the tenant UI for the consent (T-29 / settings) and the use of `resolveLLMProvider` by the agent are later parts. The migration was applied only to the suite's disposable database.
