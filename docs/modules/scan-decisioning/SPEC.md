# Module specification: Scan decisioning (Analysis and Scan Decisioning, workflow steps 4 and 5)

**Status:** **Approved (2026-11-17)** by the owner, with the decisions in the next section ("Decisions applied at approval"). Implementation follows the parts of section 16, one commit per part. Parts A, B, C, D and E are implemented (sections 17.a, 17.b, 17.c, 17.d and 17.e); part F (the screens) is implemented, see `SCREENS.md` section 9; part G is not. Written from the owner brief of 2026-11-17 (the hybrid design below), the closed Executions module (`docs/modules/executions/SPEC.md`, section 17.ai) and the documents named in section 13. Labels follow the repository rule: **Confirmed** = stated by the owner in the 2026-11-17 brief or already Confirmed elsewhere; **Recommended** = my proposal, not binding; **Open** = needs the owner. Nothing Recommended or Open is promoted.

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

When `final` is empty (an empty or fully excluded change set, or a floor of nothing and no additions) no task exists and **no scan started**. The execution ends **`succeeded`** with the status reason **`no_applicable_scans`**, `taskCounts` all zero, `resolutionEligible = false` (forced, whatever the scan kind), one `decision_completed` event, and the quota unit **refunded exactly once** (the same compare-and-set release as the other pre-scan endings, SPEC executions ER-26 / "failed before fetch"). Implementation notes (part E): (a) the migration updates the `executions_status_reason_check` so that `succeeded` may carry this one reason (the check today requires a reason for exactly the statuses blocked, skipped, cancelled, failed, partial and timed out), and the DTO, T-28 chip text and filters show "Succeeded: no scan applied"; (b) the path is `preparing -> running -> succeeded` inside the one transaction (two events, the same lease epoch); the database guard does not allow `preparing -> succeeded` and no state-machine change was made (as built in part E, section 17.e, which also records the one narrow change to `executions_guard`); (c) the completed event carries `resolutionEligible: false`.

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
7. `GET`/`PUT /api/v1/settings/ai` use the existing keys `tenant_settings.view` / `tenant_settings.manage` (confirmed in `packages/shared/src/permissions.js` and `docs/AUTHORIZATION.md`; held by the Admin bundle only). The DTO is `{ externalConsent, assistant: { configured, providerKind }, updatedAt, consentChangedAt, consentChangedBy }` (`consentChangedBy` added in part G: `{ displayName }` or `null`, see 17.f); `providerKind` is derived from the API-side `LLM_PROVIDER` (`local` for Ollama, `external` for Anthropic and OpenAI, `null` for none) and the DTO never carries the model, a URL or a key. A read creates no row.
8. Retry: one retry only on a transport reset (`ECONNRESET`, `EPIPE`, `UND_ERR_SOCKET`), none on an HTTP status, none after the caller's signal fired; redirects are refused (`redirect: "error"`).

**Suite (ADR-008 amended, count 708 to 727).** `DEC-S10a..f` and `DEC-S11a..j` (the ids of 14.1 split into lettered checks) and `DAL-299..301`. The full run after this work: 746 tests passed (727 checks, controls and the integrity test). **Mini mutation sweep** (SECURITY_SUITE_ONLY, mutate in place with backups, restore, diff against the pristine copies): 14 mutants, 14 killed, 0 survived: consent check removed from the resolver (`DEC-S10a`), per-request re-check removed (`DEC-S10a`), consent gate ignoring the tenant id (`DEC-S10a..d`), local/external classification inverted (`DEC-S10a`, `DEC-S10b`, `DEC-S11d`), audit removed (`DEC-S11e`, `DEC-S11i`, `DEC-S11j`), PUT permission check removed (`DEC-S11f`), tenant predicate removed from `getExternalConsent` (`DAL-299`, `DEC-S10a..d`), key placed on the error object (`DEC-S10d`), key placed in the URL (`DEC-S10a`, `DEC-S10c`), key sent in a second header (`DEC-S10c`), `.strict()` removed from the body schema (`DEC-S11g`, `DEC-S11h`), extra data in the audit metadata (`DEC-S11e`), audit written outside the transaction (`DEC-S11i`), GET permission check removed (`DEC-S11f`).

**What is NOT verified.** The adapters have **never been called against the real vendors**: their request and response mappings follow the vendors' documented Messages / chat completions / `/api/chat` shapes and are exercised only against local stubs that answer in those shapes. Model names, `max_completion_tokens` (OpenAI) versus older models, `temperature` support per model, tool-call behavior of any real model, rate-limit and error bodies of the vendors and a real Ollama server are unverified; the live test of part G is where they are first exercised. The platform-secret path was exercised only with the environment provider (development); production refuses it until a KMS/Vault provider exists, so an external provider cannot be used in production yet. The harness (ADR-013 section 3), the worker configuration of `LLM_*`, the tenant UI for the consent (T-29 / settings) and the use of `resolveLLMProvider` by the agent are later parts. The migration was applied only to the suite's disposable database.

### 17.c Part C as built: change detection and the deterministic floor (2026-11-17)

The owner's part C is the change-detection adapter **and** the pure floor (section 16 lists them in two bullets; the lettering of the parts is the owner's). What exists after this commit, and nothing of parts D to G (no agent, no `scan_decisions` table, no orchestrator call, no API, no UI):

**Files.** `packages/shared/src/scan-decisioning/` (`constants.js` holds every reviewable list: scan types in catalog order, file classes, manifest names and patterns, code/config/docs extensions, diff statuses and sources, rule ids `FL-1..FL-5`, the Secrets rule values; `classify.js` `classifyPath`; `floor.js` `computeFloor`, `createExclusionPredicate`, `sanitizeSamplePath`), exported from `@qmentisai/shared`. `packages/infra/src/scm/github/changed-files.js` (pure parsing, the single place where `patch` and the other fields are dropped) and `listChangedFiles` in `client.js` (the fresh-token mint is now the shared `mintRepositoryToken`, used unchanged by `openSourceSession` with `contents: read`). `apps/workers/src/execution/decision/` (`change-detection.js` `detectChanges`, `floor.js` `decideFloor`, `index.js`), `scanDecision` in `apps/workers/src/config.js` (`SCAN_DECISION_SECRETS_RULE`, `_MAX_CHANGED_FILES` default and maximum 3000, `_MAX_PAGES` default and maximum 30, `_SAMPLE_PATHS` default 20), documented in `apps/workers/.env.example` and **not wired**: the orchestrator does not call `decideFloor` (part E does). Suite: `apps/api/test/security/helpers/change-detection-checks.js`, the compare and pull-request-files endpoints of `github-stub.js`, `w.makeGitHub` in `orchestrator.js`.

**Shapes.** `listChangedFiles({ externalInstallationId, repository: { fullName }, kind, baseSha, headSha, pullRequestNumber, maxFiles, maxPages, signal })` returns `{ status: complete | truncated | unavailable, source: github_compare | github_pull_files, files: [{ path, previousPath | null, status, additions, deletions }], reason }`; it never throws, and `files` is empty unless `complete`. `detectChanges` adds `not_needed` / `none` for a full run (no API call) and maps everything else fail closed. `decideFloor` returns `{ diff: { source, status, reason, changedTotal, summary }, secretsRule, floor: [{ scanType, ruleIds }], notSelected: [{ scanType, reason }], zeroScan }`; `summary` is `{ total, byClass, byStatus, additions, deletions, samples }` (all classes and statuses always present, so the shape is stable).

**Decisions made while building (all inside the approved SPEC and AP-1..AP-7):**
1. **Reason codes** of the adapter are stable lower-case strings (`base_missing`, `base_all_zeros`, `invalid_sha`, `invalid_pull_request`, `not_found`, `access_denied`, `rate_limited`, `server_error`, `unexpected_status`, `unreachable`, `aborted`, `invalid_response`, `response_too_large`, `compare_file_cap`, `file_cap`, `page_bound`, `token_unavailable`, ...). They carry no GitHub text. `diff.source` is `unavailable` whenever the status is `unavailable` (the table value of 7.2), otherwise the API that answered.
2. **A truncated or unavailable diff carries no file list and `changedTotal` 0.** The summary is then all zeros; T-29 (part F) must show the status, not "0 files changed".
3. **Trigger mapping.** `pull_request` uses the pull-request files API of the BASE repository registered for the pipeline (a fork pull request is read through it with the base installation token; the head repository is never used). Every other trigger (`push`, and `manual`/`schedule` whenever a base exists) uses compare; no base is `unavailable` **before any request** (no token is minted either). Unknown scan kinds are `unavailable`, never a reason to call GitHub.
4. **Token.** A fresh installation token per `listChangedFiles` call, restricted to the one repository with exactly `contents`, `pull_requests` and `metadata` read (the fetch step's token is unchanged: `contents: read`), minted inside the per-installation serial queue, held in a local variable, never cached, dropped in `finally`. It is sent only in the `Authorization` header; redirects are refused (`redirect: "error"`; a renamed repository's 301 is `unavailable`, never followed with the token). The response body is read with a 32 MiB bound.
5. **Truncation rules.** Compare: the number of files is `min(maxFiles, 300)` or more. Pull-request files: `min(maxFiles, 3000)` or more, or a full page 100 at the page bound (`min(maxPages, 30)`). "N or more" is truncated also for a configured bound: a list of exactly the bound is not accepted as complete (the exact end of a list cannot be told from a cut one).
6. **Floor details.** Files with status `unchanged` are kept in the counts; they count for FL-1 (a manifest "in any status") and are ignored by FL-2, FL-3 `any_change` and `strict` (FL-3 says unchanged is ignored). FL-2 treats a renamed or copied file as code when its previous **or** new path is code. An unknown `secretsRule` value behaves as `strict` (the wider mode), an unknown file status as `changed`, a malformed entry is counted (never silently dropped). `zeroScan` is `floor.length === 0`: it covers FL-6 (empty or fully excluded set) and also a non-empty set that selects nothing (for example a removal-only code change under `any_change`, SPEC 5.6 "a floor of nothing"); part E decides the zero-scan **outcome** only after the agent's additions. A rename is dropped by the exclusions only when **both** paths are excluded. The exclusion predicate duplicates the three lines of the scan handler's `exclusionOf` (same `matchGlob`, same directory form); a path longer than the matcher's 512 characters never matches an exclusion, so it stays in the list (the safe direction). Making the scan handler import the shared predicate is a later cleanup.
7. **Samples** are produced only when a `redact` function is injected (`decideFloor` injects the platform's `redactLogText`); without it `samples` stays empty (fail safe). Each sample is control-stripped (C0, C1, DEL, U+2028/9), cut at 300 and redacted, never any patch text. The adapter already strips control characters, so the floor's own stripping is defence in depth and is checked on its own in `DEC-S04a`.
8. **Logging** (SD-10): execution ids, statuses, reason codes, counts and durations only; never a path, a file list, a patch or a token (`DEC-S04a` greps the log lines).
9. **Classification lists** are a superset of the examples in 5.3 (more code extensions such as `cc cxx hpp mm vue svelte dart groovy ps1 bash zsh`, `kts`, `sol`); they are all in `constants.js` and are Recommended, reviewable data. `requirements*.txt` and the other manifests match by base name, case-insensitively; `requirements/dev.txt` is documentation by its extension (as written in 5.3). Dotfiles that match no other class are configuration.

**Suite (ADR-008 amended, count 727 to 732).** `DEC-S07a..d` and `DEC-S04a`, see the ADR. The floor's file-to-scan table is deliberately not in the suite. **Mutation sweep** (SECURITY_SUITE_ONLY, mutate in place with backups, run `DEC-S07|DEC-S04a`, restore, `diff` against the pristine copies): 16 mutants, all killed in the end. Killed on the first run (13): truncated/unavailable mapped to an empty floor (`DEC-S07a..d`), compare threshold `>` 300 (`DEC-S07b`, `DEC-S07d`), full-run diff skip removed (`DEC-S07c`), floor not intersected with the enabled types in both places it is enforced (`DEC-S07d`), `patch` kept in the result (`DEC-S04a`), token appended to the URL (`DEC-S04a`), token put in a reason (`DEC-S04a`), 404 treated as an empty list (`DEC-S07a`), pull-request files path built from the fork repository (`DEC-S04a`), base all-zeros check removed (`DEC-S07c`: the stub saw a request), page bound reported as complete (`DEC-S07b`), token permissions widened (`DEC-S04a`), sample paths not redacted (`DEC-S04a`). Three survived the first run and were turned into checks: pull-request cap `>` instead of `>=` (equivalent for the default bound because the 30th full page also truncates; real for a configured bound, killed by the new "exactly the bound" case in `DEC-S07b`), control characters kept in samples (the adapter strips them first; killed by the direct pure-floor case in `DEC-S04a`), redirect followed (new stub redirect fixture in `DEC-S07a`). Not mutated, by design: the Secrets `strict` / `any_change` swap and the rest of the rule table (out of the suite's scope).

**What is NOT verified.** Everything above ran against the local stub, which answers in GitHub's documented shapes (including the 300-file compare cap, 3000/100 pull-request pages, `Link` headers and a `patch` on every file). Not run against real GitHub (stays a risk until the live test of part G): a compare with exactly 300 files or a pull request with more than 300 and with 3000 files, the real `Link` and last-page behavior at the page bound, rate-limit `403`/`429` answers and `retry-after`, a binary file (no `patch`; the adapter does not need one), a renamed or copied file with `previous_filename`, a file path with unusual Unicode, a 301 for a renamed repository, and the unverified verbatim page-2 limits noted in 17.a. The `SCAN_DECISION_*` settings are read and validated but nothing consumes them yet; the integration with `preparing` (token lifetime next to the fetch step, lease heartbeat during the call, cancellation) is part E.

### 17.d Part D as built: the decision agent, the bounded loop and the decision function (2026-11-17)

Part D of the owner's lettering is the agent harness, the agent and the function that combines them with the floor. What exists after this commit, and nothing of parts E to G (no `scan_decisions` table, no event, no orchestrator call, no zero-scan path, no API or UI): the orchestrator does **not** call `decideScans`; the `SCAN_DECISION_AGENT_*`, `SCAN_DECISION_MAX_TURNS`, `SCAN_DECISION_CONTEXT_PATHS` and `LLM_*` worker settings are read and validated and nothing consumes them yet.

**Files.** `packages/infra/src/llm/harness.js` (`runBoundedToolLoop`, exported from `@qmentisai/infra`); `apps/workers/src/execution/decision/` `prompt.js` (the fixed system prompt, one reviewable file), `agent.js` (`runDecisionAgent`, `buildAgentContext`, `createDecisionValidator`, `sanitizeModelText`), `decide.js` (`decideScans`, the pure `finalizeTypes`), `runtime.js` (`createDecisionAgentRuntime`); `scanDecision.agentTimeoutSeconds`, `maxTurns`, `contextPaths` and `config.llm` in `apps/workers/src/config.js` (documented in `apps/workers/.env.example`). Suite: `apps/api/test/security/helpers/decision-agent-checks.js`.

**Shapes.** `runBoundedToolLoop({ provider, system, userData, tools, maxTurns, timeoutMs, maxOutputTokens, signal, validate, logger })` returns `{ status: ok | timeout | error | invalid_output | aborted, value?, text, usage: { inputTokens, outputTokens, latencyMs, turns }, provider: { id, model } | null }` and never throws for a model or provider failure. `runDecisionAgent(...)` returns `{ agentStatus, provider, model, additions: [{ scanType, reason }], summary, usage }`. `decideScans(...)` returns `{ diff, secretsRule, floor, agent: { status, provider, model, additions, summary, usage }, finalTypes, notSelected, zeroScan }`, the object part E persists; `notSelected` is recomputed after the additions (enabled types not in `finalTypes`, reason `no_matching_changes`).

**Decisions made while building (all inside the approved SPEC, ADR-013 and AP-1..AP-7):**
1. **AG-3 reading.** "One tool per addable type" is implemented as ONE tool `request_scan({ scanType, reason })` whose `scanType` enum is exactly the addable set (enabled types outside the floor). The model is offered nothing else; a call to any other name, or a type outside the enum, invalidates the whole output. The effect is the one AG-3 wants (a closed set of requestable scans and no other capability) with one schema instead of N.
2. **Order of the checks (AG-1)**, each returning before anything is contacted: fork (`skipped_fork`, `resolveProvider` is not even called), nothing addable (`nothing_to_add`), provider resolution (`not_configured`, `consent_required`; the resolver's `key_missing` is reported as `not_configured` and the real resolver status is logged), then the loop. The tenant id passed to the resolver is the one the caller loaded from the database; the model context carries no identifier or name of any tenant, user, workspace, repository, pipeline or execution.
3. **Context (AG-2)** is built from named fields only: scan kind and reason code, addable types, floor types with rule ids, counts by class and status, additions and deletions totals, the diff status, and at most `SCAN_DECISION_CONTEXT_PATHS` of the part C sample paths (each stripped, cut at 300, redacted again; a path that still looks like a credential is dropped). It is asserted free of credential shapes before the call. It is sent as one JSON object in the single user message.
4. **Validation (AG-5)** is whole-output-or-nothing with a strict Zod schema in the worker (the harness takes a plain `validate` callback because `packages/infra` has no Zod dependency): the only tool is `request_scan`, strict input, type in the addable set, reason 1 to 300 characters, unique types, at most as many calls as addable types, text (the optional summary) at most 1000 characters. `decideScans` re-checks the additions against the floor and the enabled set before merging (second line); a failure there discards the whole agent output (`invalid_output`).
5. **Accepted text (AG-6).** Reasons and summary are control-stripped, credential-redacted (`redactLogText`), whitespace-collapsed plain text. The raw prompt and answer are never stored or logged.
6. **Loop semantics.** At most `maxTurns` provider calls (default 3, maximum 5), temperature 0, `maxOutputTokens` 1024, one `AbortSignal.timeout` shared by all turns and combined with the caller's signal. The tool calls of every turn are collected; after a turn with tool calls the harness answers with one `toolResultMessage("tool_calls", { recorded: n })` and asks again, so an accepted addition costs a second provider call; the loop ends at a turn without tool calls or at the cap. A model that repeats the same call after the tool result produces a duplicate and therefore an invalid output (floor only): safe, but a possible loss of an addition with a chatty model (to observe in the live test). A failure in any turn discards what earlier turns collected.
7. **Status mapping.** Harness `ok`, `timeout`, `error`, `invalid_output` map to the same agent status, `aborted` to `cancelled`. A provider answer the adapter cannot parse (for example malformed tool-call JSON, or a vendor answer that is not JSON) is reported as `invalid_output`, not `error`; both mean floor only. `interrupted` is part E.
8. **No exception out of the decision.** `runDecisionAgent` lets a throw of `resolveProvider` or of the context builder propagate; `decideScans` is the boundary and turns any exception into `agent.status = "error"` (floor only). A failure of the deterministic part stays fail closed in part C (`decideFloor`).
9. **Bounds in the worker configuration.** `SCAN_DECISION_AGENT_TIMEOUT_SECONDS` (default 20, validated to be below `EXECUTION_LEASE_TTL_SECONDS`), `SCAN_DECISION_MAX_TURNS` (default 3, maximum 5), `SCAN_DECISION_CONTEXT_PATHS` (default 100); the pipeline worker also reads the `LLM_*` variables through `readLLMConfig` (`config.llm`, names-only problems); the scan worker reads none (ER-5). The suite world sets the agent timeout to 3 seconds because its lease TTL is 4.
10. **Runtime factory.** `createDecisionAgentRuntime({ db, config, env, logger })` builds `resolveProvider` from `resolveLLMProvider`, the `createLlmConsentGate(createTenantLlmSettingsRepository({ db }))` port and the platform secret provider `createEnvPlatformSecretProvider`, the one the pipeline worker's GitHub adapter uses. **Production refuses the environment secret provider** (ADR-009; no KMS/Vault adapter exists): with `NODE_ENV=production` and a hosted provider the factory throws, so Anthropic and OpenAI cannot be used in production yet; a local Ollama and `LLM_PROVIDER=none` are fine. A hosted provider with a missing key is logged by variable name and resolves to `not_configured`.

**Suite (ADR-008 amended, count 732 to 739).** `DEC-S01a` (hostile model through the real Ollama, Anthropic and OpenAI adapters), `DEC-S01b` (the pure merge, exhaustively), `DEC-S01c` (the harness with plain-object providers), `DEC-S02`, `DEC-S03`, `DEC-S04b` (agent extension of `DEC-S04`), `DEC-S10g`. They reuse the part C GitHub stub, fixtures and capture logger (`change-detection-checks.js` now exports them) and the part B consent repository; the scripted model stub is new because the part B stub answers fixed bodies. Prompt wording and model quality are not tested. **Mutation sweep** (SECURITY_SUITE_ONLY `DEC-S01|DEC-S02|DEC-S03|DEC-S04|DEC-S10g`, mutate in place with backups, restore, `diff` against pristine copies): 34 mutants, 32 killed on the final run, 2 survivors proven equivalent. Killed: the merge using only the agent set (`DEC-S01a/b`, `DEC-S02`..), not intersected with the enabled types (`DEC-S01b`), tool enum widened (`DEC-S01a`), schema accepting any type (`DEC-S02`, agent alone), valid items applied from an invalid output in two places (`DEC-S01a`, `DEC-S02`), duplicates allowed, `.strict()` removed, summary cap removed, fork check removed (`DEC-S04b`), nothing-to-add check removed (`DEC-S01a`), consent status ignored or the resolver status ignored (`DEC-S10g`), turn cap removed (`DEC-S01c`, `DEC-S03`), early end of the loop removed, timeout removed or restarted per turn (`DEC-S03`, `DEC-S01c`), abort not honoured (`DEC-S03`), context with the execution id, tenant id, head repository or author (`DEC-S04b`), path cap removed (`DEC-S04b`), reason redaction and control stripping removed (`DEC-S01a`), the exception not caught in `decideScans` (`DEC-S03`), prompt or answer text logged (`DEC-S01c`, `DEC-S04b`), abort mapped to error, temperature removed, validate failure or throw treated as ok (`DEC-S01c`), resolver called before the fork check (`DEC-S01a`, `DEC-S04b`). First-run survivors turned into checks: schema accepting any type (masked by the second line; killed by the new agent-alone cases), resolver status ignored (new refusal-status case), early loop end and turn cap (the redundant `break` was removed from the harness, then the cap mutant was killable), the shared deadline (the overall-timeout case now has a second turn whose late answer must not be accepted), abort mapped to error (new late-answer-after-cancel case), validate verdicts (new `DEC-S01c`), path cap (new whitelist case). **Equivalent survivors (2):** (a) the "more calls than addable types" early exit: every call must name a distinct type from the addable set, so more calls than addable types is already impossible without a duplicate or an out-of-set type (pigeonhole); it only saves work; (b) the second-line addition check in `decideScans`: the validator guarantees what it re-checks, so it cannot be reached through the public functions (it exists so a future change to the validator cannot widen the final set).

**What is NOT verified.** No real vendor was called: the adapters, the tool-call formats of Anthropic, OpenAI and Ollama, the behavior of any real model after a tool-result turn (does it stop, or repeat the call, which would make the output invalid, see 6), token usage accounting, latency, rate limits and vendor error bodies, and the quality of the additions are all unverified until the live test of part G. The prompt text is a first version; its effect on a real model is untested. The platform-secret path was exercised only with the environment provider. The agent has not run inside `preparing` (lease heartbeat during the call, cancellation from the execution, token lifetime) because part E is not built.

### 17.e Part E as built: the decision inside the Executions `preparing` state (2026-11-17)

Part E is the integration: the orchestrator now decides, records and creates the tasks of the decided types only. What exists after this commit, and nothing of parts F and G (no T-29 section, no live test): the decision step has **no feature flag of its own** (it runs whenever the orchestrator runs, by the owner's approval); with `LLM_PROVIDER=none` the decision is the floor.

**Files.** Migration `packages/db/prisma/migrations/20261118100000_scan_decisions` (**not applied to the development database by this work**) and the Prisma model `ScanDecision` (`packages/db/prisma/schema/executions.prisma`). `packages/db/src/executions/decisions.js` (`createScanDecisionRepository`: `findDecision`, `hasDecisionStarted`, `markDecisionStarted`, `insertDecision`, `recordDecisionCompleted`, `finishZeroScan`), `createDecidedTasks` in `tasks.js`, `scan_decisions` in the retention purge, `canReleaseQuotaOnTransition(from, to, reason)` and `NO_APPLICABLE_SCANS_REASON` in `@qmentisai/shared`, the event types `decision_started` and `decision_completed`. `apps/workers/src/execution/orchestrator.js` (the decision step and the zero-scan ending), `decideScans({ interrupted })`, `decisionRuntime` injected by `apps/workers/src/execution/index.js` (`createDecisionAgentRuntime`), audit action `execution.decision_completed`, producer `decisionCompleted`. Hint message `pipeline.execution.decision_completed` (`packages/contracts`, ownership check in `apps/workers/src/ownership`, relay `execution.decision` in `apps/api/src/realtime` to the workspace and execution rooms). API: `decision` in `GET /executions/{id}` (`toDecisionDto`, `findDecision` in the module repository, response schema), contract snapshot regenerated (`docs/api/`). Suite: `apps/api/test/security/helpers/decision-integration-checks.js`, `DEC-S06c` and `DEC-S13` in `exec-http-checks.js`, `DAL-302..311` in `direct-repos.js`.

**The flow as built (5.1, 5.7).** After the archive is stored and extracted and before any task exists: (1) a `scan_decisions` row exists: reuse it (no diff, no model); (2) no row but a `decision_started` event: the previous holder died, recompute the floor (the diff call, no model), agent status `interrupted`, `decideScans({ interrupted: true })` does not even resolve a provider; (3) neither: write `decision_started` (a lease-fenced, insert-only event, empty details) BEFORE the diff or the model is contacted, run `decideScans` with the `AbortSignal` of the preparation (lease loss, cancel, deadline), the heartbeat keeps running. Cancel and lease are checked before the call, after it and inside the unit. The same holder keeps the decision it made if the step is retried after a transient failure (`entry.decision`), so a retry never reads its own marker as a dead holder. Then ONE transaction fenced by the lease epoch: the fence (a shared lock on the execution row), the cancel check, `scan_decisions` insert, `decision_completed` event (floor, added, final, agent status, provider, model, summary cut at 500 characters, diff status, changed total; 4 KiB bound by the table), the audit entry `execution.decision_completed`, then either the tasks (`createDecidedTasks`, unsupported ones marked as before, `preparing -> running`, `started`, `status_changed`, the decision hint, the first dispatch) or the zero-scan ending. Execution-log lines (`decision`, `no scan applicable`) are written before the unit because a terminal execution accepts none.

**Decisions made while building (all inside the approved SPEC and AP-1..AP-7):**
1. **Zero-scan path chosen: `preparing -> running -> succeeded` in one transaction, the same lease epoch, two transition events. The state graph is unchanged** (`preparing -> succeeded` does not exist and was not added). It needed ONE narrow change to `executions_guard` (record, as requested): the quota release was allowed only for `queued -> cancelled`, `preparing -> cancelled`, `preparing -> failed`. The function is replaced with one block changed: a release is also accepted for `running -> succeeded` **with the reason `no_applicable_scans`**, and that reason is accepted only from `running -> succeeded`, with a `scan_decisions` row whose `final_types` is `[]`, no `scan_tasks` row for the execution, `task_counts.total = 0` and the unit given back in the same statement when one was taken. `canReleaseQuotaOnTransition(from, to, reason)` mirrors it (two-argument calls still answer for the table only); `EXECDB-011`, `EXECDB-018` and `DECDB-02` cover both. The release is still the compare-and-set plus `quota_released_at` (exactly once); no other ending gained a refund.
2. **`executions_status_reason_check`** is replaced: the six statuses that need a reason still do; `succeeded` may carry NULL or exactly `no_applicable_scans`; every other status carries none; and `no_applicable_scans` is valid on `succeeded` only.
3. **`execution_events.type`** accepts `decision_started` and `decision_completed` (`EXECUTION_EVENT_TYPES` in `@qmentisai/shared` follows; `recordEvent` still refuses `transition`). The history API returns the rows with type and reason only (no details).
4. **FT-6 verified:** no constraint assumes contiguous `scan_tasks.ordinal` (the table has `ordinal >= 0` and a non-unique index `(tenant_id, execution_id, ordinal)`; `queuePending` orders by it). The ordinal is now the **catalog position** (`sbom` 0, `sca` 1, `sast` 2, `secrets` 3) everywhere, including full runs with fewer enabled types (before: the index among the enabled types); no existing check depended on the old values.
5. **`scan_decisions` guards (7.2).** Composite tenant-safe foreign key to `executions`, unique `(tenant_id, execution_id)`, insert-only (update refused, truncate refused; the retention purge deletes it with its execution), a `BEFORE INSERT` trigger that validates the JSON shapes itself (a trigger runs before the CHECKs) and requires: execution `preparing`; scan kind and trust equal the execution's; sets of known unique catalog types; floor inside the enabled types of the snapshot; additions disjoint from the floor and only with agent status `ok`; `final = floor union additions` in catalog order (stricter than 7.2's "contains the floor"); `final` and `not_selected` together exactly the enabled types; CHECKs for the enumerations, lengths, diff source/status consistency (`not_needed` iff `none` iff a full run; `unavailable` iff source `unavailable`; total only for a complete diff) and a credential-shape CHECK over every text-bearing column (the shapes of `execution_logs`, plus `sk-` keys).
6. **`createDecidedTasks`** reads the final set from the PERSISTED record (by tenant and execution) and refuses a spec outside it, a decided type without a spec and a missing record: the orchestrator cannot create a task the decision did not select even by mistake. `finishZeroScan` refuses any existing task.
7. **Early failure kept:** when no enabled type has a registered engine (17.ab) the execution still fails before the fetch with `unsupported` tasks for every enabled type and **no decision record** (nothing was decided); the detail then shows `decision: null`.
8. **Aggregation (FT-3) verified, no code change:** `aggregateTaskOutcome` and `isResolutionEligible` run over the created tasks, a type without a task is not a failure, an incremental run is never eligible, a full run has a task for every enabled type (`DEC-S12`).
9. **Zero-scan details:** the `started` message is sent with `taskCount 0` (the execution did enter `running`), then `status_changed` running, the single `completed` message (`statusReason no_applicable_scans`, `resolutionEligible false` forced in the payload builder, no tasks) and `status_changed` succeeded; one `execution.started` and one `execution.succeeded` audit entry (`quotaReleased true`); the archive is deleted after the commit as for every terminal ending.
10. **Fork (`untrusted_fork`):** floor-only (`skipped_fork`, zero model requests, no provider resolved), the diff uses the installation token as in part C, tasks go to `scan-untrusted`, no credential in any decision surface (`DEC-S12`). An incremental run whose diff cannot be read (no base, 404, 403, truncated) gets the full floor (fail closed, 17.a).
11. **Hint:** `pipeline.execution.decision_completed` carries `executionId`, `workspaceId`, `pipelineId` and `rev` (the status revision after the unit), strict schema, ownership check `executionInChain`, relayed as `execution.decision` to the same two rooms as `execution.changed`; no model text travels.
12. **DTO (8):** exactly the documented shape through an allowlist mapper (catalog-ordered `scanTypes`, states `required`/`added`/`not_selected`/`not_enabled`, `taskId` when a task exists, usage without the turn count); the required-rule reason texts are not in the API; `statusReason: no_applicable_scans` is documented on the response schema and in the OpenAPI snapshot.

**Existing checks.** No expectation of an existing check changed and no assertion was weakened. The suite world's executions are **full** scans, whose floor is every enabled type, so `EXE-0xx`, `SBOM`, cancel/retry and the other fixtures run unchanged; its fork fixtures are incremental with no stubbed pull-request files, which fails closed to the full floor, so `EXE-019/048/071` keep their intent. Only the enumerations that a new table, message type and repository must join were extended: `EXECDB-026` (table `scan_decisions`), `EXE-074` (the message sample), `EXE-076` (repository `decisions.`), the realtime hint list of the credential sweep in `exec-audit-checks.js`, and the response allowlist `DETAIL_KEYS` of `EXE-066` (`decision`).

**Suite (ADR-008 amended, count 739 to 766).** `DEC-S05a` (reclaim with a persisted record: zero model requests, zero diff requests, the recorded set), `DEC-S05b` (marker only: floor recomputed, zero model requests, `interrupted`, task set equal to a no-provider run), `DEC-S05c` (a holder that dies while the diff is in flight has already written the marker), `DEC-S05d` (a transient retry keeps the decision: one decision's two provider requests), `DEC-S06a` (data layer tenant and chain scope, the hint's ownership and contract), `DEC-S06c` (over HTTP: another tenant and a user without a role in the workspace get the 404 of a missing id, read-only roles and Admin get the decision), `DEC-S08a` (a failure injected at each of six steps leaves none of the unit; a cancel during the diff and just before the unit open leave no record), `DEC-S08b` (a zombie whose lease was taken during the diff, and a stale epoch on every decision write, write nothing), `DEC-S08c` (a deadline during the diff leaves no record), `DEC-S09a` (the zero-scan ending in full), `DEC-S09b` (exactly one refund under eight reclaimers and a racing cancel), `DEC-S12` (tasks only for the decided types, ordinals with gaps, not selected is not partial, fork), `DEC-S13` (the DTO allowlist and no leak), `DECDB-01..04` (the table guards, the CHECK amendment and the release branch, the events, the retention purge) and `DAL-302..311`. The full run after this work: 785 tests passed (766 checks, controls and the integrity test), three times in a row. The ids `DEC-S05`, `DEC-S06`, `DEC-S08`, `DEC-S09` of 14.1 are split into lettered checks as in earlier parts. The floor's rule table is not tested (feature behavior, live test).

**Mutation sweep** (SECURITY_SUITE_ONLY, mutate in place with backups, restore, `diff` against pristine copies): 51 mutants, 50 killed on the final run, 1 survivor proven equivalent. Mutated: decision reuse removed (`DEC-S05a`), the interrupted path calling the model (`DEC-S05b/c`), the `decision_started` marker not written (`DEC-S05c`, `DEC-S09a`), the record inserted outside the unit (`DEC-S08a`), tasks for all enabled types instead of the final set, with and without the repository check (`DEC-S12`), the floor type lost from the decided set (`DEC-S12`, `DEC-S05a..d`), the quota unit given back twice (`DEC-S09a/b`) and not at all (`DEC-S09a`), zero-scan `resolutionEligible` true (`DEC-S09a`), zero-scan creating a task (`DEC-S09a`), the cancel check inside the unit removed and all three safe points removed (`DEC-S08a`), the post-decision abort check removed (`DEC-S08c`), the fork reaching the model (`DEC-S12`), not selected counted as partial (`DEC-S12`), the same-holder decision cache removed (`DEC-S05d`), the lease fence removed from the record insert and from the task creation (`DEC-S08b`), tenant predicate removed from `findDecision` and `hasDecisionStarted` and the parent chain ignored (`DEC-S06a`, `DAL-303`), the zero-scan no-task guard removed (`DEC-S09a`), the DTO leaking the record id, the tenant id, the turn count (`DEC-S13`) and a not-selected type shown as required (`DEC-S13`), the API repository ignoring the workspace of the chain (`DAL-310`), the retention purge forgetting decisions (`DECDB-04`), the hint's ownership check removed (`EXE-074`), the shared release rule widened (`DECDB-02`, `EXECDB-018`), and eighteen migration mutants (final must contain the floor, additions inside the floor, the preparing-only guard, the insert-only trigger, the credential CHECK, the release branch widened to any `running -> succeeded`, the decision / no-task / quota-taken requirements of the zero-scan ending, any reason on `succeeded`, the reason on other statuses, final holding an unexplained type, the enabled-set rule, the event type, the composite foreign key, the scan kind and trust equality, the unique index, additions without status `ok`; `DECDB-01..03`, `EXECDB-011`). Survivors of the first run turned into checks or fixes of the sweep itself: the floor-containment guard was shadowed by the "neither floor nor addition" guard (new case with a floor type missing from an otherwise valid final set, `DECDB-01`), the repository's own no-task refusal of the zero-scan ending was masked by the trigger (new assertion on the repository error, `DEC-S09a`), and the API repository's chain mutant was missed only because the sweep filter named the wrong `DAL-` ids (killed by `DAL-310`). **Equivalent survivor (1):** `insertDecision` reading the execution row without the tenant: the lease fence at the top of the same function already requires the row of exactly this tenant, execution and epoch, and execution ids are primary keys, so the tenant-free lookup can only return the same row. Restored; `diff` against the pristine copies is empty for all nine mutated files.

**What is NOT verified.** Everything ran against the local GitHub stub, a scripted Ollama-shaped model stub and the disposable database; the migration was applied only to the suite's database (the owner applies it to `qmentisai`). Not run: a real GitHub compare or pull-request files answer inside `preparing`, a real model (the adapters are still unexercised against the vendors, 17.b and 17.d), the heartbeat and the abort of a real 20 s model call under a real broker, the `execution.decision` hint through a live RabbitMQ and Socket.IO session (the contract, the ownership check and `buildHint` are checked; the consumer path is the existing one), the lease TTL against the 20 s agent timeout in a deployed configuration (validated by the worker configuration), and T-29 (part F). The pipeline worker builds the decision runtime when it builds the orchestrator, at start: a hosted provider with `NODE_ENV=production` makes the worker refuse to start (17.d item 10); a local provider and `LLM_PROVIDER=none` are fine.

### 17.f Part G as built: closing checks, the changer name on the consent card, the completeness audit and the final mutation sweep (2026-11-18)

Part G adds no feature except one display field. It closes the module: an audit of the suite against sections 8, 11 and 14.1, the checks that audit found missing, one consolidated mutation sweep over every tenant-scoped function of the module, the live test plan (`LIVE_TEST_PLAN.md`) and the ADR-008, README, tracker and open-decision updates. **No migration.**

**1. The changer name (contradiction of SCREENS 3b/9, resolved).** `GET`/`PUT /settings/ai` now carry `consentChangedBy`: `{ displayName }` or `null`. Never a user id, never an email, no other key (`.strict()` response schema, allowlist mapper). `findConsentChangedBy({ tenantId })` in `createTenantLlmSettingsRepository` reads the tenant's settings row by the trusted tenant id, then the user by that row's `updated_by_user_id` **and** a membership of the same tenant (any status, so the history stays true after a removal). A user of another tenant (a row that somehow names one), a deleted user (the column is `SET NULL` on delete) or no change yet give `null`. The PUT answer is read inside the same transaction. The card reads "last changed <time> by <name>". Checks: `DEC-S11c` (exactly five DTO keys, `null` without a row), `DEC-S11d` (the mapper keeps only `displayName` even when handed an id and an email), `DEC-S11k` (the name equals the caller's, no id or email in the body, a changer from another tenant reads `null` and its name never appears, no changer reads `null`, control: the own tenant's user is shown), `DAL-312` and `DAL-313` (the function with another tenant's id, and a settings row of tenant Y that names a user of tenant X). The contract snapshot was regenerated: the diff is the `consentChangedBy` property (nullable object, `displayName` required, no additional properties) in the two `/settings/ai` responses and the `dataShape` text, nothing else.

**2. Completeness audit.** Each requirement of sections 8 and 11 and of 14.1, with the checks that cover it. "New" marks the checks this part added because the audit found no check for the property.

| Requirement | Covered by |
|---|---|
| 14.1 DEC-S01 floor never reduced, only enabled types | `DEC-S01a` (hostile model through the three real adapters), `DEC-S01b` (the pure merge, exhaustive), `DEC-S01c` (the harness), `DEC-S02`, `DEC-S12` (the database refuses a task outside the decision), `DECDB-01` (final = floor + additions, inside the snapshot's enabled types), `DAL` entries of `createDecidedTasks` |
| DEC-S02 only enabled types, whole output or nothing | `DEC-S02`, `DEC-S01a` |
| DEC-S03 fail safe, the model never fails the run | `DEC-S03` (decision level: no provider, no key, timeout, error, invalid, cancel, throwing resolver), **new `DEC-S03b`** (inside `preparing`: HTTP 500, invalid output, hang and a throwing resolver each leave the EXECUTION `succeeded` with exactly the floor as tasks), `DEC-S10g`, `DEC-S05b` |
| DEC-S04 no credential anywhere | `DEC-S04a` (the diff token: header only, minted per call, per repository), `DEC-S04b` (model request, logs, returned decision, fork), **new `DEC-S04c`** (stored rows of a TRUSTED run that used the diff token and the model: decision, events, audit, outbox, execution log, tasks), `DEC-S12` and `EXE-071` (fork end to end), `DEC-S10c`/`DEC-S10d` (provider keys), `DEC-S13` (DTO) |
| DEC-S05 no second call on reclaim | `DEC-S05a..d` |
| DEC-S06 tenant scope, no identifiers in the request, no cross-tenant cache | `DEC-S06a` (data layer, hint, ownership), `DEC-S06c` (HTTP 404), `DEC-S04b` (identifiers absent from the request), `DEC-S10c`, `DAL-302..311`, `DAL-314`; **new `DEC-S06b`** (two tenants in sequence: same request structure, nothing of the first in the second's request or decision, no conversation/session/store field, source guard against module-level mutable state in the decision and LLM layers) |
| DEC-S07 fail closed on change detection | `DEC-S07a..d` |
| DEC-S08 atomicity, zombie writes nothing | `DEC-S08a..c` |
| DEC-S09 zero-scan, refund exactly once | `DEC-S09a`, `DEC-S09b`, `DECDB-02` |
| DEC-S10 consent gate | `DEC-S10a..g` |
| DEC-S11 consent route family | `DEC-S11a..k`, **new `DEC-S11l`** (serialized concurrent writes: found by the mutation sweep, L4), `DAL-299..301`, `DAL-312..313` |
| DECDB-01 table guards and a `DAL-` entry per new function | `DECDB-01..04`, `DAL-299..314` (and the suite's "every function has a check" enumeration `EXE-076`) |
| 8 DTO shape, no internal field, same scoping and 404 | `DEC-S13` (exact keys, catalog order, states, **`taskId` now asserted**), `DEC-S06c`, `EXE-066` (allowlist), `DAL-310`, `DAL-311`, `DAL-314` (parent chain omitted fails closed) |
| 8/9 the hint: strict schema, ownership check | `DEC-S06a`, `EXE-074` |
| SD-1 untrusted data, only inside a JSON data field | `DEC-S04b` (redacted paths in the request), `DEC-S04a` (control stripping, cap, redaction), `DEC-S07a` (over-long path, bad shape), `DEC-S01c` (one JSON user message). The fixed prompt wording is not tested (AP-7) |
| SD-2 the model never decides alone | `DEC-S01a..c`, `DEC-S02` |
| SD-3 bounded tools | `DEC-S01a`, `DEC-S01c`, `DEC-S02` |
| SD-4 no credentials | see DEC-S04 |
| SD-5 tenant isolation, no memory | see DEC-S06 |
| SD-6 consent | see DEC-S10 and DEC-S11 (the change is audited: `DEC-S11e`, `DEC-S11i`) |
| SD-7 cost abuse: fork, nothing addable, concurrency cap, timeout | fork `DEC-S04b`, `DEC-S12`; nothing addable `DEC-S01a`; timeout `DEC-S03`, `DEC-S03b`; **new `DEC-S03c`** (the per-process cap holds under eight simultaneous decisions, all complete; control: a larger cap does exceed it); configuration validation `DEC-S10f` |
| SD-8 provenance | the DTO carries provider, model and status (`DEC-S13`); the labelling in the UI is not in the suite scope (live test, `LIVE_TEST_PLAN.md` section 7) |
| SD-9 SSRF, the base URL is never tenant-supplied | `DEC-S11g`/`DEC-S11h` (any unknown key in the PUT body, so a URL, is a 400), `DEC-S11c`/`DEC-S11d` (the DTO never names a URL), `DEC-S10e` (no adapter or vendor endpoint outside `packages/infra/src/llm`), `DEC-S10f` (production needs https, no credentials in a URL) |
| SD-10 logs carry no prompt, response, path list or token | `DEC-S04a`, `DEC-S04b`, `DEC-S10d` |
| 5.7/5.8 reclaim, cancel, timeout | `DEC-S05a..d`, `DEC-S08a..c`, `DEC-S09b` |
| FT-2/FT-3/FT-4 tasks only for the decided types, aggregation, quota | `DEC-S12`, `DEC-S09a/b` |

Still not in the suite, stated plainly: the floor rule table (feature behaviour, AP-7), the prompt wording and model quality, the UI labelling and rendering (live test), the realtime hint through a live RabbitMQ and Socket.IO session, a real vendor. These are in `LIVE_TEST_PLAN.md`.

**3. Final consolidated mutation sweep** over every tenant-scoped function this module added: the tenant LLM settings repository (`packages/db/src/llm-settings.js`: `getExternalConsent`, `findSettings`, `setExternalConsent`, `findConsentChangedBy`, the consent gate), the consent resolver (`packages/infra/src/llm/resolve.js`: the gate at resolution and the per-request re-check, the tenant argument, the concurrency cap), the scan decision repository (`packages/db/src/executions/decisions.js`: `findDecision`, `hasDecisionStarted`, `markDecisionStarted`, `insertDecision`, `recordDecisionCompleted`, `finishZeroScan`), `createDecidedTasks` (`tasks.js`), the decision DTO mapper and its API repository and service (`apps/api/src/modules/executions`), and the tenant AI settings service and mapper. Method: SECURITY_SUITE_ONLY with a filter per mutant, the file mutated in place from a backup, restored after every run, `cmp` against pristine copies and `git status` at the end (only the intended changes remain; no process left; the development PostgreSQL, the API and the two web servers were never touched).

Result: **58 distinct mutants. 41 killed on the first pass; 5 more killed after this part added or extended a check because they survived (L4 `DEC-S11l`, D7 `DECDB-03`, M7 `DEC-S13`, X2 `DAL-314`, T4 `DEC-S12`); 12 survivors, all proven equivalent.** In total 46 killed. Killed mutants include: every tenant predicate of the settings, decision and task lookups that can be reached with another tenant; each parent-chain predicate (`workspaceId`, `repositoryId`, `pipelineId`) of `findDecision` (`DEC-S06a`, `DAL-303`, `DAL-310`); the chain guard of the API repository (`DAL-310`, `DAL-314`); the lease fence of `markDecisionStarted`, `insertDecision`, `finishZeroScan` and `createDecidedTasks` (`DEC-S08b`); the no-task guard and the quota release of the zero-scan ending (`DEC-S09a/b`); the decided-set comparison (`DEC-S12`, three variants); the consent gate removed, inverted, bypassed, given an empty tenant, at both places (`DEC-S10a..g`); the concurrency cap removed (`DEC-S03c`); the changer lookup without the tenant, without the membership predicate, with the wrong user (`DEC-S11k`, `DAL-313`); the DTO leaking the tenant id, the record id, the turn count (`DEC-S13`); a floor state shown as something else (`DEC-S13`).

The 12 equivalent survivors (mutant id: proof):
- **D8, D10, D12, D14, D16, T2.** A lookup keyed by the execution id with the tenant predicate removed (`markDecisionStarted` marker lookup, `insertDecision` execution read, the null-event guard of `recordDecisionCompleted`, the task count and decision read of `finishZeroScan`, the decision read of `createDecidedTasks`). Every one runs after `fenceExecution({ tenantId, executionId, leaseEpoch })`, which locks and checks the execution row BY TENANT and throws `LeaseLostError` for any other tenant (`DEC-S08b`, `DEC-S06a`); the execution id is a global primary key, so the unguarded lookup can only see the row the fence already proved is the caller's. The predicates are kept as defence in depth. (`recordEvent` returns `null` only when the execution is missing, which the fence has excluded.)
- **D11.** The `!exec` guard of `insertDecision`: unreachable after the fence; removed, a missing row would be a `TypeError` instead of a `LeaseLostError`, both roll the transaction back.
- **D17.** The application-level "decision with an empty final set" guard of `finishZeroScan`: the database `executions_guard` refuses the `running -> succeeded` release without a decision whose `final_types` is `[]` (`DECDB-02`), so a violation is refused either way.
- **D19, D20.** The `!transitioned` guards of `finishZeroScan`: after the fence the row is locked in the same transaction, so a refused compare-and-set cannot happen; were it to, the next line reads `execution.statusRev` of `null` and throws, rolling back.
- **M8.** `textOrNull` on the provider: differs only for the empty string, which the database refuses (`CHECK char_length(agent_provider) BETWEEN 1 AND 100`).
- **S3.** The `row ?` guard in the settings service `get`: `findConsentChangedBy` returns `null` for a missing row anyway; the guard only saves a query.


**4. Gates and counts after this part.** The suite registers **775 checks (EXPECTED_CHECKS 766 to 775: +1 `DEC-S11k`, +1 `DEC-S11l`, +1 `DEC-S06b`, +1 `DEC-S04c`, +1 `DEC-S03b`, +1 `DEC-S03c`, +3 `DAL-312..314`) and 794 tests** in the last full run (775 checks, the controls and the integrity test; 0 failures). No existing check was weakened; the extended ones (`DEC-S11c`, `DEC-S11d`, `DEC-S12`, `DEC-S13`, `DECDB-03`) only gained assertions, and `DEC-S11c`'s expected key list gained the new field.

**What is NOT verified.** Everything in `LIVE_TEST_PLAN.md`: a real GitHub compare and pull-request-files answer inside `preparing`, a real model on any adapter (including the chatty-model duplicate call), the heartbeat and abort of a real 20 s call under the real broker, the `execution.decision` hint through live RabbitMQ and Socket.IO, T-29 and the consent card in a browser, the migrations on the development database, and kill -9 of the pipeline worker.
