# Module specification: Scan decisioning (Analysis and Scan Decisioning, workflow steps 4 and 5)

**Status:** **Proposed (2026-11-17), for owner review. Nothing is implemented.** Written from the owner brief of 2026-11-17 (the hybrid design below), the closed Executions module (`docs/modules/executions/SPEC.md`, section 17.ai) and the documents named in section 13. Labels follow the repository rule: **Confirmed** = stated by the owner in the 2026-11-17 brief or already Confirmed elsewhere; **Recommended** = my proposal, not binding; **Open** = needs the owner. Nothing Recommended or Open is promoted.

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

Open by the owner's list (section 15): diff source (spike), Secrets rule (strict versus safe), zero-scan outcome, LLM framework (ADR-013), whether to call the agent for trivial changes (cost), per-tenant provider configuration, agent timeout value.

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
| DEC-011 | `untrusted_fork` executions: the diff uses the installation token outside the scan; the scan context is unchanged (no credentials); whether the agent runs for forks is Open (recommended: floor only in v1) | Must | Confirmed (D10); agent for forks **Open** |
| DEC-012 | The execution detail DTO carries the decision; T-29 renders it (section 10) | Must | Confirmed (D12) |
| DEC-013 | The zero-scan outcome (nothing applicable) is defined and visible (section 5.6) | Must | **Open** (recommendation: `succeeded` with the reason `no_applicable_scans`) |

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
| CD-2 | Source (Open, spike): the GitHub **compare** API for pushes and same-repository PRs, the **pull-request files** API for PRs (including fork PRs, where the head lives in another repository). Whether both work on a **private base repository** with the App's current permissions (Metadata, Contents, Pull requests: read; repositories-github SPEC D5), their pagination and file limits, and how a new branch (`before` all zeros), a force push (unreachable `before`) and a tag push behave must be **verified live before implementation** |
| CD-3 | The token is the same repository-scoped installation token minted by the fetch step, used in the worker, in memory only, **never** in the scan context, a message, a log, an event or the decision record |
| CD-4 | Fetched per file: path, previous path (rename), status (`added`, `modified`, `removed`, `renamed`, `copied`, `changed`), additions and deletions counts. **The patch text is discarded at the adapter** and never stored or sent anywhere |
| CD-5 | Bounds: at most `SCAN_DECISION_MAX_CHANGED_FILES` (Recommended 3000) files and `SCAN_DECISION_MAX_PAGES` API pages. Over a bound, or any API error, empty or unparsable answer, or a base that is not reachable: `diff_status = truncated` or `unavailable` and the floor becomes **all enabled** (DEC-009). Never a partial list treated as complete |
| CD-6 | The snapshot's `exclusions.paths` are applied to the list. If every changed file is excluded the changed set is empty (zero-scan case, section 5.6) |
| CD-7 | Repository content, file names, branch names and every string from the API are **untrusted data**: validated by Zod, length-capped, control characters stripped, never executed, never interpolated into an instruction |

### 5.3 The deterministic floor (D4; the rule table is Recommended and reviewable)

File classes (by path, no content read): **manifest** (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `pom.xml`, `build.gradle*`, `Gemfile`, `Gemfile.lock`, `composer.json`, `composer.lock`, `*.csproj`, `packages.config`), **code** (known source extensions: `js jsx ts tsx mjs cjs py java kt go rs rb php cs c h cpp hpp swift scala sh sql ...`), **config** (`json yaml yml toml ini env properties tf` and dotfiles), **docs** (`md rst txt adoc`), **other** (everything else, including binaries and unknown extensions).

| Rule | Adds to the floor | When (incremental) |
|---|---|---|
| FL-1 | `sbom`, `sca` | any manifest file changed, **in any status** (a removed dependency file changes the inventory) |
| FL-2 | `sast` | any **code** file added, modified or renamed (a removed code file alone does not add SAST) |
| FL-3 | `secrets` | Secrets rule `any_change` (default): at least one file added, modified or renamed, of any class. Rule `candidate_files`: at least one added, modified or renamed file that is not **docs** and not an image or other binary class |
| FL-4 | all enabled types | change detection failed, truncated or unavailable (DEC-009) |
| FL-5 | (full run) all enabled types | `scan_kind = full`, no diff, no agent call needed |
| FL-6 | nothing | the changed set is empty (after exclusions): zero-scan case |

Then **floor = rules intersected with the enabled types**. A rule that names a type the pipeline has not enabled adds nothing. The catalog order `sbom, sca, sast, secrets` is kept for the task ordinals.

The two Secrets modes are **named by effect** because the brief's words "strict / safe" are ambiguous (Open, section 15): `any_change` is the safe default for detection, `candidate_files` trades coverage for fewer runs. Setting: `SCAN_DECISION_SECRETS_RULE` (platform, default `any_change`).

### 5.4 The agent (D5, D6; harness Recommended)

| Rule | Text |
|---|---|
| AG-1 | **Called only if** a provider resolves AND at least one enabled type is outside the floor AND the execution is not excluded by the fork rule (Open) AND the trivial-change rule (Open) does not skip it. Otherwise agent status is `not_configured`, `nothing_to_add`, `skipped_fork` or `skipped_trivial` |
| AG-2 | Context (one JSON object, passed as **data**, with a fixed system prompt that says so): scan kind and reason, the enabled-not-in-floor types, the floor types with their rule ids, counts by file class, counts by status, total additions and deletions, and up to `SCAN_DECISION_CONTEXT_PATHS` (Recommended 100) changed paths, each length-capped and passed through the credential-shape redaction. **Never**: file contents, patches, commit messages, PR titles or bodies, branch names of forks, author names, tokens, tenant, user or workspace names or ids |
| AG-3 | Tools: one tool `request_scan({ scanType, reason })` per **addable** type (enabled and not in the floor). The agent has **no other tool**: no repository read, no network, no shell. A call to a name outside the offered tools is invalid output |
| AG-4 | Loop (Recommended): at most `SCAN_DECISION_MAX_TURNS` (3) provider calls, temperature 0 where the provider supports it, `max_output_tokens` bounded, one overall timeout `SCAN_DECISION_AGENT_TIMEOUT_SECONDS` (Open value, Recommended 20 s) bound to an `AbortSignal` that a cancel request also fires |
| AG-5 | Validation (Zod, strict): `additions[]` of `{ scanType in the addable set, reason: string 1..300 }`, unique types, plus an optional `summary` string up to 1000 chars; unknown keys, a type outside the addable set, a duplicate, an over-long string or non-text output make the **entire** output invalid. It is never partially applied (a partially trusted answer from an injected prompt is not trusted) |
| AG-6 | Accepted reasons and summary are model-written **untrusted text**: redacted for credential shapes, stripped of control characters, stored as plain text, rendered as text only (never HTML or Markdown), labelled with the provider and model |
| AG-7 | The raw prompt and raw response are **not stored** (Recommended; retention of prompts is Open). Stored: the validated structured output, provider id, model, token usage, latency, agent status |
| AG-8 | Prompt-injection posture: the worst a hostile file name or any injected instruction can do is add a scan the pipeline already enabled (cost), or fail validation (floor only). It cannot remove a floor scan, add a disabled type, change the scan kind, read other data or call anything else. Safety does not depend on the model behaving |

Agent status values: `not_configured`, `nothing_to_add`, `skipped_trivial`, `skipped_fork`, `ok` (output valid, zero or more additions), `timeout`, `error` (provider failure or abort), `invalid_output`, `interrupted` (DEC-008), `cancelled` (the execution was cancelled during the call). All but `ok` mean **floor only**.

### 5.5 Final task set and the Executions rules it touches (D7, D10)

| Rule | Text |
|---|---|
| FT-1 | `final = floor union validated additions`, restricted to the enabled types, ordered by the catalog |
| FT-2 | Tasks are created **only for `final`** (amends SPEC executions ER-11, which creates one per enabled type). A type in `final` without an engine becomes an `unsupported` task as today (SPEC executions §17.ab). A type **not** in `final` has **no task row**; it appears on T-29 from the decision record as "Not selected" with its reason |
| FT-3 | Aggregation (SPEC executions 5.4) is computed over the **created** tasks. A run whose enabled types are not all in `final` is **not** `partial` for that reason: not selected is not a failure. `resolutionEligible` is unchanged in practice: a full run's floor is every enabled type, and incremental runs are never eligible |
| FT-4 | Quota: unchanged. One unit per execution, taken at request time; the decision step does not change it |
| FT-5 | The scan context, queues (`scan` versus `scan-untrusted`) and credentials rules of SPEC executions ER-5 and ER-7 are unchanged; the decision adds nothing to a task message |
| FT-6 | The `ordinal` of a task is its catalog position. Gaps are expected (for example SAST without SBOM). Whether a database constraint assumes contiguous ordinals is **to verify in part B** |

### 5.6 The zero-scan outcome (DEC-013, Open)

When `final` is empty (an empty or fully excluded change set, or a floor of nothing and no additions), no task exists. Options:

| Option | Behaviour | Trade-off |
|---|---|---|
| A (**Recommended**, the owner's lean) | Execution ends **`succeeded`** with the reason **`no_applicable_scans`**, `taskCounts` all zero, `resolutionEligible = false`, one `decision_completed` event, quota unit **kept** | Clear to users ("nothing to scan"); needs the `executions` CHECK that today forbids a reason on `succeeded` to allow this one reason, or the reason to live on the decision record and DTO only |
| B | `succeeded` with no reason; the decision record and T-29 say "no applicable scans" | No schema change; the reason is less visible in lists and API filters |
| C | `skipped` with `no_applicable_scans` (the enum value and reason column already exist) | No schema change; but `skipped` today means policy skips from the router, and users may read it as "did not run" |

Quota refund for a zero-scan run is **Open** (Recommended: keep the unit; refunds add a second release path and the decision step did run). Findings: a zero-scan run emits `resolutionEligible = false`.

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
| `secrets_rule` | `any_change` or `candidate_files` |
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
| SD-6 | **Data egress consent (Open).** File paths of a private repository leave the deployment when an external provider (Anthropic, OpenAI) is used. Recommended: an external provider is used for a tenant only if the deployment allows it **and** the tenant has accepted it; a local Ollama needs no consent. Until decided, external providers must not be enabled for real tenant data |
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

### 14.1 Security-suite additions (Recommended; needs the owner's approval to extend ADR-008 scope, area 17)

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
| DEC-S09 | **Zero-scan** per the decided outcome, including quota and `resolutionEligible = false` |
| DECDB-01 | Immutability and the table guards of 7.2; `DAL-` entries for every new repository function (the suite's "every function has a check" rule) |

## 15. Open questions (each with a recommendation; none promoted)

| Id | Question | Recommendation |
|---|---|---|
| OQ-1 | **Diff source** (GitHub compare versus pull-request files versus a base archive diff), limits, new branch, force push, tag, private base, fork PR | Spike first (section 16, part A). Recommend compare for push and PR files for PRs; fail closed to the full floor |
| OQ-2 | **Secrets rule** `strict` versus `safe` (the brief's words) | Default `any_change`; offer `candidate_files`; confirm the intended meaning of the two names |
| OQ-3 | **Zero-scan outcome** | Option A (section 5.6), quota unit kept |
| OQ-4 | **LLM framework** | ADR-013 (Proposed): in-house bounded tool-calling loop over `LLMProvider`, no separate Python service; owner decides |
| OQ-5 | **Call the agent for trivial changes?** | Always skip when nothing is addable (DEC-006). A further rule (for example docs-only, or fewer than N files) is Open; Recommended: no extra rule in v1, measure first |
| OQ-6 | **Per-tenant provider configuration** | Deployment-level provider in v1; tenant override and tenant keys later through ADR-013 and the tenant SecretStore, with the consent flag of SD-6 |
| OQ-7 | **Agent timeout value** | 20 s overall, 3 turns, platform settings; tune after the live test |
| OQ-8 | Agent for **fork PRs** | Floor only in v1 (attacker-controlled names, cost abuse); revisit |
| OQ-9 | Patch hunks or file excerpts for the agent | No in v1 (secrets, cost, injection surface); revisit only with a redaction design |
| OQ-10 | Prompt and response retention | Not stored; structured output only |
| OQ-11 | Per-pipeline controls (agent on or off, Secrets rule) in the pipeline editor | Later, as an additive optional field of the strict pipeline configuration schema; a pipelines-module change |
| OQ-12 | Does a retry reuse the original's decision? | No, a new execution decides again |
| OQ-13 | Usage metering or quota for model calls | A usage record only in v1; quota later with the commercial plan decisions |
| OQ-14 | ADR-008 scope extension for section 14.1 | Approve as area 17 coverage |

## 16. Implementation notes (plan, Recommended)

Parts, one commit each, all gates after each, report per part:
- **A. Spike (no code in the product):** verify compare and PR-files on a private base repository for push, same-repository PR and fork PR with the installation token and the current App permissions; record limits, pagination, new branch, force push; confirm the fork PR path. Update OQ-1.
- **B. Floor and records:** shared pure floor function and classifier in `@qmentisai/shared`; migration for `scan_decisions` and its guards; repository functions with tenant scope; DTO mapper; contract snapshot.
- **C. Change detection adapter:** in `packages/infra` GitHub client (new methods, patch discarded), bounds, fail-closed mapping.
- **D. Orchestrator integration:** the `preparing` flow of section 5.1, the one-transaction task creation from `final`, reclaim rules, zero-scan outcome per decision, `decision_started/completed` events, the hint message.
- **E. LLM layer and agent harness:** after ADR-013 is decided: `LLMProvider` in `packages/infra`, adapters, the harness, Zod schemas, redaction, limits, hostile-stub tests in the suite scope of 14.1.
- **F. API and T-29:** detail DTO, the "Analysis and decision" section.
- **G. Suite, mutation sweep over the new tenant-scoped functions, live test** (private base repository, push, same-repository PR, fork PR, no-provider, provider timeout, reclaim during decision), results recorded in the tracker.

Verification items for part B: ordinal gaps in `scan_tasks`; whether the `executions` CHECK on `status_reason` needs the zero-scan amendment; the exact home of `SCAN_DECISION_*` settings (worker config schema, same pattern as `EXECUTION_*`).

## Related documents
`docs/modules/executions/SPEC.md` (5.3, 5.4, 6.3, 6.4, 17.ab, 17.ai), `docs/modules/pipelines-triggers/SPEC.md` (scan kind, exclusions, fork policy), `docs/modules/repositories-github/SPEC.md` (App permissions), `docs/decisions/ADR-009-INTEGRATION-CREDENTIAL-STORAGE.md`, `docs/decisions/ADR-013-LLM-PROVIDER-ABSTRACTION.md` (Proposed), `docs/technical/SECURITY_GUIDELINES.md` (Repository and AI safety), `docs/decisions/OPEN_DECISIONS.md`.
