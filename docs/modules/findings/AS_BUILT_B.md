# Findings, Part B, lifecycle, review, approval, SOD, exceptions, comments, the findings room: as built

**Built:** 2026-11-24 on `4f6693f` (Wave 2, worktree branch `worktree-agent-a37e6df3d8bd3b32a`, not pushed). **Scope:** `SPEC.md` 16.2 row B plus the owner decisions of 0.5 (OD-2 both decisions are approved, OD-8 role bundles already applied by the amendment round). The feature flags are unchanged and still default OFF: with `FINDINGS_INGESTION_ENABLED=false` no finding is created, so the write routes answer from empty tables (404 for any id) and the scheduled expiry job is not enqueued. This part writes its notes **only here** (`SPEC.md` 16.4); Part F folds them into `SPEC.md` 17 and the progress tracker.

**Starts from:** `AS_BUILT_A0.md` (frozen contract), `AS_BUILT_A1.md` (the central `transitionFinding`, the read routes, the findings worker) and the E mock (`apps/tenant-web/src/features/findings/services/findings-api.mock.js`), which defines what the real API returns.

## 1. What was built

### 1.1 The rule the owner made hard: the SERVER computes the per-caller state

`apps/api/src/modules/findings/policies/lifecycle.js` holds two pure functions the read side and the write side share.

- **`computeAllowedActions(facts, can)`** gives `lifecycle.allowedActions` of the finding DETAIL DTO for THE CALLER. Rule (the mock's): an action the caller can **never** take (no key, wrong status, not their review or request) is **omitted**; an action they may reasonably ask for but cannot take **now** is listed with `allowed: false` and a `disabledReason` in plain words (at most 200 characters, absent when `allowed`). The UI renders it and never recomputes it. `can` is the central authorization engine in the finding's workspace; the caller's id is the authenticated user, never a body field.
- **`decideStateOf(...)`** gives `canDecide` and `cannotDecideReason` (`separation_of_duties`, `missing_permission`, else null) of each row of `GET /approvals`.
- The inputs are the effective status (an overdue acceptance reads as `reopened`, EX-3), the pending review's reviewer, the pending exception's requester, the claimant, the assignee, the pipeline's deleted flag, the advisory status, and **`sodUserIds`**: every user who recorded a review (any round) or requested an exception on this finding. `getDetail` of `@qmentisai/db` returns it (one added query); ids are never exposed.

Rules computed (a row of `FINDING_ACTIONS` is listed only when its key is held and its status fits):

| Action | Shown when | Disabled (words) when |
|---|---|---|
| `claim` | `finding.review`; status `new`, or `in_review` claimed by someone else (take-over) | never |
| `record_review` | `finding.review`; `new` or `in_review` | a pending exception exists: "A request is pending for this finding. Decide it first." |
| `withdraw_review` | `finding.review` AND the caller is the pending review's reviewer | never (hidden for anyone else) |
| `approve_review`, `reject_review` | `approval.approve` / `approval.reject`; status `awaiting_approval` with a pending review | the caller is in `sodUserIds`: "You recorded a decision on this finding. Another lead must approve it." |
| `reopen_review` | `finding.review`; `false_positive` or `reopened` | never |
| `assign`, `reassign`, `unassign`, `start_work`, `submit_fix` | the mock's rules (Part C enforces them) | `start_work`/`submit_fix` and not the assignee without `finding.assign`: "You can only move findings assigned to you."; `submit_fix` on a deleted pipeline: "The pipeline was deleted, so no scan can verify a fix." |
| `request_accept_risk`, `request_suppression` | `finding.accept_risk` / `finding.suppress`; one of the six source statuses | a request is pending: "A request is already pending for this finding." |
| `withdraw_exception` | the caller is the pending request's requester | never |
| `approve_exception`, `reject_exception` | approval keys; a pending request | the caller is in `sodUserIds`: "You requested this. Another lead must approve it." (the requester) or the review wording (an earlier reviewer) |
| `revoke_accept_risk`, `revoke_suppression` | the key of the kind; status `accepted_risk` / `suppressed` | never |
| `comment` | `finding.comment` | never |
| `request_advisory` | `finding.review`; `agentRunsOn` (not secrets, not info) | the advisory is `pending`: "Advice is already being prepared." |

Examples (all asserted by `FND-S07c`): a user who holds BOTH review and approval keys and recorded the decision sees `approve_review` `{ allowed: false, disabledReason: "You recorded a decision on this finding. Another lead must approve it." }` and `withdraw_review` allowed; another lead sees both approve and reject allowed with no reason; an analyst who is not the reviewer sees none of the three; Admin (no approval key by default) sees none of approve or reject; a viewer sees an empty list.

### 1.2 Routes (all tenant audience, `Idempotency-Key` accepted, `write` rate limit; reads use `read`)

Every item route loads the finding by TENANT and id and authorizes in ITS workspace (`findingScope`): a hidden workspace, another tenant's finding and an unknown id are one identical `404`; a visible finding without the key is `403`. A body never carries `tenantId`, `workspaceId`, `status` or a user id (the frozen schemas are strict). Request bodies are the frozen shared schemas. **Every write answers with the finding detail DTO as the CALLER now sees it** (the E mock's shape) with a new `ETag: W/"finding-<rev>"`; the comment answers with the comment DTO, the bulk call with `{ results }`. Creates (`reviews`, `exceptions`, `comments`) answer `201`, the rest `200`.

| Method and path | Permission (route) | Request | Notes |
|---|---|---|---|
| `GET /review-queue?workspaceId=` | `security_review.view` | `reviewQueueQuerySchema` | `new` and `in_review`, oldest first (or `sort=severity`); the read service of A1 |
| `GET /approvals?workspaceId=` | `approval.view` | `approvalsQuerySchema` (`kind`, `severity`, `pipelineId`, `page`/`pageSize` or `cursor`/`limit`) | pending reviews and pending exceptions, oldest first; each row has `canDecide`, `cannotDecideReason` for the caller; signed cursor bound to the filters, tenant and workspace |
| `POST /findings/{id}/claim` | `finding.review` | `{ expectedRev }` | SM-2, or an audited take-over of another's claim (no status change, `rev + 1`) |
| `POST /findings/{id}/reviews` | `finding.review` | `{ decision, rationale, severityOverride?, expectedRev }` | SM-3; from `new` two history rows (SM-2 then SM-3); records the latest `ok` advisory id as a reference only (RV-3); `409 exception_pending` while a request is pending |
| `POST /findings/{id}/reviews/{reviewId}/withdraw` | `finding.review` | `{ expectedRev }` | SM-4; only the reviewer (`403 not_reviewer`) |
| `POST /findings/{id}/reviews/{reviewId}/approve` | `approval.approve` | `{ comment?, expectedRev }` | SM-5 (applies the override, recomputes the SLA, audit `finding.severity_overridden`), SM-6 (SLA stops); SOD |
| `POST /findings/{id}/reviews/{reviewId}/reject` | `approval.reject` | `{ comment, expectedRev }` | SM-7; SOD |
| `POST /findings/{id}/reopen-review` | `finding.review` | `{ reason, expectedRev }` | SM-8 (`fp_reopened`) or SM-18 (`rereview`) |
| `POST /findings/{id}/comments` | `finding.comment` | `{ body }` | insert-only; no `rev` change; `201` comment DTO |
| `POST /findings/{id}/exceptions` | `finding.accept_risk` for `kind: accept_risk`, `finding.suppress` for `suppress` (picked from the validated body) | `{ kind, justification, compensatingControls?, expiresAt?, requestedApproverUserId?, expectedRev }` | a pending request; the status is unchanged, `rev + 1` |
| `POST /findings/{id}/exceptions/{exceptionId}/withdraw` | `finding.view`, then the service: the requester | `{}` | `403 not_requester` |
| `POST /findings/{id}/exceptions/{exceptionId}/approve` | `approval.approve` | `{ comment?, expectedRev }` | SM-19 / SM-20; SOD; a request whose expiry already passed cannot be approved (`409 transition_not_allowed`) |
| `POST /findings/{id}/exceptions/{exceptionId}/reject` | `approval.reject` | `{ comment, expectedRev }` | no status change; SOD |
| `POST /findings/{id}/exceptions/{exceptionId}/revoke` | `finding.view`, then the service: the key of the exception's kind | `{ reason, expectedRev }` | SM-21 (user); `403 missing_permission` |
| `POST /findings/bulk/claim` | `finding.review` in the body's workspace | `{ workspaceId, findingIds (1..50, distinct) }` | one transaction per finding; a finding of another workspace or unknown is `{ ok: false, errorCode: "RESOURCE_NOT_FOUND" }`, never forbidden |

Error codes used: `VALIDATION_FAILED` (`details.reason`: `credential_shape`, `override_requires_tp`, `expiry_out_of_range`, `approver_not_eligible`), `FORBIDDEN` (`separation_of_duties`, `missing_permission`, `not_reviewer`, `not_requester`), `RESOURCE_NOT_FOUND`, `FINDING_STATE_CONFLICT` 409 (`stale_revision`, `transition_not_allowed`, `exception_pending`, `already_decided`), `CONFLICT` 409 (`workspace_archived`), `IDEMPOTENCY_CONFLICT`, `RATE_LIMITED`, `INVALID_CURSOR`. (`pipeline_deleted` is Part C's `submit`.)

### 1.3 The write transaction (`services/lifecycle-support.js`, `runFindingWrite`)

Every write is ONE transaction: workspace not archived (`409 CONFLICT workspace_archived`; AUTHORIZATION 5.7) -> the finding row locked by tenant, workspace and id -> checks that decide before the revision (the SOD refusal, the ownership of a review or request) -> `expectedRev` equal to the row's revision AS THE CLIENT SAW IT (`409 stale_revision`) -> an overdue acceptance is expired lazily (EX-3) and the work continues on the refreshed row, so the client's first write after an expiry does not fail on the revision the expiry raised -> the change through `transitionFinding` of A1 with the actor a USER (history row with `actor_type = user`, audit entry, one `finding.status_changed` hint) -> the domain event. Domain errors map to the API's (`FindingNotFoundError` is the identical 404, `FindingConflictError` the 409; no duplicate error class). Secret-shaped text is refused before the transaction (`refuseSecretText`: the frozen schemas refuse the database CHECK shapes; the service additionally refuses the WIDER platform list of `@qmentisai/shared`, `hasSecretShape`).

### 1.4 Segregation of duties, three layers

1. **Service** (`approval.js`, `exceptions.js`): the approver or rejecter must not be in `sodUserIds` (any reviewer of any round, any exception requester of the finding). Not even a custom role holding review and approval bypasses it; Admin has no approval key by default. The refusal is `403 FORBIDDEN / separation_of_duties`, nothing is written, and an audit entry `finding.approval_denied` is written OUTSIDE the failed transaction (so it survives the rollback) with `approverUserId`, `counterpartUserId`, `decisionId`, `kind`, `reason`. A lost race (two approvers at once) is a `409` and is audited the same way (`already_decided` or `stale_revision`).
2. **Database trigger** `finding_approvals_sod` (A0, FNDDB-05): the backstop. If the service check were bypassed, the insert fails and `isSodTriggerError` maps it to the same `403`.
3. **DTO**: `allowedActions` and `canDecide` (1.1).

### 1.5 Exceptions and expiry (`packages/db/src/findings/exceptions.js`, `apps/workers/src/findings/expiry.js`)

`request` / `withdraw` / `decide` / `revoke` / `end` / `expireIfDue` / `dueForExpiry` / `expireDue`. A request stores `accepted_severity` = the effective severity and uses the service clock as `created_at`, so the expiry window the service validated (accept risk: required, in the future, at most 180 days; suppress: optional, at most 365) is the one the database CHECK sees. Approval moves the finding to `accepted_risk` / `suppressed` (SLA stops, pending pointer cleared, active pointer, expiry and accepted severity set). Revoke and expiry end an approved exception and reopen the finding (`reopen_count + 1`, SLA restarted by `transitionFinding`).

**The job `findings.exception.expire`:** the scheduler worker enqueues one platform job per five-minute bucket to the `findings` queue (message id `findings-exception-expire-<bucket>`, so several scheduler instances make ONE job) only while `FINDINGS_INGESTION_ENABLED=true` (the findings worker runs only then); the findings worker handler (`createExceptionExpiryHandler`, a NEW file `apps/workers/src/findings/expiry.js`, dispatched by a two-line edit of `handler.js`) asks for approved exceptions whose `expires_at` has passed and ends each in its OWN transaction, under the tenant, workspace and id of the row, locked, with the system actor `expiry`: history row (`actor_type = system`, `actor_code = expiry`, reason `risk_acceptance_expired` or `suppression_expired`), audit `finding.exception_expired`, events `finding.exception_expired` and `finding.reopened`. At most 5 batches of 200 per tick; a failure of one item is logged (ids only) and does not stop the others. Idempotent (a replay or a second instance finds nothing due). A suppression without an expiry never expires. **The read path never waits for the job** (A1's effective status), and every write expires an overdue acceptance first.

### 1.6 The findings realtime room (`apps/api/src/realtime/`)

Room `findings:workspace:<tenantId>:<workspaceId>` (`realtime/findings.js`, the name is built by the server from validated ids). A client subscribes with `{ findingsWorkspaceId }` (strict: any other key, a `room`, a malformed id is the generic `NOT_FOUND` ack); the join needs `finding.view` in that workspace (execution.view alone is `FORBIDDEN`; a hidden or foreign workspace is `NOT_FOUND`), and every re-validation pass (`reauthSeconds`, and `sweep()`) re-checks it with the key of the room kind, so a revoked permission ends the subscription (`subscription.ended` with `scope: "findings"`). The hint event is `finding.changed` with `{ type, findingId, workspaceId, status?, rev? }` only (strict schema; no title, rationale, snippet or user). The `realtime` consumer now verifies a finding message against the DATABASE (the finding by tenant and id, the workspace of the payload must match) and builds the room from the row, never from the message; a forged or mismatched message is dead-lettered and produces no hint. Types that produce a hint: `finding.created`, `status_changed`, `review_recorded`, `approval_decided`, `assigned`, `fix_submitted`, `verified`, `reopened`, `exception_requested`, `exception_decided`, `exception_expired`, `comment_added`, `advisory.completed`. **Wave 3 (E integration)** must add `findingsWorkspaceId` to `realtime-client.js` (subscribe payload, the `finding.changed` hint schema, and `scope: "findings"` in `subscription.ended`); until then the screens poll as built.

### 1.7 Events and audit written (ids and enums only; never a rationale, comment, justification or snippet)

| Action | History | Audit (`FINDING_AUDIT_ACTIONS`) | Events (queue `realtime`) |
|---|---|---|---|
| claim | `review_started` | `finding.review_started` (take-over: `takeover: true`, no status change) | `finding.status_changed` |
| record | `review_started` (from new) and `review_recorded` | the same two | `finding.status_changed` x1 or x2, `finding.review_recorded` |
| withdraw | `review_withdrawn` | `finding.review_withdrawn` | `finding.status_changed` |
| approve / reject (review) | `approved_tp`, `approved_fp`, `rejected` | `finding.approval_decided` (+ `finding.severity_overridden` when the severity moved) | `finding.status_changed`, `finding.approval_decided` |
| reopen-review | `fp_reopened` / `rereview` | `finding.review_started` | `finding.status_changed` |
| exception request | none (no status change) | `finding.exception_requested` | `finding.exception_requested` |
| exception withdraw / reject | none | `finding.exception_withdrawn` / `finding.exception_decided` | `finding.exception_decided` |
| exception approve | `risk_accepted` / `suppressed` | `finding.exception_decided` | `finding.status_changed`, `finding.exception_decided` |
| revoke | `revoked` | `finding.exception_revoked` | `finding.status_changed`, `finding.exception_decided`, `finding.reopened` |
| expiry (system) | `risk_acceptance_expired` / `suppression_expired` | `finding.exception_expired` | `finding.status_changed`, `finding.exception_expired`, `finding.reopened` |
| comment | none | `finding.comment_added` | `finding.comment_added` |
| a refused decision | none | `finding.approval_denied` | none |

`finding.status_changed` rows equal the status transitions exactly (a request, a rejection of a request, a withdrawal of a request and a take-over change `rev` without a status change and write NO status hint; their own domain event is the hint). `FND-S14` (Part F) can count them.

### 1.8 Files

New: `packages/db/src/findings/lifecycle-support.js`; `apps/api/src/modules/findings/{policies/lifecycle.js, mappers/lifecycle.js, repositories/{lifecycle,write-scopes}.js, schemas/lifecycle.js, services/{lifecycle-support,review,approval,exceptions}.js, controllers/{review,approval,exceptions}.js}`; `apps/api/src/realtime/findings.js`; `apps/workers/src/findings/expiry.js`; `apps/api/test/security/helpers/findings/findings-b-fixtures.js`. Filled: `packages/db/src/findings/{reviews,exceptions}.js` (all frozen method names kept; `exceptions.end` is the generic ending, additive: `claim`, `reopenForReview`, `sodBlockedIds`, `revoke`, `expireIfDue`, `expireDue`), the three route files, `findings-b-checks.js`.

## 2. Checks (`helpers/findings/findings-b-checks.js`, 15, `expected.js` line `B: 15`)

| Id | Property |
|---|---|
| `FND-S02a` | 403 vs 404 on every Part B write route (viewer, Admin without approval keys, hidden workspace, another tenant, unknown id, forged body keys, bulk with a hidden, foreign or unknown workspace); controls succeed |
| `FND-S02b` | Reviews and Approvals queues: scoping, 403/404, `canDecide` per caller, numbered and keyset pages agree, cursor under another filter, workspace or tampered is `INVALID_CURSOR` |
| `FND-S07a`, `FND-S07b` | SOD over HTTP for reviews and for exceptions (self, both-key custom role, earlier rejected round, an earlier reviewer approving an exception), audit with both ids, nothing written, second user succeeds, only the reviewer withdraws |
| `FNDDB-05` | the database trigger: reviewer, earlier-round reviewer, exception requester refused; controls succeed |
| `FND-S07c` | the per-caller `allowedActions` and `canDecide` for nine states and seven callers, agreeing with what the write routes enforce |
| `FND-S08a` | stale revision, disallowed sources, pending exception, already decided, status hints equal transitions, two concurrent approvals give one success and an audited loser |
| `FND-S08b` | history, audit and events of the whole review lifecycle, override and SLA recomputation, false positive stops the clock, rejection, reopen, a forced failure leaves nothing behind |
| `FND-S09a` | exception rules (expiry limits, approver hint, pending, withdraw, reject, approve, revoke by kind, audit trail) |
| `FND-S09b` | expiry job with an injected clock (two tenants), idempotency, no-expiry suppression, overdue reads as reopened before the job, the first write after expiry works |
| `FND-S10a` | secrets refused in every free-text field (five canaries: the database shapes and the wider platform shapes), never echoed or stored; controls succeed; no canary in any table |
| `FND-S11a` | route table (idempotent, write limit, tenant audience), replay, different request, per user and per route, failure frees the key, bulk caps and per-item results |
| `FND-S11b` | the real write rate limiter: per user and per route, reads separate |
| `FND-S15` | the findings room (join rules, hints from a real write, exact hint keys, forged and mismatched messages, revoked permission) with the real server and consumer |
| `FND-S16` | archived workspace refuses every mutation and not reads, restored works; suspended tenant has no context; every write route is a tenant route |

**Mutation checks (each run, then the code restored):** removing the per-caller SOD from `computeAllowedActions` and `decideStateOf` fails `FND-S07c` and `FND-S02b`; removing the service SOD check AND the trigger mapping fails `FND-S07a` and `FND-S07b` (with the trigger mapping kept they still pass: the database trigger is the backstop, as designed); commenting the `finding_approvals_sod` trigger out of the migration fails `FNDDB-05`; making the job's due query miss, and making `expireIfDue` never expire, each fail `FND-S09b`.

## 3. Deviations from the specification and why

1. **Writes answer with the finding detail DTO, not "the review"** (8.2 says `POST reviews` "returns the review"): the E mock, which defines the real API, returns the detail for every write so the UI refreshes in one round trip with its new `rev` and per-caller actions.
2. **A deleted pipeline hides nothing but `submit_fix`.** The mock returns an empty action list for a deleted pipeline; SPEC 5.13 says review, approve, comment, accept risk, expiry and assignment still work there. The server follows the spec: only `submit_fix` is disabled ("The pipeline was deleted...").
3. **`If-Match` is not implemented.** The optimistic-concurrency token is `expectedRev` of the body (SPEC 8) and the `ETag` of every response; no `If-Match` header is read.
4. **Permission denials are not audited.** `finding.approval_denied` is written for SOD refusals and for lost races (reason `already_decided` / `stale_revision`); a refusal by the central authorization middleware (`403` for a missing key) is not audited by the findings module (as for every other module; the executions module's guard pattern needs a per-route policy and a contract-extractor entry, not built).
5. **`withdraw` and `revoke` of an exception are authorized in two steps** (route: `finding.view`; service: the requester, or the key of the exception's kind), because the key depends on the stored exception. `PERMISSION_BY_ROUTE` already lists `finding.view` for withdraw; revoke says `finding.accept_risk|finding.suppress`, enforced in the service (`403 missing_permission`).
6. **Extra `details.reason` values:** `not_reviewer`, `not_requester` (as in the mock) and `workspace_archived` (`CONFLICT`); `FINDING_FORBIDDEN_REASONS` of `@qmentisai/shared` lists only the first two of SPEC 8.
7. **`VALIDATION_FAILED` now carries `details.reason`.** The frozen schemas mark credential, override and expiry issues with `params.reason`; the central formatter dropped it. `lib/validation.js` (`formatZodIssues`) now copies it per issue and `ValidationError` lifts the first one to `details.reason`, as SPEC 8 says. No other module sets `params.reason`, so no other response changes.
8. **The expiry job is enqueued by the scheduler worker only while `FINDINGS_INGESTION_ENABLED=true`** (the findings worker, which consumes the `findings` queue, starts only then); spec 9.1 says "every 5 minutes". With the flag off nothing is queued; the read path still treats an overdue acceptance as reopened and every write expires it.
9. **A request whose `expires_at` has passed can be rejected but not approved** (`409 transition_not_allowed`): approving it would accept a risk that is already over. Not in the spec.
10. **An exception expiry has no slack:** `expiresAt` must be in the future and at most 180 (365) days from the server's clock. A browser date picker that offers "180 days from now, end of day" can be refused; E should offer at most 179 days.
11. **The take-over of a claim** (SM-2 text) writes no history row (the status does not move; the machine has no `in_review` to `in_review` pair); it is audited (`finding.review_started`, `takeover: true`) and raises `rev`.
12. **`EXE-076`'s exemption table** (`exec-audit-checks.js`) got one entry, `realtime.findFinding` (see section 4).
13. **The `FNDA0-15` check was edited in one place** (it asserted that Part B's repository methods reject "as owned by part B"): one added line, like A1's. `snapshot-contract.js` got a `NAMED_GATES` entry so the exception request records its by-kind permission in `docs/api/`.

## 4. Verified, and not verified

**Run (ephemeral PostgreSQL cluster of the suite; the user's development database and stack were not touched):** `pnpm install --frozen-lockfile --offline` then `prisma generate`; `pnpm lint` (0 errors; 11 warnings, none in a file of this part: 7 in tenant-web, 4 in the api suite files); `pnpm build --force` (2 tasks); `pnpm contract:snapshot` (140 operations = 125 + 15 of this part; the diff of `docs/api/` is committed with the `parity-accepted.json` entry); `pnpm --filter @qmentisai/api contract:parity` (0 differences, 214 explained); `pnpm test:security` (976 checks registered = 909 + 67 findings: A0 15, A 18, B 15, D 12, AM 7; 995 tests, 995 passed, exit 0; the first full run had failed only `EXE-076`, which enumerates the realtime repository's functions: `findFinding` is now in its exemption table, covered by `FND-S15`, because a new DAL entry would change the fixed check count); `npx prettier --check apps packages`. Each of the 15 checks passed alone and with the whole findings family (`SECURITY_SUITE_ONLY="FND|FPA"`), and the mutations of section 2 were run once each.

**Not verified:** a live RabbitMQ round trip (outbox relay of the new events to the `realtime` queue and of the scheduled job to the `findings` queue; the consumer and the handler are run in process, on a broker double); the scheduler's enqueue itself (the `enqueuePlatformJob` helper is the existing one; the new tick is not exercised); the real authentication chain (checks use a stub chain with the real authorization middleware; a suspended tenant is proved through the real `resolveTenantContext`, not through an HTTP request); the real socket server behind the real session cookie (the checks use a fake resolver and real session rows); the approver-hint check against the real permission engine (the engine is stubbed by the principals' registered sets); a two-process race on the same finding (one process, `Promise.all`; the row lock is PostgreSQL's); an exception whose `expires_at` falls between two ticks of the job under load; the `Idempotency-Key` store on Redis (in-process store); browsers and the UI (Wave 3).

## 5. Open decisions and notes for the integrator

- **E (Wave 3):** realtime client additions (1.6); the date-picker limit (deviation 10); the writes return the detail DTO (deviation 1); the Approvals row has no `requesterId`, only `requestedBy`.
- **F:** `FND-S14` should count `finding.status_changed` rows against transitions (1.7); `FND-S01`'s write sweep can reuse `findings-b-fixtures.js` (`startWriteApi`); the `AUTHORIZATION.md` SOD wording (any reviewer of the finding, any round) is built as D-21 says.
- **C:** `computeAllowedActions` already lists the assignment and remediation actions with the mock's rules (own rules `assignee_or_assign_holder`); Part C's write services must enforce them and may refine the reasons in `policies/lifecycle.js` (`DISABLED_REASONS`).
- **D-integration:** `request_advisory` is computed here from `agentRunsOn` and the advisory DTO's status; the advisory route itself is D's.
- **Shared-file edits outside this part's ownership (all small):** `packages/db/src/findings/findings.js` (`hydrate` method and `sodUserIds` in `getDetail`), `apps/api/src/modules/findings/{mappers/index.js (the allowedActions block and the call), services/read.js (`callerUserId`)}`, `apps/api/src/lib/validation.js` and `apps/api/src/errors/app-error.js` (deviation 7), `apps/api/scripts/snapshot-contract.js` (`NAMED_GATES`), `apps/workers/src/findings/handler.js` (two lines) and `apps/workers/src/scheduler/index.js` (one tick), `apps/api/test/security/helpers/findings/findings-a0-checks.js` (one line), `apps/api/test/security/helpers/exec-audit-checks.js` (one exemption), `docs/api/**` (the snapshot and `parity-accepted.json`).
