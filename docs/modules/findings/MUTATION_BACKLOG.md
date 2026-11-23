# Findings, Part F: suite coverage matrix, mutation sweep backlog and defects found

Written 2026-11-24 for Part F of `SPEC.md` 16.2 (suite integration, cross-cutting checks, mutation sweep, documentation). It follows the model of `docs/modules/scan-engines/MUTATION_BACKLOG.md`. Five parts: (1) the coverage matrix of the `SPEC.md` 14.1 requirements and of the owner's cross-cutting list against the registered checks, with the gaps found and filled; (2) the mutation sweep method, sample and totals; (3) the survivors, grouped by file, **not triaged** (the standing order defers triage); (4) the survivors that were killed in this part because they are security-critical; (5) defects found by the audit and the sweep, recorded and not fixed.

**Status:** 1000 checks registered (909 + 91 findings). Sweep sample of 470 mutants: 301 killed, 166 survived, 0 timeouts, 3 invalid (kill rate 64.5 percent of the 467 valid mutants; 66.9 percent in the memory pass, 55.4 percent in the database pass, whose sample includes lines no filtered check runs). **Triage is deferred by standing order: none of the survivors is triaged except the security-critical ones killed by `FND-S19` and `FND-S20` (section 4).** The kill rate is lower than the scan-engines sweep (84.6 percent) mostly because the database pass is unmapped and filtered; do not read it as the strength of the checks.

## 1. Coverage matrix

Check files are under `apps/api/test/security/helpers/findings/` (`findings-a0-checks.js`, `findings-a-checks.js`, `findings-b-checks.js`, `findings-c-*.js`, `findings-d-checks.js` with `findings-d-integration.js`, `findings-amend-checks.js`, `findings-f-checks.js`). "Docker-free" is by design (ADR-008, ADR-014): none of these starts a container; the database checks run on the suite's ephemeral PostgreSQL cluster. A part's checks keep its prefix; Part F's are `FND-S01c`, `FND-S01d`, `FND-S10e`, `FND-S14d`, `FND-S16b`, `FND-S18`, `FND-S19`, `FND-S20`.

### 1.1 Requirements of `SPEC.md` 14.1

| Requirement | Proved by | Notes |
|---|---|---|
| FND-S01 cross-tenant and cross-workspace 404 on every route; forged ids refused or ignored | reads `FND-S01a`, `FND-S01b` (A); Part B writes and queues `FND-S02a`, `FND-S02b`; Part C assignment, remediation, board and settings `FND-S08c`, `FND-S08d`, `FND-S12c`, `FND-S14c`; the advisory request `FPA-I04`; **Part F `FND-S01c` (the route manifest) and `FND-S01d` (the sweep of every route)** | **GAP found: each part proved its own routes, no check enumerated the 31 routes, so a new route could ship unswept, and no check asserted that a denial writes nothing across the whole family. Filled.** |
| FND-S02 403 vs 404, permissions | `FND-S02a`, `FND-S02b`, `FND-S07c`, `FND-S08c`, `FND-S08d`; `FND-S01d` (403 without the route's key on every route) | |
| FND-S03 identity never crosses pipelines | `FND-S03`, `FNDA0-02`, `FNDA0-03` | |
| FND-S04 fingerprint properties | `FNDA0-02`, `FNDA0-03`, `FND-S04` | |
| FND-S05 recurrence and idempotency | `FND-S05a`, `FND-S05b`, `FND-S05c` | |
| FND-S06 resolution gating | `FND-S06a`, `FND-S06b`, `FND-S06c`, `FND-S08e`, `FNDA0-05`; **Part F `FND-S20` (every refusal of `evaluateCoverage` and the coverage-gap matching)** | **GAP found by the sweep: a coverage gap that equals the ecosystem or is a directory prefix of the path could be mutated away unseen. Filled by `FND-S20`.** |
| FNDDB-01 immutability | `FNDA0-11` | |
| FNDDB-02 state machine in the database | `FNDA0-10`, `FNDDB-02` | |
| FNDDB-03 composite keys and CHECKs | `FNDA0-09`, `FNDA0-12`, `FNDDB-03` | |
| FNDDB-05 SOD trigger | `FNDA0-13`, `FNDDB-05` | `FNDDB-04` is not defined in the specification |
| FND-S07 SOD over HTTP | `FND-S07a`, `FND-S07b`, `FND-S07c`, `FNDDB-05` | |
| FND-S08 transition permissions and conflicts | `FND-S08a`, `FND-S08b`, `FND-S08c`, `FND-S08d`, `FND-S08e` | |
| FND-S09 accept risk and suppression | `FND-S09a`, `FND-S09b` (injected clock) | |
| FND-S10 no secrets anywhere | stored rows `FND-S04`; rationales and comments `FND-S10a`; the agent path `FND-S10d`, `FPA-S04`, `FNDAM-01..04`; **Part F `FND-S10e` (the whole chain: ingestion, every table, outbox and audit, every read DTO, the advisory input, the logs)** | **GAP found: no check followed one canary through the whole chain. Filled. It found defect D-F2 (section 5).** |
| FND-S11 idempotency keys, bulk caps | `FND-S11a`, `FND-S11b`, `FND-S11c`; `FND-S01c` (every POST has the flag and the write limit) | |
| FND-S12 DTO no-leak | `FND-S12`, `FND-S12c`, `FND-S12d`, `FPA-I05`, `FNDAM-05`; `FND-S10e` | |
| FND-S13 list scoping and pagination | `FND-S13a`, `FND-S13b` | |
| FND-S14 atomicity and events | `FNDDB-02`, `FND-S14a`, `FND-S14b`, `FND-S14c`; **Part F `FND-S14d`** | **GAP found: no check reconciled the events with the history across ALL writers (ingestion also writes `finding.created`, `finding.verified`, `finding.reopened`, which a naive count of `finding.*` rows confuses with hints). Filled: `finding.status_changed` rows equal the history rows with a source status one for one, over ingestion, users and the expiry job.** |
| FND-S15 realtime | `FND-S15` | |
| FND-S16 suspended tenant and archived workspace | `FND-S16` (B), `FND-S08c` (assignment); **Part F `FND-S16b` (every workspace write route)** | **GAP found: only Part B's routes and assignment were proved in an archived workspace. Filled. It found defect D-F1.** |
| FND-S17 seed refuses production | `FND-S17` | |
| FPA-S01 no-write | `FPA-S01a`, `FPA-S01b`, `FNDA0-14`, `FNDA1-02`, `FPA-I01` | |
| FPA-S02 advice never decides | `FPA-S02`, `FPA-I05` | |
| FPA-S03 consent gate | `FPA-S03a`, `FPA-S03b`, `FPA-S03c`, `FNDA0-06`, `FPA-I02`, `FPA-I03` | |
| FPA-S04 input bounds and redaction | `FPA-S04`, `FNDAM-01..04` | |
| FPA-S05 output safety | `FPA-S05`, `FPA-S05b` | |
| FPA-S06 fail-safe | `FPA-S06`, `FPA-I07` | |
| FPA-S07 tenant scope | `FPA-S07`, `FPA-I06`; **Part F `FND-S19` (the five comparisons of the loaded row)** | **GAP found by the sweep: each of the five identity comparisons of `runAdvisory` could be weakened unseen (the stub repository of `FPA-S07` is exact). Filled.** |
| `FNDA0-01..15`, `FNDA1-01..02`, `FNDAM-01..07` | themselves | the freeze, the A1 additions and the amendment round |

### 1.2 The owner's cross-cutting list

| Property | Proved by |
|---|---|
| Cross-tenant and cross-workspace 404 on every read and write route | `FND-S01c`, `FND-S01d` (plus the per-part checks above) |
| Identity never crosses pipelines | `FND-S03`, `FNDA0-02` |
| SOD enforced | `FND-S07a..c` (service), `FNDDB-05` and `FNDA0-13` (database), `FND-S01d` (a custom both-key role is a part B case) |
| The false-positive agent cannot transition or write state | `FPA-S01a` (import graph), `FPA-S01b` (hostile model), `FNDA0-14` and `FPA-I01` (the real restricted login) |
| Advisory never auto-decides | `FPA-S02`, `FPA-I05` (an advisory of 99 percent changes neither status, revision nor allowed actions) |
| Incremental, partial, fork and non-baseline never mark fixed | `FND-S06a`, `FND-S06c`, `FND-S08e`, `FNDA0-05`, `FND-S20` |
| The external provider is blocked without consent | `FPA-S03a`, `FPA-I02`, `FPA-I03`, `FNDA0-06` |
| No secrets in findings and advisories, ingestion to DTOs to advisory input to logs | `FND-S04`, `FND-S10a`, `FND-S10d`, `FNDAM-01..04`, **`FND-S10e`** |
| Accept-risk expiry enforced | `FND-S09a`, `FND-S09b`, `FND-S13b` (an expired acceptance is never listed as accepted before the job) |
| No finding route under `/platform` | `FND-S01c` |
| Every repository function has a check | **`FND-S18`** (the A1 report said the `DAL-` entries were not added; this is the replacement: a new function fails until it names the check that covers it) |

### 1.3 Checks added by Part F

| Check | What it proves |
|---|---|
| `FND-S01c` | The REAL findings router is registered on a recorder and equals a manifest of 31 routes (method, path, tenant audience, central permission, the workspace scope read from the resolver the route was built with, rate limit profile, idempotency, params schema, handler); every route has a validation schema, every write the write limit, every POST an idempotency key, none is under `/platform`; seven planted deviations are each reported |
| `FND-S01d` | On the real HTTP stack, for every route of the manifest with valid bodies: another tenant's finding, a hidden workspace and an unknown id answer one identical 404 body; a visible resource without the key is 403; the whole denial phase writes nothing; the legitimate call is never a 404; the bulk calls report a foreign finding as a per-item not found; the SLA settings need their tenant key |
| `FND-S16b` | In an archived workspace every one of the 19 workspace write routes answers `409 CONFLICT workspace_archived` (the bulk calls per item) and nothing changes, the reads still answer 200, the restored workspace writes again; the advisory request is the recorded known deviation D-F1 |
| `FND-S14d` | Over a chain of ingestion (create, fix pending, verified, reopened), users (claim, review, approval, assignment, start, submit, an exception request and approval) and the expiry job: status hints equal transitions, one `finding.created` per finding, `finding.verified` and `finding.reopened` follow their transitions, every event has exactly its catalogued ids-and-enums keys |
| `FND-S10e` | A canary credential (Stripe, Slack, AWS, GitHub shapes; plain, base64 and URL-encoded) in an item title and excerpt appears in no row of the 14 tables, the outbox or the audit log, no read DTO, no advisory input (snippet and metadata level), and no ingestion log line; the agent cannot read a secret finding; known deviation D-F2 on the evidence surface only |
| `FND-S18` | The functions of the eight repositories are enumerated; each is in the coverage table with a registered covering check and names the tenant (or is a recorded delegation); four planted violations are reported |
| `FND-S19` | A row whose tenant, workspace, repository, pipeline or id differs from the message in exactly one of the five is dropped by `runAdvisory` with no provider resolved, no consent read and nothing stored (kills the survivors of the sweep in `findings-agent/advise.js`) |
| `FND-S20` | Every refusal of `evaluateCoverage` one at a time and the coverage-gap matching (ecosystem, case, path, directory prefix, a sibling that only shares the prefix, an empty gap) (kills the survivors of the sweep in `coverage.js`) |

## 2. Mutation sweep

### 2.1 Method and tooling

The tooling of the scan-engines part M (`apps/api/scripts/mutation-sweep.js`, `mutation-worker.js`, `mutation-hook.js`, `mutation-register.js`) was reused. Two additive changes were made for this module: `MUTATION_TARGETS` (comma separated repository-relative files or directories) replaces the scan-engine target list, and `MUTATION_GROUP=findings` makes the worker run the checks of `helpers/findings/index.js`, skipping (not counting) the ones that need the database (a Proxy world throws `NEEDS_DB`). A plain file is accepted as a target.

- **Memory pass (Docker-free, database-free).** The 30 findings checks that need no database run in process (about 3 seconds for all of them). `map` records which check executes which source range; `run` applies ONE operator mutant at a time IN MEMORY (the loader hook replaces the source of one module; **the working tree is never written**) and runs only the checks that execute the mutated line. Used for `packages/shared/src/findings`, `packages/shared/src/secret-redaction.js` and `apps/workers/src/findings-agent`.
- **Database pass (in place).** The code that only database checks execute cannot be mutated in memory, so `dbsweep` changes the file IN PLACE, runs the real suite filtered to the checks that cover it (`SECURITY_SUITE_ONLY`, one ephemeral cluster per mutant, about 55 seconds each) and restores the file in a `finally` and on a signal. After the sweep `git diff` showed no change to any source file (section 2.2).
- Verdicts: killed (a check failed), timeout, survived (every covering check stayed green; a line that no pure check executes is also a survivor in the memory pass), invalid (did not compile).
- Seeds: 20261122 (memory pass), 20261124 (database pass). Operators: `===` and `!==`, `&&` and `||`, comparison boundaries, `true` and `false`, a removed negation, an integer literal plus one, `startsWith` and `endsWith`, `every` and `some`, `Math.min` and `Math.max`, a removed array element line, a removed statement call, a removed `continue`, `break` or `return`.

### 2.2 Sample and result

- **Memory pass:** 369 mutants in 21 files (`packages/shared/src/findings` 9 files, `secret-redaction.js`, `findings-agent` 11 files), seed 20261122, up to 30 covered mutants per file and 2 uncovered: **245 killed, 121 survived (25 on lines no pure check executes), 0 timeouts, 3 invalid.** 107 seconds in total (map 14 seconds).
- **Database pass:** 101 mutants in 19 files (`packages/db/src/findings` 9 files, `apps/api/src/modules/findings/{services,policies}`, `apps/workers/src/findings` 3 files, `apps/api/src/realtime/findings.js`), seed 20261124, one mutant per run of the filtered real suite, in place, in two checkouts in parallel (about 40 minutes): **56 killed, 45 survived, 0 timeouts, 0 invalid.**
- **Totals: 470 mutants, 301 killed, 166 survived, 0 timeouts, 3 invalid.**
- The memory-pass results above were taken BEFORE `FND-S19` and `FND-S20` were added; section 4 gives the re-run of the lines they cover.
- **The tree was never left mutated:** the memory pass writes nothing; the database pass restored every file (verified by `git status` after each stop, once after an owner-requested pause where the drivers were killed with SIGTERM and restored their file, and after the final run: only intended changes). One accident is recorded for honesty: a mistyped `rerun --help` started a scan-engine `rerun` for a few seconds; it was killed at once and `git status` showed no change.

Per file:


| File | Mode | Mutants | Killed | Survived | Timeout | Invalid |
|---|---|---|---|---|---|---|
| `apps/api/src/modules/findings/policies/advisory.js` | database | 2 | 2 | 0 | 0 | 0 |
| `apps/api/src/modules/findings/policies/lifecycle.js` | database | 4 | 3 | 1 | 0 | 0 |
| `apps/api/src/modules/findings/services/advisory.js` | database | 3 | 3 | 0 | 0 | 0 |
| `apps/api/src/modules/findings/services/approval.js` | database | 5 | 2 | 3 | 0 | 0 |
| `apps/api/src/modules/findings/services/exceptions.js` | database | 6 | 3 | 3 | 0 | 0 |
| `apps/api/src/modules/findings/services/read.js` | database | 4 | 1 | 3 | 0 | 0 |
| `apps/api/src/realtime/findings.js` | database | 6 | 2 | 4 | 0 | 0 |
| `apps/workers/src/findings-agent/advise.js` | memory | 32 | 21 | 11 (2 on lines no pure check runs) | 0 | 0 |
| `apps/workers/src/findings-agent/completed.js` | memory | 1 | 0 | 1 (1 on lines no pure check runs) | 0 | 0 |
| `apps/workers/src/findings-agent/constants.js` | memory | 6 | 2 | 4 | 0 | 0 |
| `apps/workers/src/findings-agent/controls.js` | memory | 20 | 13 | 7 (2 on lines no pure check runs) | 0 | 0 |
| `apps/workers/src/findings-agent/handler.js` | memory | 11 | 7 | 4 | 0 | 0 |
| `apps/workers/src/findings-agent/harden.js` | memory | 7 | 6 | 1 | 0 | 0 |
| `apps/workers/src/findings-agent/main.js` | memory | 4 | 0 | 4 (2 on lines no pure check runs) | 0 | 0 |
| `apps/workers/src/findings-agent/output.js` | memory | 17 | 15 | 2 (1 on lines no pure check runs) | 0 | 0 |
| `apps/workers/src/findings-agent/prompt.js` | memory | 5 | 0 | 5 | 0 | 0 |
| `apps/workers/src/findings-agent/rate-limit.js` | memory | 2 | 0 | 2 (2 on lines no pure check runs) | 0 | 0 |
| `apps/workers/src/findings-agent/runtime.js` | memory | 9 | 5 | 4 (2 on lines no pure check runs) | 0 | 0 |
| `apps/workers/src/findings/expiry.js` | database | 4 | 1 | 3 | 0 | 0 |
| `apps/workers/src/findings/handler.js` | database | 4 | 1 | 3 | 0 | 0 |
| `apps/workers/src/findings/sla.js` | database | 5 | 1 | 4 | 0 | 0 |
| `packages/db/src/findings/advisories.js` | database | 4 | 2 | 2 | 0 | 0 |
| `packages/db/src/findings/agent-repository.js` | database | 4 | 3 | 1 | 0 | 0 |
| `packages/db/src/findings/assignments.js` | database | 6 | 3 | 3 | 0 | 0 |
| `packages/db/src/findings/exceptions.js` | database | 6 | 6 | 0 | 0 | 0 |
| `packages/db/src/findings/findings.js` | database | 6 | 4 | 2 | 0 | 0 |
| `packages/db/src/findings/ingestion.js` | database | 14 | 7 | 7 | 0 | 0 |
| `packages/db/src/findings/lifecycle-support.js` | database | 3 | 2 | 1 | 0 | 0 |
| `packages/db/src/findings/remediation.js` | database | 3 | 2 | 1 | 0 | 0 |
| `packages/db/src/findings/reviews.js` | database | 6 | 3 | 3 | 0 | 0 |
| `packages/db/src/findings/transitions.js` | database | 6 | 5 | 1 | 0 | 0 |
| `packages/shared/src/findings/advisory-input.js` | memory | 31 | 19 | 11 (1 on lines no pure check runs) | 0 | 1 |
| `packages/shared/src/findings/constants.js` | memory | 30 | 24 | 6 (2 on lines no pure check runs) | 0 | 0 |
| `packages/shared/src/findings/coverage.js` | memory | 30 | 26 | 4 | 0 | 0 |
| `packages/shared/src/findings/fingerprint.js` | memory | 32 | 20 | 11 (2 on lines no pure check runs) | 0 | 1 |
| `packages/shared/src/findings/normalize.js` | memory | 32 | 19 | 12 (2 on lines no pure check runs) | 0 | 1 |
| `packages/shared/src/findings/permissions-map.js` | memory | 3 | 3 | 0 | 0 | 0 |
| `packages/shared/src/findings/plan-ingestion.js` | memory | 32 | 21 | 11 (2 on lines no pure check runs) | 0 | 0 |
| `packages/shared/src/findings/schemas.js` | memory | 32 | 18 | 14 (2 on lines no pure check runs) | 0 | 0 |
| `packages/shared/src/findings/sha256.js` | memory | 30 | 25 | 5 | 0 | 0 |
| `packages/shared/src/secret-redaction.js` | memory | 3 | 1 | 2 (2 on lines no pure check runs) | 0 | 0 |


### 2.3 Limits of this sweep (read before trusting a kill rate)

- A sample, not the population: at most 30 covered mutants per file in the memory pass (8 module-level ones at most) and 3 to 14 per file in the database pass. The memory pass covers `packages/shared/src/findings` (9 files), `secret-redaction.js` and `findings-agent` (10 files); the database pass samples 19 files of `packages/db/src/findings`, `apps/api/src/modules/findings/{services,policies}`, `apps/workers/src/findings` and `apps/api/src/realtime/findings.js`. **Not swept:** the controllers, mappers, schemas and routes of `apps/api/src/modules/findings` (a declaration is not an operator target; `FND-S01c` pins the route declarations instead), `packages/db/src/findings/{events,errors,not-implemented}.js`, `apps/workers/src/findings/main.js`, and most of `repositories/`.
- The database-pass sample is random over the candidate lines, **including lines no check executes**: a survivor there is either a real gap or a line outside the filtered checks. The survivors of the database pass were run against the checks of the part that owns the file, not the whole suite (one run with the whole suite per mutant would take about 80 seconds).
- Mutation in memory does not change a source FILE that a check reads (the source guards `FPA-S01a`, `FNDA1-02`, `FNDAM-04` see the original text).
- Equivalent mutants are not removed (triage is deferred): a changed cap by one, an error message, a log argument, a sort tie-break that never ties and a schema description are among the survivors.

## 3. Survivors (not triaged; a star marks lines whose text matches a security keyword and that look security-relevant at first sight, to be confirmed at triage)

#### `apps/api/src/modules/findings/policies/lifecycle.js` (1)

- `D0003` line 91 (drop-call): `add("reassign");`

#### `apps/api/src/modules/findings/services/approval.js` (3)

- `D0001` line 14 (int): `const MAX_APPROVALS_OFFSET = 10000;`
- `D0004` line 96 (int): `const page = query.page ?? 1;`
- `D0005` line 97 (bound): `if (numbered && (page - 1) * limit > MAX_APPROVALS_OFFSET)`

#### `apps/api/src/modules/findings/services/exceptions.js` (3)

- `D0002` line 58 (bound): `if (!Number.isFinite(t) || t <= now.getTime() || t > now.getTime() + max)`
- ★ `D0003` line 93 (eq): `if (decision === "approve" && e.expiresAt && e.expiresAt.getTime() <= clock().getTime())`
- `D0005` line 200 (logic): `!exception ||`

#### `apps/api/src/modules/findings/services/read.js` (3)

- `D0001` line 46 (eq): `direction: direction === "desc" ? "asc" : "desc",`
- `D0003` line 108 (int): `if (numbered && (page - 1) * limit > MAX_FINDINGS_LIST_OFFSET)`
- `D0004` line 269 (bool): `{ field: "id", direction: "asc", type: "uuid", nullable: false },`

#### `apps/api/src/realtime/findings.js` (4)

- ★ `D0002` line 20 (logic): `if (!UUID.test(String(tenantId)) || !UUID.test(String(workspaceId)))`
- `D0004` line 32 (drop-element): `"finding.fix_submitted",`
- `D0005` line 35 (drop-element): `"finding.exception_requested",`
- `D0006` line 38 (drop-element): `"finding.comment_added",`

#### `apps/workers/src/findings-agent/advise.js` (11)

- ★ `A0002` line 56 (logic): `providerKind === "local" && level === "snippet" ? "local" : level;`
- ★ `A0008` line 56 (eq): `providerKind === "local" && level === "snippet" ? "local" : level;`
- `A0017` line 75 (bool): `state.withdrawn = true;`
- ★ `A0016` line 122 (logic): `finding.tenantId !== ids.tenantId ||`
- ★ `A0021` line 123 (logic): `finding.workspaceId !== ids.workspaceId ||`
- `A0026` line 124 (logic): `finding.repositoryId !== ids.repositoryId ||`
- `A0030` line 125 (logic): `finding.pipelineId !== ids.pipelineId ||`
- `A0031` line 161 (bool, no check runs the line): `inputError = true;`
- `A0007` line 164 (int): `v: 1,`
- `A0032` line 167 (bool, no check runs the line): `input: inputError ? { invalid: true } : input,`
- `A0014` line 180 (int): `schemaVersion: 1,`

#### `apps/workers/src/findings-agent/completed.js` (1)

- `A0033` line 18 (int, no check runs the line): `schemaVersion: 1,`

#### `apps/workers/src/findings-agent/constants.js` (4)

- `A0034` line 11 (int): `export const ADVISORY_MAX_TURNS = 2;`
- `A0035` line 13 (int): `export const ADVISORY_MAX_OUTPUT_TOKENS = 400;`
- ★ `A0038` line 17 (int): `export const EGRESS_RANK = Object.freeze({ none: 0, metadata: 1, local: 2, snippet: 2 });`
- ★ `A0039` line 17 (int): `export const EGRESS_RANK = Object.freeze({ none: 0, metadata: 1, local: 2, snippet: 2 });`

#### `apps/workers/src/findings-agent/controls.js` (7)

- `A0041` line 15 (logic): `if (!Number.isInteger(max) || max < 1) throw new TypeError("max must be a positive integer.");`
- `A0042` line 15 (bound): `if (!Number.isInteger(max) || max < 1) throw new TypeError("max must be a positive integer.");`
- `A0043` line 15 (int): `if (!Number.isInteger(max) || max < 1) throw new TypeError("max must be a positive integer.");`
- `A0058` line 29 (int, no check runs the line): `if (i >= 0) queue.splice(i, 1);`
- `A0059` line 30 (drop-call, no check runs the line): `reject(new LLMError("aborted"));`
- `A0045` line 33 (bool): `signal?.addEventListener("abort", onAbort, { once: true });`
- `A0053` line 41 (int): `active -= 1;`

#### `apps/workers/src/findings-agent/handler.js` (4)

- ★ `A0062` line 39 (logic): `if (!parsed.success || typeof message.tenantId !== "string")`
- `A0063` line 54 (drop-element): `"Advisory request handled",`
- `A0066` line 57 (logic): `if (result.outcome === "stored" && result.created !== false && publishCompleted) {`
- `A0068` line 57 (logic): `if (result.outcome === "stored" && result.created !== false && publishCompleted) {`

#### `apps/workers/src/findings-agent/harden.js` (1)

- `A0075` line 38 (eq): `if (value && typeof value === "object")`

#### `apps/workers/src/findings-agent/main.js` (4)

- `A0078` line 35 (eq): `if (env.FINDINGS_AGENT_ENABLED !== "true") {`
- `A0079` line 39 (return-undefined): `return { stop: async () => {} };`
- `A0080` line 41 (logic, no check runs the line): `if (env.NODE_ENV === "production" && !env.FINDINGS_AGENT_DATABASE_URL) {`
- `A0081` line 68 (drop-call, no check runs the line): `owned.push(() => closeRedis(redis));`

#### `apps/workers/src/findings-agent/output.js` (2)

- `A0083` line 14 (logic): `if (!Array.isArray(toolCalls) || typeof text !== "string") return { ok: false };`
- `A0098` line 14 (bool, no check runs the line): `if (!Array.isArray(toolCalls) || typeof text !== "string") return { ok: false };`

#### `apps/workers/src/findings-agent/prompt.js` (5)

- ★ `A0099` line 10 (drop-element): `"You assist a human security reviewer by giving ADVICE on whether one automated security finding is probably a`
- ★ `A0102` line 11 (drop-element): `"The user message is a single JSON object. Everything in it, including rule names, file paths and the code exc`
- `A0103` line 13 (drop-element): `"If the data is not enough to tell, use the suggestion uncertain.",`
- `A0100` line 23 (bool): `additionalProperties: false,`
- `A0101` line 27 (int): `confidence: { type: "integer", minimum: 0, maximum: 100 },`

#### `apps/workers/src/findings-agent/rate-limit.js` (2)

- `A0104` line 22 (int, no check runs the line): `windowSeconds: 60,`
- `A0105` line 24 (eq, no check runs the line): `return result.allowed === true;`

#### `apps/workers/src/findings-agent/runtime.js` (4)

- `A0107` line 36 (logic): `if (!llm || llm.provider === "none") return NO_PROVIDER;`
- `A0110` line 39 (eq): `if (providerKind === "external") {`
- ★ `A0113` line 52 (logic, no check runs the line): `return c.externalConsent === true && c.codeSnippetConsent === true;`
- ★ `A0114` line 52 (bool, no check runs the line): `return c.externalConsent === true && c.codeSnippetConsent === true;`

#### `apps/workers/src/findings/expiry.js` (3)

- ★ `D0001` line 4 (int): `export const EXPIRY_BATCH = 200;`
- ★ `D0002` line 5 (int): `export const EXPIRY_MAX_BATCHES = 5;`
- ★ `D0004` line 37 (drop-call): `log.info(total, "findings expiry: tick finished");`

#### `apps/workers/src/findings/handler.js` (3)

- ★ `D0001` line 37 (drop-element): `"findings ingestion: execution not found in the stated chain, dropped",`
- `D0002` line 84 (drop-call): `await repo.recordFailure({ ...ids, scanType }, Date.now() - startedMs).catch(() => {});`
- `D0004` line 98 (drop-call): `log.info("findings ingestion is disabled (FINDINGS_INGESTION_ENABLED), message acknowledged");`

#### `apps/workers/src/findings/sla.js` (4)

- `D0001` line 4 (int): `export const SLA_SWEEP_BATCH = 200;`
- `D0002` line 5 (int): `export const SLA_SWEEP_MAX_BATCHES = 5;`
- `D0004` line 54 (int): `total.failed += 1;`
- `D0005` line 62 (logic): `if (rows.length < SLA_SWEEP_BATCH || notified === 0) break;`

#### `packages/db/src/findings/advisories.js` (2)

- `D0001` line 14 (bool): `findingId: true,`
- `D0002` line 22 (bool): `createdAt: true,`

#### `packages/db/src/findings/agent-repository.js` (1)

- `D0001` line 4 (logic): `if (typeof value !== "string" || !UUID.test(value)) throw new TypeError('${name} must be a uuid');`

#### `packages/db/src/findings/assignments.js` (3)

- `D0003` line 235 (int): `limit: 1,`
- `D0004` line 236 (bool): `withTotal: true,`
- `D0006` line 373 (bool): `return { notified: false };`

#### `packages/db/src/findings/findings.js` (2)

- `D0004` line 237 (bool): `path: true,`
- `D0006` line 292 (bool): `select: { findingId: true, suggestion: true, confidence: true },`

#### `packages/db/src/findings/ingestion.js` (7)

- `D0005` line 452 (logic): `startLine !== null && posInt(f.endLine) !== null && f.endLine >= startLine`
- `D0006` line 452 (eq): `startLine !== null && posInt(f.endLine) !== null && f.endLine >= startLine`
- `D0007` line 452 (logic): `startLine !== null && posInt(f.endLine) !== null && f.endLine >= startLine`
- `D0008` line 478 (int): `fixedVersions: (f.fixedVersions ?? []).map((v) => clean(v, 100)),`
- `D0009` line 566 (int): `ecosystem: clean(f.ecosystem, 40),`
- `D0010` line 571 (bound): `startLine !== null && posInt(f.endLine) !== null && f.endLine >= startLine`
- ★ `D0012` line 654 (int): `columns.absentCount = t.effects.absentCount ?? 1;`

#### `packages/db/src/findings/lifecycle-support.js` (1)

- ★ `D0002` line 37 (eq): `metadata: { ...metadata, ...(actor.type === "system" ? { actor: actor.code } : {}) },`

#### `packages/db/src/findings/remediation.js` (1)

- `D0003` line 98 (int): `take: 100,`

#### `packages/db/src/findings/reviews.js` (3)

- `D0001` line 41 (eq): `if (unique.length === 0) return new Map();`
- `D0004` line 328 (logic): `if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new TypeError("limit");`
- `D0006` line 411 (bool): `select: { id: true, authorUserId: true, body: true, createdAt: true },`

#### `packages/db/src/findings/transitions.js` (1)

- `D0004` line 163 (eq): `? FINDING_TRANSITIONS.some((t) => t.to === null && t.from.includes(row.status)) &&`

#### `packages/shared/src/findings/advisory-input.js` (11)

- `S0006` line 60 (int): `const safeText = (max) => z.string().min(1).max(max);`
- `S0021` line 67 (int): `rule: z.object({ id: safeText(200), name: safeText(200).optional() }).strict(),`
- `S0027` line 67 (int): `rule: z.object({ id: safeText(200), name: safeText(200).optional() }).strict(),`
- `S0031` line 128 (int, no check runs the line): `const start = Number.isInteger(evidence.startLine) ? evidence.startLine : 1;`
- `S0008` line 130 (minmax): `? Math.max(0, evidence.focusStart - start)`
- `S0016` line 133 (minmax): `const from = Math.max(0, Math.min(focusIdx - Math.floor(maxLines / 2), all.length - maxLines));`
- `S0022` line 133 (minmax): `const from = Math.max(0, Math.min(focusIdx - Math.floor(maxLines / 2), all.length - maxLines));`
- ★ `S0009` line 140 (bound): `if (out.length > FINDINGS_LIMITS.advisorySnippetChars)`
- `S0026` line 197 (logic): `if (finding.scanType === "sca" && finding.componentName) {`
- ★ `S0017` line 212 (bound): `evidence.snippet.length > 0`
- ★ `S0023` line 215 (bound): `if (snippet.length > 0)`

#### `packages/shared/src/findings/constants.js` (6)

- `S0060` line 318 (eq, no check runs the line): `if (typeof own === "number") return own;`
- `S0061` line 319 (return-undefined, no check runs the line): `return Object.hasOwn(SLA_DEFAULT_HOURS, severity) ? SLA_DEFAULT_HOURS[severity] : null;`
- `S0034` line 328 (logic): `if (!dueAt || !startedAt) return "not_applicable";`
- `S0035` line 332 (bound): `if (t > due) return "breached";`
- `S0044` line 334 (bound): `return target > 0 && due - t <= target * SLA_DUE_SOON_FRACTION ? "due_soon" : "on_track";`
- `S0049` line 334 (bound): `return target > 0 && due - t <= target * SLA_DUE_SOON_FRACTION ? "due_soon" : "on_track";`

#### `packages/shared/src/findings/coverage.js` (4)

- `S0072` line 61 (bound): `if (gap === eco || (gap.length > 0 && (path === raw || path.startsWith('${raw}/'))))`
- `S0083` line 61 (logic): `if (gap === eco || (gap.length > 0 && (path === raw || path.startsWith('${raw}/'))))`
- `S0087` line 61 (eq): `if (gap === eco || (gap.length > 0 && (path === raw || path.startsWith('${raw}/'))))`
- `S0089` line 61 (eq): `if (gap === eco || (gap.length > 0 && (path === raw || path.startsWith('${raw}/'))))`

#### `packages/shared/src/findings/fingerprint.js` (11)

- `S0092` line 38 (int): `const FAMILY_RANK = { cve: 0, ghsa: 1, osv: 2 };`
- `S0100` line 38 (int): `const FAMILY_RANK = { cve: 0, ghsa: 1, osv: 2 };`
- `S0093` line 47 (logic): `const list = (item.advisories ?? []).filter((a) => a && typeof a.id === "string" && a.id.trim());`
- `S0094` line 47 (eq): `const list = (item.advisories ?? []).filter((a) => a && typeof a.id === "string" && a.id.trim());`
- `S0101` line 47 (logic): `const list = (item.advisories ?? []).filter((a) => a && typeof a.id === "string" && a.id.trim());`
- `S0102` line 48 (eq): `if (list.length === 0) return String(item.ruleId ?? "").trim();`
- `S0122` line 77 (bool, no check runs the line): `if (purl === null) return { ok: false, reason: "skipped_invalid" };`
- `S0116` line 107 (bool): `ok: true,`
- `S0104` line 115 (bound): `const raw = lines && lines.length > 0 ? lines[0] : null;`
- `S0112` line 243 (drop-call): `list.sort((a, b) => a.order[0] - b.order[0] || a.order[1] - b.order[1]);`
- `S0123` line 243 (logic, no check runs the line): `list.sort((a, b) => a.order[0] - b.order[0] || a.order[1] - b.order[1]);`

#### `packages/shared/src/findings/normalize.js` (12)

- `S0128` line 29 (bound): `if (p.length === 0 || p.startsWith("/") || p.length > FINDINGS_LIMITS.pathMax) return null;`
- `S0135` line 29 (string-method): `if (p.length === 0 || p.startsWith("/") || p.length > FINDINGS_LIMITS.pathMax) return null;`
- `S0149` line 29 (logic): `if (p.length === 0 || p.startsWith("/") || p.length > FINDINGS_LIMITS.pathMax) return null;`
- `S0137` line 51 (bound): `.filter((l) => l.length > 0);`
- `S0139` line 61 (return-undefined): `return null;`
- `S0154` line 69 (eq, no check runs the line): `if (fs === null) return evidence.kind === "line" ? [lines[0]] : null;`
- `S0136` line 74 (int): `return lines.slice(from, to + 1);`
- `S0144` line 129 (int): `const base = seg[seg.length - 1] ?? "";`
- `S0146` line 131 (quantifier): `seg.some((s) =>`
- `S0152` line 137 (quantifier): `seg.some((s) =>`
- `S0155` line 161 (return-undefined, no check runs the line): `return "config";`
- `S0150` line 172 (int): `let rest = purl.slice(4);`

#### `packages/shared/src/findings/plan-ingestion.js` (11)

- ★ `S0159` line 66 (return-undefined): `return redactCredentialShapes(value).slice(0, max);`
- `S0189` line 70 (logic, no check runs the line): `clean("title", it.title || it.ruleName || it.ruleId, FINDINGS_LIMITS.titleMax) || ruleId;`
- `S0160` line 79 (eq): `severityAssumed: it.severityAssumed === true,`
- `S0161` line 79 (bool): `severityAssumed: it.severityAssumed === true,`
- `S0162` line 81 (int): `cwe: (it.cwe ?? []).slice(0, 10),`
- `S0171` line 83 (int): `.slice(0, 20)`
- `S0180` line 89 (int): `fixedVersions: (it.fix?.fixedVersions ?? []).slice(0, 10),`
- ★ `S0179` line 129 (bool): `resolutionEligible: false,`
- `S0167` line 202 (bound): `if (lastSeen !== null && startedMs < lastSeen) {`
- ★ `S0185` line 278 (bound): `if (!verdict.absent || (lastSeen !== null && lastSeen > startedMs)) {`
- `S0190` line 331 (bound, no check runs the line): `execution.markers.lastIngestedStartedAt.getTime() > startedMs`

#### `packages/shared/src/findings/schemas.js` (14)

- `S0191` line 29 (bool): `const iso = z.string().datetime({ offset: true });`
- `S0192` line 55 (int): `export const userRefSchema = z.object({ id: uuid, displayName: z.string().max(200) }).strict();`
- `S0200` line 61 (int): `.max(200)`
- `S0193` line 62 (bound): `.transform((s) => s.split(",").filter((x) => x.length > 0))`
- `S0207` line 71 (int): `page: z.coerce.number().int().min(1).max(100000).optional(),`
- `S0210` line 71 (int): `page: z.coerce.number().int().min(1).max(100000).optional(),`
- `S0213` line 77 (int): `cursor: z.string().min(1).max(2000).optional(),`
- `S0216` line 77 (int): `cursor: z.string().min(1).max(2000).optional(),`
- `S0219` line 78 (int): `limit: z.coerce.number().int().min(1).max(L.maxLimit).optional(),`
- `S0201` line 83 (eq): `(q.page !== undefined || q.pageSize !== undefined) &&`
- `S0197` line 92 (drop-element): `"severity",`
- `S0221` line 246 (bool, no check runs the line): `return false;`
- ★ `S0222` line 282 (drop-call, no check runs the line): `bad("compensatingControls", "expiry_out_of_range");`
- `S0199` line 320 (quantifier): `.refine((b) => b.targets.every((t) => t.severity !== "info"), "info has no target");`

#### `packages/shared/src/findings/sha256.js` (5)

- `S0225` line 35 (bool): `view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000), false);`
- `S0229` line 35 (drop-call): `view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000), false);`
- `S0243` line 37 (int): `const w = new Uint32Array(64);`
- `S0236` line 40 (bound): `for (let i = 16; i < 64; i += 1) {`
- `S0249` line 40 (int): `for (let i = 16; i < 64; i += 1) {`

#### `packages/shared/src/secret-redaction.js` (2)

- `S0254` line 55 (eq, no check runs the line): `if (typeof text !== "string") return false;`
- ★ `S0255` line 57 (logic, no check runs the line): `SECRET_VALUE_SHAPES.some((re) => re.test(text)) ||`


## 4. Survivors killed in this part (security-critical, `FND-S19` and `FND-S20`)

Found as survivors of the memory pass and judged security-critical at first sight (tenant scoping of the agent, fixed only on a resolution-eligible covering result):

| Survivors | Where | Killed by |
|---|---|---|
| `||` turned into `&&` in each of the five identity comparisons (tenant, workspace, repository, pipeline, id) of the loaded row, 5 mutants plus their neighbours (S/A0016, A0021, A0026, A0030 and the matching lines) | `apps/workers/src/findings-agent/advise.js` 122 to 126 | `FND-S19`: a repository returning a row that differs in exactly one of the five is dropped with no provider, consent read or insert. Re-run: **all 9 mutants of lines 122 to 126 killed** |
| equality, boundary and logic mutants of the coverage-gap matching (ecosystem equal, path equal, directory prefix) | `packages/shared/src/findings/coverage.js` 61 (S0072, S0083, S0087, S0089) | `FND-S20`: every refusal one at a time and the matching table. Re-run: **6 of 7 mutants of line 61 killed**; the survivor (a boundary on `gap.length > 0`, an empty gap never matches a path) is not distinguishable by behaviour and is left for triage |

Not killed here (kept for the triage round, starred in section 3): the `plan-ingestion.js` bounds on the watermark equality (`startedMs < lastSeen`, lines 202 and 278: equal timestamps), the SCA advisory filter of `fingerprint.js` 47, the absolute path test of `normalize.js` 29, the `advisory-input.js` SCA branch 197 and the caps of the schemas.

## 5. Defects found (recorded, not fixed)

| Id | Where | What | Severity and why |
|---|---|---|---|
| **D-F1** | `apps/api/src/modules/findings/services/advisory.js` (the advisory request route) | `POST /findings/{id}/advisory/request` is accepted (`202`, one outbox job, one audit entry) in an **archived workspace**. Every other workspace write answers `409 CONFLICT workspace_archived` (`FND-S16b`). The bulk routes answer `200` with a per-item `CONFLICT / workspace_archived`, which is the specified per-item shape and is asserted | Low: the request changes no finding and the agent only writes an advisory row. It breaks the rule "every mutation is refused" of `FND-S16` and wastes a provider call on a workspace nobody can act in. Fix: check the workspace status in the advisory service like `runFindingWrite`. The check `FND-S16b` accepts 202 or 409 and fails when the refusal is added only if the assertion is left as is: replace the known-deviation branch by the 409 assertion when it is fixed |
| **D-F2** | `packages/db/src/findings/ingestion.js` (`evidenceRow`, the snippet test) and `packages/shared/src/findings/normalize.js` | The evidence copy keeps an excerpt unless `hasCredentialShape` flags it, and that list is the database-aligned one (GitHub, AWS, bearer, private key, URL credentials). The **widened shared list** (`hasSecretShape`: Stripe `sk_live`, Slack `xox`, JWT, quoted password assignments, ...) is applied to titles and to the advisory input but **not** to the stored excerpt. A Stripe key or a Slack token inside a SAST excerpt is therefore stored in `finding_evidence.snippet` and returned by `GET /findings/{id}` in `evidence`. The scan layer's own CHECK (`qm_has_credential_shape`) does not flag those shapes either, so nothing upstream stops them. Titles are redacted and the advisory input redacts again, so nothing reaches a provider | Medium: a secret hardcoded in code is exactly what SAST excerpts show, and the findings DTO is wider than the scan result. Fix: in `evidenceRow`, drop or redact the snippet with `hasSecretShape` / `redactCredentialShapes` (a design choice: drop, as for the database shapes, or redact). Not a one-line fix (behaviour of the evidence panel), so it is reported. `FND-S10e` allows it on the evidence surface only and fails if the canary appears anywhere else |
| D-F3 | `apps/workers/src/findings/` | The retention purge that `SPEC.md` 9.2 puts in the findings worker is **not built**: the SECURITY DEFINER functions `qm_findings_purge_snippets`, `_advisories`, `_ingestions` and `_tenant` exist (A0) but no job calls them (A0 said "Part A1 or F"; neither built it). The 90-day retention of evidence excerpts and advisories (`SPEC.md` 7.6) is therefore not enforced | Medium before general availability: stored excerpts (see D-F2) and advisories outlive their retention. Recorded in the tracker and the open decisions |

| D-F4 (S-1, logged by the Part E integration agent) | `apps/api/src/modules/findings` detail mapper and ETag | The ETag of `GET /findings/{id}` (`W/"finding-<rev>"`) covers the revision only, while the detail DTO also carries state that changes WITHOUT a revision change: the advisory card (`pending`, `stale`, a new advisory row), `lifecycle.allowedActions` (they depend on the caller's permissions, the assignee's membership and the exception clock) and the SLA state (`due_soon`, `breached` derive from the clock). A client or cache that revalidates with the ETag, or that treats an equal ETag as an unchanged page, can show stale advisory, action or SLA state. Optimistic concurrency itself is unaffected (`expectedRev` is the write token, `If-Match` is not read) | Medium for the UI (stale buttons and chips until a rev change or a poll); no security effect, the server re-checks every write. Open: either derive the ETag from a hash of the whole DTO, or stop sending a validator on reads. Not fixed here (server code) |
No other defect was found. One earlier report (A1 section 4, `FINDING_STATE_CONFLICT` answered 500) was fixed by the amendment round (`FNDAM-06`).
