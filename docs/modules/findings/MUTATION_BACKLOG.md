# Findings, Part F: suite coverage matrix, mutation sweep backlog and defects found

Written 2026-11-24 for Part F of `SPEC.md` 16.2 (suite integration, cross-cutting checks, mutation sweep, documentation). It follows the model of `docs/modules/scan-engines/MUTATION_BACKLOG.md`. Five parts: (1) the coverage matrix of the `SPEC.md` 14.1 requirements and of the owner's cross-cutting list against the registered checks, with the gaps found and filled; (2) the mutation sweep method, sample and totals; (3) the survivors, grouped by file, **not triaged** (the standing order defers triage); (4) the survivors that were killed in this part because they are security-critical; (5) defects found by the audit and the sweep, recorded and not fixed.

**Status:** @@STATUS@@

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

@@RESULT@@

### 2.3 Limits of this sweep (read before trusting a kill rate)

- A sample, not the population: at most 30 covered mutants per file in the memory pass (8 module-level ones at most) and 3 to 14 per file in the database pass. The memory pass covers `packages/shared/src/findings` (9 files), `secret-redaction.js` and `findings-agent` (10 files); the database pass samples 19 files of `packages/db/src/findings`, `apps/api/src/modules/findings/{services,policies}`, `apps/workers/src/findings` and `apps/api/src/realtime/findings.js`. **Not swept:** the controllers, mappers, schemas and routes of `apps/api/src/modules/findings` (a declaration is not an operator target; `FND-S01c` pins the route declarations instead), `packages/db/src/findings/{events,errors,not-implemented}.js`, `apps/workers/src/findings/main.js`, and most of `repositories/`.
- The database-pass sample is random over the candidate lines, **including lines no check executes**: a survivor there is either a real gap or a line outside the filtered checks. The survivors of the database pass were run against the checks of the part that owns the file, not the whole suite (one run with the whole suite per mutant would take about 80 seconds).
- Mutation in memory does not change a source FILE that a check reads (the source guards `FPA-S01a`, `FNDA1-02`, `FNDAM-04` see the original text).
- Equivalent mutants are not removed (triage is deferred): a changed cap by one, an error message, a log argument, a sort tie-break that never ties and a schema description are among the survivors.

## 3. Survivors (not triaged; a star marks lines whose text matches a security keyword and that look security-relevant at first sight, to be confirmed at triage)

@@SURVIVORS@@

## 4. Survivors killed in this part (security-critical, `FND-S19` and `FND-S20`)

@@KILLED@@

## 5. Defects found (recorded, not fixed)

| Id | Where | What | Severity and why |
|---|---|---|---|
| **D-F1** | `apps/api/src/modules/findings/services/advisory.js` (the advisory request route) | `POST /findings/{id}/advisory/request` is accepted (`202`, one outbox job, one audit entry) in an **archived workspace**. Every other workspace write answers `409 CONFLICT workspace_archived` (`FND-S16b`). The bulk routes answer `200` with a per-item `CONFLICT / workspace_archived`, which is the specified per-item shape and is asserted | Low: the request changes no finding and the agent only writes an advisory row. It breaks the rule "every mutation is refused" of `FND-S16` and wastes a provider call on a workspace nobody can act in. Fix: check the workspace status in the advisory service like `runFindingWrite`. The check `FND-S16b` accepts 202 or 409 and fails when the refusal is added only if the assertion is left as is: replace the known-deviation branch by the 409 assertion when it is fixed |
| **D-F2** | `packages/db/src/findings/ingestion.js` (`evidenceRow`, the snippet test) and `packages/shared/src/findings/normalize.js` | The evidence copy keeps an excerpt unless `hasCredentialShape` flags it, and that list is the database-aligned one (GitHub, AWS, bearer, private key, URL credentials). The **widened shared list** (`hasSecretShape`: Stripe `sk_live`, Slack `xox`, JWT, quoted password assignments, ...) is applied to titles and to the advisory input but **not** to the stored excerpt. A Stripe key or a Slack token inside a SAST excerpt is therefore stored in `finding_evidence.snippet` and returned by `GET /findings/{id}` in `evidence`. The scan layer's own CHECK (`qm_has_credential_shape`) does not flag those shapes either, so nothing upstream stops them. Titles are redacted and the advisory input redacts again, so nothing reaches a provider | Medium: a secret hardcoded in code is exactly what SAST excerpts show, and the findings DTO is wider than the scan result. Fix: in `evidenceRow`, drop or redact the snippet with `hasSecretShape` / `redactCredentialShapes` (a design choice: drop, as for the database shapes, or redact). Not a one-line fix (behaviour of the evidence panel), so it is reported. `FND-S10e` allows it on the evidence surface only and fails if the canary appears anywhere else |
| D-F3 | `apps/workers/src/findings/` | The retention purge that `SPEC.md` 9.2 puts in the findings worker is **not built**: the SECURITY DEFINER functions `qm_findings_purge_snippets`, `_advisories`, `_ingestions` and `_tenant` exist (A0) but no job calls them (A0 said "Part A1 or F"; neither built it). The 90-day retention of evidence excerpts and advisories (`SPEC.md` 7.6) is therefore not enforced | Medium before general availability: stored excerpts (see D-F2) and advisories outlive their retention. Recorded in the tracker and the open decisions |

No other defect was found. One earlier report (A1 section 4, `FINDING_STATE_CONFLICT` answered 500) was fixed by the amendment round (`FNDAM-06`).
