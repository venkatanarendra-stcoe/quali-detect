# Findings, Part F, cross-cutting checks, mutation sweep, documentation: as built

**Built:** 2026-11-24 on main `6a4734c` (branch `worktree-agent-a836f8c8b5fd32e8d`, not pushed). This part folded its notes into `SPEC.md` 17.x (as-built summary of every part) and `MUTATION_BACKLOG.md` (coverage matrix, sweep, survivors, defects). No application code was changed; the only code edits are the suite files, the additive mutation tooling modes and one-line pointers in docs.

## Built

- **Eight cross-cutting checks** in `apps/api/test/security/helpers/findings/findings-f-checks.js` (`expected.js` line `F: 8`; the suite is `909 + 91 = 1000` checks):
  `FND-S01c` (route manifest of the 31 findings routes against the REAL router on a recorder, seven planted deviations), `FND-S01d` (cross-tenant, hidden-workspace, unknown-id and permission sweep of every route on the real HTTP stack, denials write nothing, controls), `FND-S16b` (every workspace write route in an archived workspace), `FND-S14d` (status hints equal history transitions across ingestion, users and the expiry job; `finding.created`/`verified`/`reopened` counted apart), `FND-S10e` (a canary through ingestion, all 14 tables, outbox, audit, every read DTO, the advisory input and the logs), `FND-S18` (every repository function classified with a covering check), `FND-S19` and `FND-S20` (kill checks for sweep survivors: the five identity comparisons of `runAdvisory`, every refusal and the gap matching of `evaluateCoverage`).
- **Mutation tooling:** `apps/api/scripts/mutation-sweep.js` takes `MUTATION_TARGETS`; `mutation-worker.js` takes `MUTATION_GROUP=findings` (runs the findings checks that need no database, skips the others). Both additive; the scan-engine behaviour is unchanged.
- **Documentation:** ADR-008 area 19 (OD-3 wording fix and an amendment line), `docs/AUTHORIZATION.md` (new 5.12, 6.4, decision 33), `docs/technical/DATABASE_DESIGN.md`, `docs/technical/API_STANDARDS.md` (the stale Idempotency-Key sentence, `expectedRev`/ETag, `details.reason`, keyset cursor binding), `docs/README.md`, `AGENT_INSTRUCTIONS.md`, `AGENTS.md`, the suite README, `SPEC.md` 17.x, `MUTATION_BACKLOG.md`, the tracker and the open decisions. `CLAUDE.md` was **not** edited: its area 19 sentence is consistent with OD-3 (it does not say secret findings are sent as snippets).

## Deviations from the specification and why

1. `FND-S19` and `FND-S20` are extra ids (not in `SPEC.md` 14.1): they exist to kill survivors of the sweep (`SPEC.md` 16.2 allows Part F to add what no part owns).
2. The `DAL-` entries for the new repository functions were not added to `direct-repos.js` (another part's file and a fixed count); `FND-S18` is the replacement and fails for a function without a covering check.
3. Two known defects are asserted strictly as current behaviour (D-F1 `FND-S16b`, D-F2 `FND-S10e`), so the suite fails when either is fixed and the assertion is tightened in the same change.
4. The database half of the sweep is a sample (section 2 of the backlog) and was run in two checkouts in parallel; the files were mutated in place one at a time and restored by the driver.

## Verified, and not verified

Numbers and gates: see `MUTATION_BACKLOG.md` 2.2 and the tracker row. **Not verified:** the whole sweep population (a sample), the controllers, mappers, schemas and routes of the API module (not swept), real broker, Redis, model and browser behaviour (live tests LT-F1 to LT-F7 of `SPEC.md` 14.4 remain with the owner), the real authentication chain in front of the findings routes (the suite uses a stub chain with the real authorization middleware and scope resolvers).

**Defects reported, not fixed:** D-F1 (advisory request accepted in an archived workspace), D-F2 (evidence copy keeps a Stripe or Slack shaped credential), D-F3 (the retention purge job is not built), D-F4 (the ETag of the finding detail covers `rev` only; found by the Part E integration as S-1).
