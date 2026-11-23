# Scan Engines, part M: suite coverage matrix and mutation sweep backlog

Written 2026-11-22 for part M of `SPEC.md` 16.1 (security suite completion and mutation sweep). Four parts: (1) the coverage matrix of the requirements `SE-1` to `SE-48` and of the ADR-008 area 18 properties against the registered checks, with the gaps found and filled; (2) the mutation sweep method, tooling and totals; (3) the survivors of the sweep, grouped by file, each with its disposition where it has been triaged; (4) **the triage round of 2026-11-23** (owner decision, option B: the security-relevant groups plus a 20 percent sample now, full triage (A) before general availability). A survivor is either a missing check or an equivalent mutant and none may be assumed equivalent: every disposition below is a check that kills the mutant (re-run against the mutant with `mutation-sweep.js one`) or a written proof.

**Status after the triage round (2026-11-23): 909 checks; 104 of the 219 survivors triaged (88 killed by 10 new kill checks, 14 equivalent with a proof, 2 deferred); 115 survivors not triaged; kill rate 90.8 percent (section 4.3). Full triage (A) remains REQUIRED before general availability (gate G-7).**

## 1. Coverage matrix

The suite has **898 checks** (889 before part M: four gap checks from the audit and five checks that kill sweep survivors; `pnpm test:security` reports 917 tests because the integrity check and the controls count as tests). The ENG-S ids are those of `SPEC.md` 14.1 (`ENG-S01` to `ENG-S14`, the later `ENG-S15` comparison tooling, `ENG-S16` engines in the worker path, `ENG-S17` event loop yielding). Check files are under `apps/api/test/security/helpers/`. "Docker-free" is by design (ADR-008, ADR-014): none of these starts a container.

### 1.1 Requirements SE-1 to SE-48

| Requirement | Proved by | Notes |
|---|---|---|
| SE-1 one engine per scan type in the registry, existing adapter contract | `ENG-S16b` (registry only with the flag), `ENG-S16c`, `ENG-S16e`, `ENG-S16f`, `ENG-S16g` (identity, contract, hooks) | |
| SE-2 tool adapter shape | `ENG-S16f`, `ENG-S16g`, `ENG-S06e` to `ENG-S06n` (real adapters), `ENG-S09*` | |
| SE-3 no shell, no repository string in argv | `ENG-S03a` (runner), `ENG-S03c`, `ENG-S03d`, `ENG-S03e`, `ENG-S03g`, `ENG-S03h` (sealed command lines per tool), `ENG-S03i` and `ENG-S03j` (part M) | |
| SE-4 adapters return raw-parsed records only, no side effects | `ENG-S03b`, `ENG-S09a` to `ENG-S09g` | |
| SE-5 no network, database, SecretStore, GitHub or LLM in the ensemble | `ENG-S03b` (core), **`ENG-S03k` (part M: every file under `ensemble/**`, with a ten-case negative control)**, `ENG-S12g` (scan path never reaches the refresh code), `ENG-S04a`, `ENG-S04b` | **GAP found: only the core directory was guarded. Filled.** |
| SE-6 tool set is platform data keyed by scan type and profile | `ENG-S02b` (lock file, resolver), `ENG-S16b` | pipeline-side profile selection is `PIP-*` (Pipelines module) |
| SE-7 language detection from file names only | `ENG-S11e` | |
| SE-8, SE-9 applicability, `skipped` / `no_applicable_files` | `ENG-S11e`, `ENG-S11h`, `ENG-S11c`, `ENG-S16f`, `ENG-S16g` | |
| SE-10 merger takes one task and keeps no state | `ENG-S06a`, `ENG-S06g` | |
| SE-11 dedup key is a merge key only | `ENG-S06c`, `ENG-S06i`, `ENG-S06j` | |
| SE-12 two candidates of one tool never merge | `ENG-S06a`, `ENG-S06b`, `ENG-S06d`, `ENG-S06e`, `ENG-S06j`, `ENG-S06l`, `ENG-S06n` | |
| SE-13 provenance per tool, confidence rule | `ENG-S06b`, `ENG-S06d`, `ENG-S11b` | |
| SE-14 deterministic order | `ENG-S06d`, `ENG-S17a` | |
| SE-15 scan types never merged | `ENG-S06a`, `ENG-S06b` | |
| SE-16 per-task tool parallelism | `ENG-S14b`, `ENG-S14a` | |
| SE-17 per-worker semaphore | `ENG-S14a`, `ENG-S14b` | |
| SE-18 per-tenant limit | `ENG-S14a`, `ENG-S14b` | |
| SE-19 fork share | `ENG-S14a`, `ENG-S14b` | |
| SE-20 waiting is not running, `unavailable` / `capacity` | `ENG-S14b`, `ENG-S17c` (heartbeat) | |
| SE-21 tree on local disk once per attempt, deleted in `finally` | `EXE-020` (scan temp directory empty after the hostile archive run), `ENG-S07b` | |
| SE-22 changed-paths artifact, tenant scoped | `ENG-S16a`, `ENG-S16c`, `ENG-S08e` | |
| SE-23 fail closed to full | `ENG-S16a`, `ENG-S11g`, `ENG-S11h` | |
| SE-24 merge first, filter after | `ENG-S11g`, `ENG-S11h`, `ENG-S16f`, `ENG-S16g` | |
| SE-25 engine identity and version | `ENG-S11c`, `ENG-S16c`, `ENG-S12p` | |
| SE-26 reproducibility record, run manifest | `ENG-S11c`, `ENG-S16c`, `ENG-S16g`, `ENG-S08a` | |
| SE-27 argument safety, targets after `--` | `ENG-S03e`, `ENG-S03h`, `ENG-S03a`, `ENG-S11g`, `ENG-S11h`, `ENG-S16d` | |
| SE-28 progressive enablement flags | `ENG-S16b`, `ENG-S01b` | the per-type flags are Open (OQ-18); only the rollout flag exists and is asserted |
| SE-29 no tenant credential reaches any tool | `ENG-S04a` (runner), **`ENG-S04b` (part M: the real engine, planted environment, trusted and fork)**, `ENG-S01a`, `ENG-S02a`, `EXE-019` | **GAP found: ENG-S04 was proved at the runner only. Filled for the SBOM engine; the other three engines build their specifications through the same plan function whose environment `ENG-S03d`, `ENG-S03e`, `ENG-S03h` assert.** |
| SE-30 fork code is hostile, same sandbox, own pool | `ENG-S04b`, `ENG-S14a`, `ENG-S14b`, `ENG-S01a` | |
| SE-31 fork results keep their marks | `EXE-019`, `EXE-025` (the Executions module owns the marks; unchanged by this module) | |
| SE-32 platform mirror, shared, no tenant in the path | `ENG-S12d`, `ENG-S12h` | |
| SE-33 snapshots by digest, one active per tool | `ENG-S12d`, `ENG-S12h`, `ENG-S12i`, `ENG-S12k` | |
| SE-34 refresh job off by default, platform message | `ENG-S12f`, `ENG-S12l`, `ENG-S12c`, `ENG-S12j` | |
| SE-35 promotion gate and canary | `ENG-S12e`, `ENG-S12i`, `ENG-S12j` | |
| SE-36 read-only mount, offline switches | `ENG-S12e`, `ENG-S12o`, `ENG-S03d` | |
| SE-37 provenance on every result, tenant scoped | `ENG-S12m`, `ENG-S12o`, `ENG-S16e` | |
| SE-38 staleness never fails a scan | `ENG-S12a`, `ENG-S12o`, `ENG-S16e` | |
| SE-39 refresh logs, one quarantine audit entry | `ENG-S12l`, `ENG-S12n` | |
| SE-40 no secret value stored, preview rule, length bucket | `ENG-S05a`, `ENG-S05e`, `ENG-S13d` | |
| SE-41 redacted Gitleaks, value-dropping schemas | `ENG-S05e`, `ENG-S09g`, `ENG-S03h` | |
| SE-42 masked line preview | `ENG-S13d`, `ENG-S05f` | |
| SE-43 snippets, titles, messages redacted | `ENG-S05b`, `ENG-S05c`, `ENG-S05d`, `ENG-S05e`, `ENG-S05f` | |
| SE-44 raw Secrets stdout never stored or logged | `ENG-S05e`, `ENG-S16g`, `ENG-S05b` | |
| SE-45 allowed v1 sources, language ecosystems | `ENG-S12b`, `ENG-S12j`, `ENG-S03d`, `ENG-S03f` | |
| SE-46 quarantine | `ENG-S12b`, `ENG-S12j`, `ENG-S12n`, `ENG-S02b` (`DEFERRED_V2`) | |
| SE-47 GHSA attribution text | none in area 18 | display text of the screens and the legal notices page, not a security property of the suite (UI / legal gate OQ-26); not a gap of this suite |
| SE-48 legal sign-off gate | none | a process gate (OQ-26), not testable in a Docker-free suite; not a gap |

### 1.2 ADR-008 area 18 properties

| Property of the area 18 scope sentence | Proved by |
|---|---|
| Properties of the container invocation (no network, read-only mounts, non-root, dropped capabilities, limits) | `ENG-S01a`, `ENG-S01b`, `ENG-S03c` to `ENG-S03h` (per tool), `ENG-S12e` (canary) |
| Digest-pinned images | `ENG-S02a`, `ENG-S02b`, `ENG-S02c` |
| No credentials | `ENG-S04a`, `ENG-S04b` |
| Repository content never executed or used as tool configuration | `ENG-S03a` to `ENG-S03k`, `ENG-S07a` (the `.git` deny list), `ENG-S03h` and `ENG-S03i` (tool-control deny list, at the scan handler) |
| Secret values never stored or transmitted | `ENG-S05a` to `ENG-S05f`, `ENG-S13d` |
| Cross-tool merge never crosses a tenant, pipeline or task | `ENG-S06a` to `ENG-S06n`, `ENG-S06g` |
| Hostile archives contained | `ENG-S07a`, `ENG-S07b`, `ENG-S07c`, `ENG-S12c` (the database archives), `EXE-020` |
| Hostile tool output contained | `ENG-S09a` to `ENG-S09g`, `ENG-S13b`, `ENG-S15d` |
| Tenant isolation of scan results and tool runs | `ENG-S08a` to `ENG-S08i`, `DAL-317`, `ENG-S12m` |
| Cancellation without orphans | `ENG-S10a`, `ENG-S10b`, `ENG-S10c` |
| Roll-up, sealed path, links and evidence, capacity | `ENG-S11a` to `ENG-S11h`, `ENG-S12a` to `ENG-S12p`, `ENG-S13a` to `ENG-S13e`, `ENG-S14a`, `ENG-S14b` |

### 1.3 Gaps found by this audit and filled in part M

| Gap | New check | What it proves |
|---|---|---|
| The extraction deny list (`.gitleaksignore`, `.gitleaks.toml`, `.secrets.baseline`) was proved on the extractor and on the predicate, but not composed with `exclusions.paths` at the scan handler (a change of `withEngineDeny` could drop it) | `ENG-S03i` (database; real orchestrator, scan handler, archive store) | The Secrets engine's tree has none of the three names at the root or at any depth, also inside a user-excluded directory, and with `exclusions.paths` of `**`; the user's exclusions still apply; look-alike names stay; the engine of another scan type receives all of them (control) |
| The Gitleaks `--max-target-megabytes 5` cap was only part of a whole-line equality | `ENG-S03j` | The flag is in the arguments the sandbox is given (after the image), once, with the value 5, before `/src`; the inspection reports each of seven mutated copies (negative control) |
| SE-5 was guarded for `ensemble/core` and `packages/shared/src/scan-engines` only | `ENG-S03k` | No file under `ensemble/**` imports a network, process or thread module, calls `fetch`, `eval` or `new Function`, reads `process.env`, names a SecretStore, GitHub client or LLM provider, or imports the database package outside `engine/wiring.js`; ten planted violations are reported |
| ENG-S04 (no credentials) was proved at the runner, not through the engine, and not for the `fork` trust level | `ENG-S04b` | Planted credentials in the worker process environment never appear in any recorded runtime call of the real SBOM engine, trusted or fork; container environment names are on the allowlist |

Checks added after the sweep to kill security-critical survivors (section 3.2; each was re-run against its mutants and kills them):

| Check | Kills (survivors of the sweep) |
|---|---|
| `ENG-S01c` | the sandbox argument audit with a seccomp profile other than the configured one (`build-run-args.js` 160); the reserved egress network names `bridge` and `default` dropped from the refusal list (`config.js` 41, 42) |
| `ENG-S03l` | the container name check of the CLI driver (`cli-runtime.js` 139): `remove` and `kill` with a name that starts with a dash would have been an option of `rm -f` |
| `ENG-S03m` | one unsafe target among safe ones accepted by the plan of the SAST and Secrets tools (`sast/plan.js` 58, `every` turned into `some`, SE-27) |
| `ENG-S07d` | the quarantine list of the DB mirror losing `trivy-os`, `chainguard` or `wolfi` (`dbmirror/sources.js` 38 to 40) and the tree name guard (`archive/tree.js` 40) |
| `ENG-S13f` | the credential-shaped run test of the secret line mask (`evidence/mask.js` 47, 48, 52: a known prefix of 8 characters, runs of 15 and 16 characters, the 20 character entropy rule) and the permalink name guard (`evidence/permalink.js` 100) |

Not gaps (recorded so nobody re-audits them): SE-47 and SE-48 (display text and legal process, see 1.1). Item still open from earlier reports: the engine-level planted-environment run is done for the SBOM engine only (see `ENG-S04b`).

## 2. Mutation sweep

### 2.1 Method and tooling

The earlier sweeps (Executions part I, 365 mutants, stopped at 308) kept their generator in a session scratchpad, so part M wrote reusable tooling under `apps/api/scripts/` (a development tool, not part of `pnpm test:security`):

- `mutation-sweep.js` (driver). `map` runs every Docker-free check alone under V8 coverage and records which check executes which source range. `run` generates operator mutants of the target files, applies ONE at a time and runs only the checks that execute the mutated line, in the order "checks that killed an earlier mutant of the file first, then the fastest". Operators: `===` and `!==`, `&&` and `||`, comparison boundaries, `true` and `false`, a removed negation in a condition, an integer literal plus one, `startsWith` and `endsWith`, `every` and `some`, `Math.min` and `Math.max`, a removed array element line (flag lists, allowlists), a removed statement call, a removed `continue` or `break`, a statement turned into `return undefined`. Comments, strings, template text and regular expression literals are never mutated (a small tokenizer). Selection is deterministic (seed 20261122): round robin over the operators, at most 30 covered mutants per file in the first pass and 12 in the second, at most 10 and 4 module-level ones (a constant or exported table, covered by every check that loads the file, so a survivor costs a full run), and two uncovered ones per file.
- `mutation-worker.js` runs the Docker-free, database-free, network-free checks IN PROCESS (the `run()` functions of the suite group "Scan engines: sandbox invocation and runner") and stops at the first failing check; `mutation-hook.js` and `mutation-register.js` replace the source of ONE module in memory (a Node module loader hook), so **the working tree is never written** for these runs. A source guard that reads a source FILE sees the unmutated text.
- `http`, `rerun` and `dbsweep` handle the code that only database or HTTP checks cover (the repository SBOM download route, the DB refresh worker, the tool run DTO): the file is changed IN PLACE, the real suite runs filtered (`SECURITY_SUITE_ONLY`), and the file is restored in a `finally` and on a signal. `confirm` re-runs, one at a time, every kill attributed to a check that is sensitive to machine load (capacity timers, event loop slices, heap and time guards: `ENG-S14a`, `ENG-S14b`, `ENG-S17a` to `ENG-S17c`, `ENG-S02a`, `ENG-S09d`, `ENG-S10a` to `ENG-S10c`) so a kill produced only by a loaded machine is found. `report` writes the tables and lists below.
- Verdicts: killed (a check failed), timeout (the run did not end: an infinite loop is a kill by the clock, counted apart), survived (every covering check stayed green; a line that no Docker-free check executes is also a survivor), invalid (the mutant did not compile).

### 2.2 Result

- **1426 mutants in 85 of the 91 files in scope** (the other six hold no executable statement: re-export `index.js` files and the `dbrefresh` entry point): **1191 killed, 12 timeouts, 219 survived, 4 invalid; kill rate 84.6 percent** of the 1422 valid mutants (killed plus timeout). 16 of the kills come from checks added after the sweep (section 1.3, listed in 3.2); without them 1175 killed, 235 survived, 83.5 percent. The 1426 are 1384 Docker-free mutants (two passes: 867 mutants with the first caps, stopped when the survivors of the large engine files made the run too slow, then 517 with lower caps for the files that had no result yet), 25 database-world mutants of `dbrefresh/refresh.js` and 17 of the repository SBOM download. They are a bounded sample of the 4367 candidates of the 91 files, not the whole population.
- Kills by load-sensitive checks: 124 kills were attributed to them; the serial re-run confirmed 123; **one (`R0163`, `ENG-S09d`) was not confirmed and is counted as a survivor.** The first map run under a load of 12 parallel workers showed `ENG-S02a` and `ENG-S09d` failing; both pass alone and under a load of 8.
- The sweep needs about two hours on a 16 core machine (map 1.5 minutes, the Docker-free mutants about 70 minutes, database and HTTP mutants about 30 minutes). To repeat it: from `apps/api`, `node scripts/mutation-sweep.js map`, then `run --per-file 30 --module-level 10 --jobs 10`, then `report`; the commands of 2.1 for the other parts. A new Docker-free check array must be added to `mutation-worker.js`.

### 2.3 Limits of this sweep (read before trusting a kill rate)

- A sample, not the population (above); the two passes used different caps.
- The coverage map is built from the Docker-free checks only. The database checks (`ENG-S08*`, `ENG-S12h` to `ENG-S12n`, `ENG-S16c`, `ENG-S16e`) and the HTTP checks are not in it: a line that only they execute is reported "not executed by any Docker-free check" and can be a false survivor. `dbrefresh/*` and `tool-dto.js` were re-run against the database and HTTP checks; other database-only code (`packages/db` scan engine repositories, the database parts of `engine/wiring.js`) was not.
- Mutation of a module is in memory, so a check that READS a source file (the source guards `ENG-S03a`, `ENG-S03b`, `ENG-S12g`, `ENG-S17b`, `ENG-S03k`) sees the original text; a guard is never credited with a kill it did not earn, and a mutant that only a guard could kill shows as a survivor.
- Equivalent mutants are not removed (triage is deferred): a changed memory or CPU limit by one, an error message, a sort comparator that never ties and a log line are among the survivors.

## 3. Survivors (disposition in section 4; a line without a `->` disposition is NOT triaged and stays on the full triage (A))

### 3.1 Totals per file


| File | Mutants | Killed | Survived | Timeout | Invalid |
|---|---|---|---|---|---|
| `apps/workers/src/dbrefresh/canary.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/dbrefresh/index.js` | 10 | 9 | 1 | 0 | 0 |
| `apps/workers/src/dbrefresh/refresh.js` | 31 | 29 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/catalog/index.js` | 7 | 7 | 0 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/core/adapter.js` | 30 | 28 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/core/fingerprint.js` | 3 | 1 | 1 | 0 | 1 |
| `apps/workers/src/execution/engines/ensemble/core/merge-keys.js` | 30 | 27 | 3 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/core/merger.js` | 32 | 20 | 8 | 2 | 2 |
| `apps/workers/src/execution/engines/ensemble/core/parse-kit.js` | 30 | 28 | 1 | 1 | 0 |
| `apps/workers/src/execution/engines/ensemble/core/run-parse.js` | 30 | 28 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/core/scrub.js` | 23 | 23 | 0 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/core/storage.js` | 32 | 27 | 5 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/core/yield.js` | 24 | 20 | 0 | 4 | 0 |
| `apps/workers/src/execution/engines/ensemble/db/resolve-db.js` | 2 | 2 | 0 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/constants.js` | 2 | 2 | 0 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/container-run.js` | 6 | 5 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/engine.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/run-manifest.js` | 5 | 1 | 4 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/sast-engine.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/sbom-redaction.js` | 12 | 11 | 0 | 1 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/sca-engine.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/secrets-engine.js` | 12 | 10 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/tool-exit.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/tree-paths.js` | 12 | 10 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/engine/wiring.js` | 14 | 3 | 11 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/evidence/block-extractor.js` | 14 | 10 | 4 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/evidence/constants.js` | 4 | 3 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/evidence/enrich.js` | 14 | 8 | 6 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/evidence/mask.js` | 14 | 6 | 8 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/evidence/permalink.js` | 13 | 11 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/evidence/secret-preview.js` | 12 | 5 | 7 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/evidence/snippet.js` | 14 | 9 | 5 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/evidence/source.js` | 13 | 7 | 6 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sast/bandit.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sast/common.js` | 13 | 9 | 4 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sast/index.js` | 8 | 6 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sast/languages.js` | 13 | 11 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sast/opengrep.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sast/plan.js` | 12 | 9 | 3 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sast/rule-pack.js` | 12 | 7 | 5 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sast/scope.js` | 12 | 10 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sbom/cyclonedx.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sbom/index.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sbom/plan.js` | 12 | 12 | 0 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sbom/sbom-lite.js` | 12 | 10 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sbom/syft.js` | 4 | 4 | 0 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sbom/trivy-sbom.js` | 5 | 5 | 0 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sca/common.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sca/index.js` | 12 | 11 | 1 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sca/osv-scanner.js` | 12 | 12 | 0 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sca/plan.js` | 12 | 9 | 3 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/sca/trivy-vuln.js` | 14 | 12 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/secrets/common.js` | 12 | 6 | 6 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/secrets/detect-secrets.js` | 12 | 10 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/secrets/gitleaks.js` | 12 | 9 | 3 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/secrets/index.js` | 8 | 6 | 2 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/secrets/plan.js` | 5 | 1 | 4 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/secrets/scope.js` | 14 | 11 | 3 | 0 | 0 |
| `apps/workers/src/execution/engines/ensemble/secrets/type-class.js` | 12 | 8 | 4 | 0 | 0 |
| `packages/infra/src/archive/errors.js` | 1 | 1 | 0 | 0 | 0 |
| `packages/infra/src/archive/tar.js` | 32 | 20 | 12 | 0 | 0 |
| `packages/infra/src/archive/tree.js` | 30 | 29 | 1 | 0 | 0 |
| `packages/infra/src/dbmirror/inspect.js` | 30 | 27 | 3 | 0 | 0 |
| `packages/infra/src/dbmirror/sources.js` | 30 | 27 | 2 | 0 | 1 |
| `packages/infra/src/dbmirror/store.js` | 31 | 30 | 1 | 0 | 0 |
| `packages/infra/src/sandbox/build-run-args.js` | 31 | 30 | 1 | 0 | 0 |
| `packages/infra/src/sandbox/capacity.js` | 31 | 27 | 3 | 1 | 0 |
| `packages/infra/src/sandbox/cli-runtime.js` | 32 | 27 | 5 | 0 | 0 |
| `packages/infra/src/sandbox/config.js` | 30 | 29 | 1 | 0 | 0 |
| `packages/infra/src/sandbox/errors.js` | 1 | 1 | 0 | 0 | 0 |
| `packages/infra/src/sandbox/fake-runtime.js` | 30 | 25 | 5 | 0 | 0 |
| `packages/infra/src/sandbox/image-catalog.js` | 31 | 27 | 4 | 0 | 0 |
| `packages/infra/src/sandbox/janitor.js` | 19 | 17 | 2 | 0 | 0 |
| `packages/infra/src/sandbox/policy.js` | 10 | 8 | 2 | 0 | 0 |
| `packages/infra/src/sandbox/run-spec.js` | 31 | 29 | 2 | 0 | 0 |
| `packages/infra/src/sandbox/runner.js` | 10 | 8 | 2 | 0 | 0 |
| `packages/infra/src/sandbox/runtime.js` | 5 | 0 | 4 | 1 | 0 |
| `packages/shared/src/scan-engines/constants.js` | 15 | 13 | 2 | 0 | 0 |
| `packages/shared/src/scan-engines/cvss.js` | 30 | 25 | 4 | 1 | 0 |
| `packages/shared/src/scan-engines/db-mirror.js` | 30 | 25 | 4 | 1 | 0 |
| `packages/shared/src/scan-engines/finding.js` | 30 | 28 | 2 | 0 | 0 |
| `packages/shared/src/scan-engines/json-size.js` | 26 | 26 | 0 | 0 | 0 |
| `packages/shared/src/scan-engines/rollup.js` | 30 | 29 | 1 | 0 | 0 |
| `packages/shared/src/scan-engines/severity.js` | 30 | 30 | 0 | 0 | 0 |
| `packages/shared/src/scan-engines/tool-dto.js` | 10 | 1 | 9 | 0 | 0 |

### 3.1b Repository SBOM download route (in place, against `ENG-S08i` and `DAL-317`)

Three survivors, all probably equivalent or low value, not asserted: `H009` (the `ETag` header removed when the audit write fails: the failing download is already refused), `H015` (the `read` rate limit removed from the route declaration: a global default may apply), `H017` (the `nosniff` header removed from the controller: `ENG-S08i` asserts the header and still passes, so another layer, probably the global header middleware, sets it).

| File | Mutants | Killed | Survived |
|---|---|---|---|
| `apps/api/src/modules/repositories/controllers/index.js` | 10 | 8 | 2 |
| `apps/api/src/modules/repositories/mappers/index.js` | 2 | 2 | 0 |
| `apps/api/src/modules/repositories/routes/index.js` | 2 | 1 | 1 |
| `apps/api/src/modules/repositories/schemas/index.js` | 2 | 2 | 0 |
| `apps/api/src/modules/repositories/services/index.js` | 1 | 1 | 0 |

- `H009` apps/api/src/modules/repositories/controllers/index.js line 51 drop-call: `reply.removeHeader("ETag");` -> `;`
- `H015` apps/api/src/modules/repositories/routes/index.js line 96 manual: `sbom route without rate limit` -> (the route declaration without the rate limit line)
- `H017` apps/api/src/modules/repositories/controllers/index.js line 45 manual: `sbom nosniff removed` -> `(removed)`

### 3.2 Which survivors look security-relevant (the note that drove the triage of section 4)

Killed after the sweep by the checks of section 1.3 (the survivors are listed with their verdict changed to killed): `build-run-args.js` 160, `config.js` 41 and 42, `cli-runtime.js` 139, `dbmirror/sources.js` 38 to 40, `archive/tree.js` 40, `sast/plan.js` 58, `evidence/permalink.js` 100, `evidence/mask.js` 47, 48 and 52 (16 mutants).

Still surviving and worth looking at first (the first four groups touch redaction, hostile input and evidence):

1. **Secret masking** (`evidence/mask.js` 36, 65, 86, 87, 103, 170; `evidence/secret-preview.js` 29, 36, 45, 52, 55, 56; `evidence/snippet.js` 17, 19, 83, 97): boundaries of the masked line preview. A moved boundary can show more of a secret line than the rule says. `ENG-S13d` and `ENG-S05f` assert the properties on real tool output but not each boundary.
2. **Secrets mapping and hostile records** (`secrets/common.js` 55 to 67, `secrets/gitleaks.js` 90 and 110, `secrets/detect-secrets.js` 50, `secrets/type-class.js` 52 to 54 and 123): the object guard `&&` turned into `||`, the redacted title and name length, the known type labels.
3. **Hostile archive parsing** (`archive/tar.js` 62, 66, 143, 177; `archive/tree.js` 43; `dbmirror/inspect.js` 53, 96, and 45 which is probably equivalent): the PAX header length arithmetic, the end-of-archive flag and the ustar prefix join.
4. **Evidence file reads** (`evidence/source.js` 29, 35, 51, 52, 70): 29 is probably equivalent (the real-path containment check that follows refuses every escape), 35 is the file size cap boundary.
5. **Engine wiring and capacity** (`engine/wiring.js` 30, 31, 45, 121; `engine/secrets-engine.js` 141 and 260; `sandbox/capacity.js` 43, 54 (timeout), 92, 99; `sandbox/runner.js` 32, 60; `sandbox/janitor.js` 59, 60): the database readiness gate of the SCA engine, the fork share, the in-scope flag of secret findings, release of capacity, the janitor failure count.
6. **Sandbox configuration and catalog** (`sandbox/image-catalog.js` 94, 129, 132 and 305 (a placeholder digest is refused in production only: the mutant refuses it everywhere, so the production rule is asserted but the development rule is not), `sandbox/config.js` 105 (`every` turned into `some` over the forbidden mount roots), `sandbox/policy.js` 19 and 20 (Grype variables, a deferred tool), `sandbox/run-spec.js` 77 (equivalent: an empty first segment is refused by the next line) and 101).
7. **DB mirror and refresh** (`dbmirror/sources.js` 82, 83, 97 (invalid), `dbmirror/store.js` 258, `dbrefresh/refresh.js` 39, `dbrefresh/canary.js` 57, `dbrefresh/index.js` 73): record caps, the staging cleanup, the canary identifier length, the abandon time.
8. **Repository SBOM download**: see 3.1b.

Probably equivalent or low value (not asserted): sort comparators (`core/merger.js` 54, `engine/run-manifest.js` 15, `sast/languages.js` 164), constant limits moved by one (`MiB`, CPU counts, buffer sizes, `SEVERITY_RANK`), error and log message elements dropped from a list, the key size of the in-task HMAC (`core/fingerprint.js` 11), `shared/scan-engines/tool-dto.js` (the enumerated words of the tool run DTO: `ENG-S08g` and `ENG-S08h` do not enumerate them).

### 3.3 Survivors by file

Format: `id`, line, operator, the replaced text and its replacement, the line. An id starting with `M` is the first pass, `R` the second, `D` the database-world pass.

### apps/workers/src/dbrefresh/canary.js

killed 11, survived 1, timeout 0, invalid 0

- `R0501` line 57 bound: `<=` -> `<` in `if (typeof node[key] === "string" && node[key].length <= 120) ids.add(node[key]);` **-> killed by ENG-S09h**

### apps/workers/src/dbrefresh/index.js

killed 9, survived 1, timeout 0, invalid 0

- `R0510` line 73 int (not executed by any Docker-free check): `1000` -> `1001` in `olderThanMs: scanDb.candidateAbandonSeconds * 1000,`

### apps/workers/src/dbrefresh/refresh.js

killed 29, survived 2, timeout 0, invalid 0

- `R0514` line 39 int: `50` -> `51` in `sources: z.array(z.string().max(64)).min(1).max(50),`
- `D0002` line 39 int: `50` -> `51` in `sources: z.array(z.string().max(64)).min(1).max(50),`

### apps/workers/src/execution/engines/ensemble/catalog/index.js

killed 7, survived 0, timeout 0, invalid 0


### apps/workers/src/execution/engines/ensemble/core/adapter.js

killed 28, survived 2, timeout 0, invalid 0

- `M0628` line 84 quantifier: `every` -> `some` in `!exitCodes.every((c) => Number.isInteger(c))`
- `M0630` line 124 drop-element: `          "An adapter is already registered for this tool and scan type.",` -> `(removed)` in `"An adapter is already registered for this tool and scan type.",` **-> killed by ENG-S06o**

### apps/workers/src/execution/engines/ensemble/core/fingerprint.js

killed 1, survived 1, timeout 0, invalid 1

- `M0654` line 11 int: `32` -> `33` in `const key = randomBytes(32);`

### apps/workers/src/execution/engines/ensemble/core/merge-keys.js

killed 27, survived 3, timeout 0, invalid 0

- `M0668` line 44 bound: `<=` -> `<` in `if (slash <= 0) return null;`
- `M0664` line 57 quantifier: `some` -> `every` in `if (decoded.some((s) => s === null || s === "" || CONTROL.test(s))) return null;`
- `M0685` line 82 bound: `<=` -> `<` in `if (eq <= 0) continue;`

### apps/workers/src/execution/engines/ensemble/core/merger.js

killed 20, survived 8, timeout 2, invalid 2

- `M0689` line 54 int: `1` -> `2` in `const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);` **-> equivalent: `cmp` is read only as the sign (or the truthiness) of a sort comparator, so `1` and `2` order identically**
- `M0700` line 54 int: `1` -> `2` in `const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);`
- `M0711` line 60 int: `3` -> `4` in `const SCOPE_RANK = { prod: 3, dev: 2, optional: 1, peer: 1, unknown: 0 };`
- `M0712` line 69 logic: `||` -> `&&` in `cmp(pathOf(a), pathOf(b)) ||`
- `M0715` line 273 drop-jump: `break;` -> `;` in `break;`
- `M0717` line 317 logic (not executed by any Docker-free check): `||` -> `&&` in `cmp(a.ruleId ?? "", b.ruleId ?? "") ||` **-> equivalent given the merge invariant: the tie-break operands run only for two members of ONE tool, and a merged finding holds at most one member per tool (SE-12: two records of one tool at one key stay two findings, shown for SBOM, SAST, Secrets and SCA); the line is never executed**
- `M0718` line 403 int (not executed by any Docker-free check): `1` -> `2` in `? -1`
- `M0707` line 450 drop-element: `        "A candidate belongs to another scan type.",` -> `(removed)` in `"A candidate belongs to another scan type.",`

### apps/workers/src/execution/engines/ensemble/core/parse-kit.js

killed 28, survived 1, timeout 1, invalid 0

- `M0731` line 43 bound: `<` -> `<=` in `for (let i = 0; i < buffer.length; i += 1) {`

### apps/workers/src/execution/engines/ensemble/core/run-parse.js

killed 28, survived 2, timeout 0, invalid 0

- `M0754` line 75 bound: `>` -> `>=` in `Number.isInteger(parsed.fileErrors) && parsed.fileErrors > 0 ? parsed.fileErrors : 0;`
- `M0773` line 75 logic: `&&` -> `||` in `Number.isInteger(parsed.fileErrors) && parsed.fileErrors > 0 ? parsed.fileErrors : 0;` **-> killed by ENG-S06o**

### apps/workers/src/execution/engines/ensemble/core/scrub.js

killed 23, survived 0, timeout 0, invalid 0


### apps/workers/src/execution/engines/ensemble/core/storage.js

killed 27, survived 5, timeout 0, invalid 0

- `M0811` line 32 eq: `===` -> `!==` in `(d.scmRef === null ? 0 : jsonbTextBytes(d.scmRef)) +`
- `M0815` line 112 int: `1` -> `2` in `const normalized = normalizeItems([findingToItem(finding)], 1);`
- `M0832` line 115 drop-jump (not executed by any Docker-free check): `continue;` -> `;` in `continue;`
- `M0827` line 133 logic: `||` -> `&&` in `detailRowBytes(detail) > FINDING_LIMITS.detailRowBytes ||`
- `M0833` line 136 int (not executed by any Docker-free check): `1` -> `2` in `dropped += 1;` **-> killed by ENG-S06o**

### apps/workers/src/execution/engines/ensemble/core/yield.js

killed 20, survived 0, timeout 4, invalid 0


### apps/workers/src/execution/engines/ensemble/db/resolve-db.js

killed 2, survived 0, timeout 0, invalid 0


### apps/workers/src/execution/engines/ensemble/engine/constants.js

killed 2, survived 0, timeout 0, invalid 0


### apps/workers/src/execution/engines/ensemble/engine/container-run.js

killed 5, survived 1, timeout 0, invalid 0

- `M0868` line 36 minmax: `max` -> `min` in `const end = Math.max(now(), startedMs);`

### apps/workers/src/execution/engines/ensemble/engine/engine.js

killed 11, survived 1, timeout 0, invalid 0

- `R0004` line 88 minmax: `max` -> `min` in `const end = Math.max(now(), startedMs);`

### apps/workers/src/execution/engines/ensemble/engine/run-manifest.js

killed 1, survived 4, timeout 0, invalid 0

- `R0016` line 15 bound: `>` -> `>=` in `.sort((a, b) => (a.toolId < b.toolId ? -1 : a.toolId > b.toolId ? 1 : 0))` **-> equivalent given the unique tool id invariant: the adapter registry refuses a second adapter for a tool and scan type (`adapter_duplicate`, ENG-S06o), so the comparator never sees two equal ids**
- `R0017` line 15 int: `1` -> `2` in `.sort((a, b) => (a.toolId < b.toolId ? -1 : a.toolId > b.toolId ? 1 : 0))`
- `R0013` line 15 bound: `<` -> `<=` in `.sort((a, b) => (a.toolId < b.toolId ? -1 : a.toolId > b.toolId ? 1 : 0))`
- `R0014` line 15 int: `1` -> `2` in `.sort((a, b) => (a.toolId < b.toolId ? -1 : a.toolId > b.toolId ? 1 : 0))`

### apps/workers/src/execution/engines/ensemble/engine/sast-engine.js

killed 11, survived 1, timeout 0, invalid 0

- `R0019` line 61 logic: `||` -> `&&` in `if (typeof rulesDir !== "string" || !path.isAbsolute(rulesDir))`

### apps/workers/src/execution/engines/ensemble/engine/sbom-redaction.js

killed 11, survived 0, timeout 1, invalid 0


### apps/workers/src/execution/engines/ensemble/engine/sca-engine.js

killed 11, survived 1, timeout 0, invalid 0

- `R0045` line 111 drop-call: `ctx.log("warn", 'The vulnerability database of ${adapter.toolId} could not be resolved');` -> `;` in `ctx.log("warn", 'The vulnerability database of ${adapter.toolId} could not be resolved');`

### apps/workers/src/execution/engines/ensemble/engine/secrets-engine.js

killed 10, survived 2, timeout 0, invalid 0

- `R0058` line 141 bool: `true` -> `false` in `candidates: outcome.candidates.map((c) => ({ ...c, scope: { kind, inScope: true } })),`
- `R0060` line 260 bound: `>` -> `>=` in `...(enriched.summary.capped > 0 ? [EVIDENCE_CAPPED_NOTE_CODE] : []),` **-> killed by ENG-S16h**

### apps/workers/src/execution/engines/ensemble/engine/tool-exit.js

killed 11, survived 1, timeout 0, invalid 0

- `R0071` line 34 int: `1024` -> `1025` in `export const TOOL_EXIT_STDERR_BYTES = 16 * 1024;`

### apps/workers/src/execution/engines/ensemble/engine/tree-paths.js

killed 10, survived 2, timeout 0, invalid 0

- `R0087` line 27 bool: `false` -> `true` in `let exists = false;`
- `R0082` line 34 bound: `<` -> `<=` in `if (cache.size < TREE_PATH_CACHE_MAX) cache.set(relativePath, exists);`

### apps/workers/src/execution/engines/ensemble/engine/wiring.js

killed 3, survived 11, timeout 0, invalid 0

- `R0090` line 30 eq: `===` -> `!==` in `const dbReady = typeof d.cacheRoot === "string" && typeof d.mirrorRoot === "string";` **-> killed by ENG-S16h**
- `R0102` line 30 logic (not executed by any Docker-free check): `&&` -> `||` in `const dbReady = typeof d.cacheRoot === "string" && typeof d.mirrorRoot === "string";` **-> killed by ENG-S16h**
- `R0103` line 30 eq (not executed by any Docker-free check): `===` -> `!==` in `const dbReady = typeof d.cacheRoot === "string" && typeof d.mirrorRoot === "string";` **-> killed by ENG-S16h**
- `R0091` line 31 negation: `!` -> `(removed)` in `if (!dbReady)` **-> killed by ENG-S16h**
- `R0093` line 45 int: `1` -> `2` in `const forkShare = Math.max(1, Math.floor((s.maxContainers * s.untrustedCapacityShare) / 100));` **-> killed by ENG-S16h**
- `R0092` line 45 minmax: `max` -> `min` in `const forkShare = Math.max(1, Math.floor((s.maxContainers * s.untrustedCapacityShare) / 100));` **-> killed by ENG-S16h**
- `R0098` line 45 int: `100` -> `101` in `const forkShare = Math.max(1, Math.floor((s.maxContainers * s.untrustedCapacityShare) / 100));` **-> killed by ENG-S16h**
- `R0099` line 58 int: `1000` -> `1001` in `toolWaitMs: s.waitSeconds * 1000,` **-> killed by ENG-S16h**
- `R0100` line 74 int: `1000` -> `1001` in `toolWaitMs: s.waitSeconds * 1000,` **-> deferred to full triage A before GA: the SCA engine acquires capacity only with a promoted database snapshot (a mirror object, a database row and a cache directory); the same expression is killed for the SBOM engine (`R0099`) and the SAST engine (`R0101`) by ENG-S16h**
- `R0101` line 84 int: `1000` -> `1001` in `toolWaitMs: s.waitSeconds * 1000,` **-> killed by ENG-S16h**
- `R0095` line 121 bound: `>` -> `>=` in `if (r.removed.length > 0)` **-> killed by ENG-S16h**

### apps/workers/src/execution/engines/ensemble/evidence/block-extractor.js

killed 10, survived 4, timeout 0, invalid 0

- `R0104` line 15 int: `1024` -> `1025` in `const MiB = 1024 * 1024;`
- `R0114` line 15 int: `1024` -> `1025` in `const MiB = 1024 * 1024;` **-> killed by ENG-S09h**
- `R0116` line 225 logic (not executed by any Docker-free check): `&&` -> `||` in `return error instanceof SandboxError && error.code === "image_unavailable"`
- `R0117` line 225 eq (not executed by any Docker-free check): `===` -> `!==` in `return error instanceof SandboxError && error.code === "image_unavailable"`

### apps/workers/src/execution/engines/ensemble/evidence/constants.js

killed 3, survived 1, timeout 0, invalid 0

- `R0121` line 13 int: `4096` -> `4097` in `snippetBytes: 4096,`

### apps/workers/src/execution/engines/ensemble/evidence/enrich.js

killed 8, survived 6, timeout 0, invalid 0

- `R0122` line 30 int: `1` -> `2` in `const RANK = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });`
- `R0130` line 30 int: `2` -> `3` in `const RANK = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });` **-> killed by ENG-S13i**
- `R0131` line 35 logic: `||` -> `&&` in `(a.location?.path ?? "").localeCompare(b.location?.path ?? "") ||`
- `R0127` line 98 bound: `>` -> `>=` in `if (extractor && code.length > 0 && !signal?.aborted) {`
- `R0134` line 160 eq (not executed by any Docker-free check): `===` -> `!==` in `if (f.kind === "secret") summary.secretOmitted += 1;`
- `R0135` line 161 drop-jump (not executed by any Docker-free check): `continue;` -> `;` in `continue;`

### apps/workers/src/execution/engines/ensemble/evidence/mask.js

killed 6, survived 8, timeout 0, invalid 0

- `R0136` line 18 int: `300` -> `301` in `export const MAX_LINE_CHARS = 300;` **-> killed by ENG-S13g**
- `R0146` line 36 int: `1` -> `2` in `for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);` **-> killed by ENG-S13g**
- `R0137` line 39 return-undefined: `return h;` -> `return undefined;` in `return h;` **-> killed by ENG-S13g**
- `R0141` line 65 minmax: `max` -> `min` in `KNOWN_PREFIX.test(line.slice(Math.max(0, start - 12), start + m[0].length))` **-> killed by ENG-S13g**
- `R0143` line 86 eq: `===` -> `!==` in `if (s < e && (line[s] === "=" || line[s] === ":")) s += 1;` **-> killed by ENG-S13g, ENG-S13h**
- `R0144` line 87 negation: `!` -> `(removed)` in `while (s > 0 && !BOUNDARY.has(line[s - 1]) && line[s - 1] !== "=" && line[s - 1] !== ":") s -= 1;` **-> killed by ENG-S13g**
- `R0149` line 103 int (not executed by any Docker-free check): `1` -> `2` in `const start = span.startColumn === undefined ? 1 : span.startColumn;` **-> equivalent: only reached as `Math.max(0, a - 1)` with `a = start - 1`; a start column of 1 and of 2 both give `0` (the UTF-8 reading gives `unitAt(1) - 1 = 0` as well), so the default start column cannot be observed**
- `R0145` line 170 quantifier: `every` -> `some` in `if (own.every(([a, b]) => b <= a)) return null;` **-> killed by ENG-S13g**

### apps/workers/src/execution/engines/ensemble/evidence/permalink.js

killed 11, survived 2, timeout 0, invalid 0

- `R0150` line 23 int: `2000` -> `2001` in `const MAX_URL = 2000;` **-> killed by ENG-S13i**
- `R0162` line 116 return-undefined (not executed by any Docker-free check): `return null;` -> `return undefined;` in `return null;`

### apps/workers/src/execution/engines/ensemble/evidence/secret-preview.js

killed 5, survived 7, timeout 0, invalid 0

- `R0163` line 16 int (not executed by any Docker-free check): `2000` -> `2001` in `const MAX_RANGE_MARKED = 2000;` **-> killed by ENG-S13h**
- `R0165` line 29 bool: `false` -> `true` in `entry = { spans: [], unknown: false, carries: true, typeClass: "other" };` **-> killed by ENG-S13h**
- `R0168` line 36 logic: `||` -> `&&` in `if (!loc?.path || !Number.isInteger(loc.startLine)) continue;` **-> killed by ENG-S13h**
- `R0169` line 45 eq: `===` -> `!==` in `if (end === loc.startLine) {` **-> killed by ENG-S13h**
- `R0170` line 52 drop-jump: `continue;` -> `;` in `continue;` **-> killed by ENG-S13h**
- `R0171` line 55 bound: `<=` -> `<` in `if (end - loc.startLine <= MAX_RANGE_MARKED)` **-> killed by ENG-S13h**
- `R0173` line 56 int: `1` -> `2` in `for (let n = loc.startLine + 1; n < end; n += 1) mark(n, null);` **-> killed by ENG-S13h**

### apps/workers/src/execution/engines/ensemble/evidence/snippet.js

killed 9, survived 5, timeout 0, invalid 0

- `R0175` line 17 bound: `>` -> `>=` in `return line.length > EVIDENCE_CAPS.lineChars` **-> killed by ENG-S13h**
- `R0185` line 19 bool: `false` -> `true` in `: { text: line, cut: false };` **-> killed by ENG-S13h**
- `R0177` line 32 int: `1` -> `2` in `let last = from - 1;` **-> killed by ENG-S13h**
- `R0187` line 83 bool (not executed by any Docker-free check): `true` -> `false` in `...(joined.truncated ? { truncated: true } : {}),` **-> killed by ENG-S13h**
- `R0188` line 97 bound (not executed by any Docker-free check): `<` -> `<=` in `if (again.last < startLine) return null;` **-> killed by ENG-S13h**

### apps/workers/src/execution/engines/ensemble/evidence/source.js

killed 7, survived 6, timeout 0, invalid 0

- `R0191` line 29 logic: `||` -> `&&` in `if (typeof root !== "string" || !path.isAbsolute(root) || !isSafeRelativePath(relativePath))`
- `R0199` line 29 logic: `||` -> `&&` in `if (typeof root !== "string" || !path.isAbsolute(root) || !isSafeRelativePath(relativePath))`
- `R0194` line 35 bound: `>` -> `>=` in `if (!stat.isFile() || stat.size > maxBytes) return null;`
- `R0196` line 51 int: `1` -> `2` in `if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();` **-> killed by ENG-S13i**
- `R0201` line 52 int (not executed by any Docker-free check): `1` -> `2` in `return lines.map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));`
- `R0197` line 70 drop-call: `cache.delete(relativePath);` -> `;` in `cache.delete(relativePath);`

### apps/workers/src/execution/engines/ensemble/sast/bandit.js

killed 11, survived 1, timeout 0, invalid 0

- `R0206` line 102 int: `5000` -> `5001` in `? r.line_range.filter(Number.isInteger).slice(0, 5000)`

### apps/workers/src/execution/engines/ensemble/sast/common.js

killed 9, survived 4, timeout 0, invalid 0

- `R0214` line 19 int: `1` -> `2` in `export const text = (max, min = 1) =>`
- `R0217` line 36 logic: `&&` -> `||` in `return Number.isInteger(n) && n >= 1 && n <= 100000 ? n : null;` **-> killed by ENG-S13i**
- `R0218` line 36 bound: `>=` -> `>` in `return Number.isInteger(n) && n >= 1 && n <= 100000 ? n : null;`
- `R0226` line 81 bool (not executed by any Docker-free check): `true` -> `false` in `truncated = true;`

### apps/workers/src/execution/engines/ensemble/sast/index.js

killed 6, survived 2, timeout 0, invalid 0

- `R0233` line 66 bool (not executed by any Docker-free check): `true` -> `false` in `export function runSastEnsemble({ taskRef, runs, relevantFilesExist = true, coverageGaps = [] }) {`
- `R0234` line 75 drop-call (not executed by any Docker-free check): `tools.push({ toolId: run.adapter.toolId, status: outcome.status, reason: outcome.reason })` -> `;` in `tools.push({ toolId: run.adapter.toolId, status: outcome.status, reason: outcome.reason });`

### apps/workers/src/execution/engines/ensemble/sast/languages.js

killed 11, survived 2, timeout 0, invalid 0

- `R0247` line 164 int (not executed by any Docker-free check): `1` -> `2` in `list.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));`
- `R0244` line 164 drop-call: `list.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));` -> `;` in `list.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));` **-> deferred to full triage A before GA: only the order of `readdir` is changed, which decides WHICH entries survive a truncating cap; killing it needs a filesystem seam (or a fixed directory order) that does not exist**

### apps/workers/src/execution/engines/ensemble/sast/opengrep.js

killed 11, survived 1, timeout 0, invalid 0

- `R0253` line 138 int: `10` -> `11` in `.slice(0, 10),`

### apps/workers/src/execution/engines/ensemble/sast/plan.js

killed 9, survived 3, timeout 0, invalid 0

- `R0267` line 11 int: `1024` -> `1025` in `const MiB = 1024 * 1024;`
- `R0260` line 11 int: `1024` -> `1025` in `const MiB = 1024 * 1024;`
- `R0271` line 16 int: `2` -> `3` in `cpus: 2,` **-> killed by ENG-S09h**

### apps/workers/src/execution/engines/ensemble/sast/rule-pack.js

killed 7, survived 5, timeout 0, invalid 0

- `R0272` line 21 int: `50` -> `51` in `export const RULE_PACK_LIMITS = Object.freeze({ files: 50, bytesPerFile: 512 * 1024, rules: 2000 });`
- `R0281` line 21 int: `512` -> `513` in `export const RULE_PACK_LIMITS = Object.freeze({ files: 50, bytesPerFile: 512 * 1024, rules: 2000 });`
- `R0276` line 53 bound: `>` -> `>=` in `if (files.length > RULE_PACK_LIMITS.files) problems.push("the pack has too many files");`
- `R0283` line 60 logic: `||` -> `&&` in `if (typeof text !== "string" || text.length === 0) {`
- `R0278` line 62 drop-jump: `continue;` -> `;` in `continue;` **-> killed by ENG-S13i**

### apps/workers/src/execution/engines/ensemble/sast/scope.js

killed 10, survived 2, timeout 0, invalid 0

- `R0285` line 34 drop-element: `  "u",` -> `(removed)` in `"u",`
- `R0292` line 44 int: `1024` -> `1025` in `value.length <= 1024 &&`

### apps/workers/src/execution/engines/ensemble/sbom/cyclonedx.js

killed 11, survived 1, timeout 0, invalid 0

- `R0306` line 32 int: `1` -> `2` in `const text = (max, min = 1) =>`

### apps/workers/src/execution/engines/ensemble/sbom/index.js

killed 11, survived 1, timeout 0, invalid 0

- `R0319` line 55 drop-call: `outcomes.push({ toolId: run.toolId, status: run.status, reason: run.reason });` -> `;` in `outcomes.push({ toolId: run.toolId, status: run.status, reason: run.reason });`

### apps/workers/src/execution/engines/ensemble/sbom/plan.js

killed 12, survived 0, timeout 0, invalid 0


### apps/workers/src/execution/engines/ensemble/sbom/sbom-lite.js

killed 10, survived 2, timeout 0, invalid 0

- `R0332` line 25 int: `1100` -> `1101` in `path: z.string().max(1100),` **-> equivalent: the schema bound 1100 is looser than `isSafeRelativePath` (1024) applied on the next line, so a path of 1101 is refused either way (checked: 1100 and 1101 both give the same dropped record)**
- `R0341` line 26 int: `1000` -> `1001` in `componentPurl: z.string().max(1000),`

### apps/workers/src/execution/engines/ensemble/sbom/syft.js

killed 4, survived 0, timeout 0, invalid 0


### apps/workers/src/execution/engines/ensemble/sbom/trivy-sbom.js

killed 5, survived 0, timeout 0, invalid 0


### apps/workers/src/execution/engines/ensemble/sca/common.js

killed 11, survived 1, timeout 0, invalid 0

- `R0360` line 25 int: `1` -> `2` in `export const text = (max, min = 1) =>`

### apps/workers/src/execution/engines/ensemble/sca/index.js

killed 11, survived 1, timeout 0, invalid 0

- `R0374` line 53 bool: `true` -> `false` in `export function runScaEnsemble({ taskRef, runs, relevantFilesExist = true }) {`

### apps/workers/src/execution/engines/ensemble/sca/osv-scanner.js

killed 12, survived 0, timeout 0, invalid 0


### apps/workers/src/execution/engines/ensemble/sca/plan.js

killed 9, survived 3, timeout 0, invalid 0

- `R0389` line 9 int: `1024` -> `1025` in `const MiB = 1024 * 1024;`
- `R0395` line 9 int: `1024` -> `1025` in `const MiB = 1024 * 1024;` **-> killed by ENG-S09h**
- `R0399` line 14 int: `2` -> `3` in `cpus: 2,`

### apps/workers/src/execution/engines/ensemble/sca/trivy-vuln.js

killed 12, survived 2, timeout 0, invalid 0

- `R0413` line 131 drop-call (not executed by any Docker-free check): `out.push(null);` -> `;` in `out.push(null);`
- `R0414` line 150 drop-jump (not executed by any Docker-free check): `continue;` -> `;` in `continue;`

### apps/workers/src/execution/engines/ensemble/secrets/common.js

killed 6, survived 6, timeout 0, invalid 0

- `R0418` line 55 logic: `&&` -> `||` in `const end = endLine !== undefined && endLine > startLine ? endLine : undefined;` **-> killed by ENG-S05g**
- `R0419` line 55 bound: `>` -> `>=` in `const end = endLine !== undefined && endLine > startLine ? endLine : undefined;` **-> killed by ENG-S05g**
- `R0421` line 55 eq: `!==` -> `===` in `const end = endLine !== undefined && endLine > startLine ? endLine : undefined;` **-> killed by ENG-S05g**
- `R0424` line 59 int: `200` -> `201` in `title: redactLogText(cleanText(SECRET_TITLES[typeClass])).slice(0, 200),` **-> equivalent: `SECRET_TITLES` is a frozen table whose longest title is 49 characters, so `slice(0, 200)` and `slice(0, 201)` return the same string**
- `R0426` line 62 int: `200` -> `201` in `...(ruleName ? { name: redactLogText(cleanText(ruleName)).slice(0, 200) } : {}),` **-> killed by ENG-S05g**
- `R0423` line 67 eq: `!==` -> `===` in `...(end !== undefined ? { endLine: end } : {}),` **-> killed by ENG-S05g**

### apps/workers/src/execution/engines/ensemble/secrets/detect-secrets.js

killed 10, survived 2, timeout 0, invalid 0

- `R0429` line 50 logic: `&&` -> `||` in `const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);` **-> killed by ENG-S05g**
- `R0436` line 50 logic: `&&` -> `||` in `const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);` **-> killed by ENG-S05g**

### apps/workers/src/execution/engines/ensemble/secrets/gitleaks.js

killed 9, survived 3, timeout 0, invalid 0

- `R0442` line 90 logic: `&&` -> `||` in `const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);` **-> killed by ENG-S05g**
- `R0448` line 90 logic: `&&` -> `||` in `const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);` **-> killed by ENG-S05g**
- `R0450` line 110 int: `1` -> `2` in `endColumn: Number.isInteger(r.EndColumn) && r.EndColumn >= 1 ? r.EndColumn : undefined,` **-> killed by ENG-S05g**

### apps/workers/src/execution/engines/ensemble/secrets/index.js

killed 6, survived 2, timeout 0, invalid 0

- `R0457` line 70 drop-call (not executed by any Docker-free check): `outcomes.push({ toolId: run.toolId, status: run.status, reason: run.reason });` -> `;` in `outcomes.push({ toolId: run.toolId, status: run.status, reason: run.reason });` **-> killed by ENG-S05g**
- `R0458` line 76 return-undefined (not executed by any Docker-free check): `return { outcomes, rollup, findings: merged.findings, stats: merged.stats };` -> `return undefined;` in `return { outcomes, rollup, findings: merged.findings, stats: merged.stats };` **-> killed by ENG-S05g**

### apps/workers/src/execution/engines/ensemble/secrets/plan.js

killed 1, survived 4, timeout 0, invalid 0

- `R0461` line 9 int: `1024` -> `1025` in `const MiB = 1024 * 1024;` **-> killed by ENG-S05g**
- `R0459` line 9 int: `1024` -> `1025` in `const MiB = 1024 * 1024;` **-> killed by ENG-S05g**
- `R0462` line 14 int: `1` -> `2` in `cpus: 1,` **-> killed by ENG-S05g**
- `R0463` line 15 int: `1024` -> `1025` in `memoryMiB: 1024,` **-> killed by ENG-S05g**

### apps/workers/src/execution/engines/ensemble/secrets/scope.js

killed 11, survived 3, timeout 0, invalid 0

- `R0476` line 74 drop-jump (not executed by any Docker-free check): `continue;` -> `;` in `continue;` **-> killed by ENG-S05g**
- `R0473` line 77 int: `1` -> `2` in `entries += 1;` **-> killed by ENG-S05g**
- `R0477` line 112 bool (not executed by any Docker-free check): `true` -> `false` in `else inv.truncated = true;` **-> killed by ENG-S05g**

### apps/workers/src/execution/engines/ensemble/secrets/type-class.js

killed 8, survived 4, timeout 0, invalid 0

- `R0478` line 52 drop-element: `  "AWS Access Key",` -> `(removed)` in `"AWS Access Key",` **-> killed by ENG-S05g**
- `R0484` line 53 drop-element: `  "Artifactory Credentials",` -> `(removed)` in `"Artifactory Credentials",` **-> killed by ENG-S05g**
- `R0488` line 54 drop-element: `  "Azure Storage Account access key",` -> `(removed)` in `"Azure Storage Account access key",` **-> killed by ENG-S05g**
- `R0489` line 123 eq: `===` -> `!==` in `const generic = GENERIC.has(typeClass) || typeClass === "password_assignment";` **-> killed by ENG-S05g**

### packages/infra/src/archive/errors.js

killed 1, survived 0, timeout 0, invalid 0


### packages/infra/src/archive/tar.js

killed 20, survived 12, timeout 0, invalid 0

- `M0464` line 33 int: `100000` -> `100001` in `maxEntries: 100000,` **-> killed by ENG-S07e**
- `M0476` line 34 int: `50` -> `51` in `maxFileBytes: 50 * 1024 * 1024,` **-> killed by ENG-S07e**
- `M0488` line 34 int: `1024` -> `1025` in `maxFileBytes: 50 * 1024 * 1024,` **-> killed by ENG-S07e**
- `M0467` line 62 bound: `<` -> `<=` in `while (pos < data.length) {` **-> equivalent: `data.indexOf(0x20, data.length)` is always -1, so the extra iteration of `pos <= data.length` ends at the next line (`break`) with the same result**
- `M0469` line 66 logic: `||` -> `&&` in `if (!Number.isFinite(length) || length <= space - pos + 1 || pos + length > data.length) break;` **-> killed by ENG-S07e**
- `M0479` line 66 bound: `<=` -> `<` in `if (!Number.isFinite(length) || length <= space - pos + 1 || pos + length > data.length) break;` **-> killed by ENG-S07e**
- `M0481` line 66 logic: `||` -> `&&` in `if (!Number.isFinite(length) || length <= space - pos + 1 || pos + length > data.length) break;` **-> killed by ENG-S07e**
- `M0474` line 130 drop-element: `          "The archive does not contain the requested commit.",` -> `(removed)` in `"The archive does not contain the requested commit.",` **-> killed by ENG-S07e**
- `M0483` line 143 bool: `true` -> `false` in `if (zeroBlocks >= 2) ended = true;` **-> killed by ENG-S07e**
- `M0494` line 177 logic (not executed by any Docker-free check): `&&` -> `||` in `(prefix && field(block, 257, 262) === "ustar" ? '${prefix}/${baseName}' : baseName);` **-> killed by ENG-S07e**
- `M0495` line 177 int (not executed by any Docker-free check): `257` -> `258` in `(prefix && field(block, 257, 262) === "ustar" ? '${prefix}/${baseName}' : baseName);` **-> killed by ENG-S07e**
- `M0486` line 324 drop-element: `      "The extraction parent directory is not private.",` -> `(removed)` in `"The extraction parent directory is not private.",` **-> killed by ENG-S07e**

### packages/infra/src/archive/tree.js

killed 29, survived 1, timeout 0, invalid 0

- `M0499` line 43 return-undefined: `return null;` -> `return undefined;` in `return null;` **-> killed by ENG-S07e**

### packages/infra/src/dbmirror/inspect.js

killed 27, survived 3, timeout 0, invalid 0

- `M0535` line 45 bool: `true` -> `false` in `if (size > limit) this.over = true;`
- `M0537` line 53 return-undefined: `return undefined;` -> `return undefined;` in `return undefined;` **-> equivalent: the replacement text is identical to the original (`return undefined;`), a no-op mutant produced by the sweep tool**
- `M0543` line 96 return-undefined: `return null;` -> `return undefined;` in `return null;`

### packages/infra/src/dbmirror/sources.js

killed 27, survived 2, timeout 0, invalid 1

- `M0568` line 82 int: `50` -> `51` in `const aliases = Array.isArray(record.aliases) ? record.aliases.slice(0, 50).map(short) : [];`
- `M0577` line 83 int: `200` -> `201` in `const affected = Array.isArray(record.affected) ? record.affected.slice(0, 200) : [];`

### packages/infra/src/dbmirror/store.js

killed 30, survived 1, timeout 0, invalid 0

- `M0616` line 258 drop-call (not executed by any Docker-free check): `await removeTree(temp).catch(() => {});` -> `;` in `await removeTree(temp).catch(() => {});`

### packages/infra/src/sandbox/build-run-args.js

killed 30, survived 1, timeout 0, invalid 0

- `M0202` line 17 int: `100` -> `101` in `const fmt = (n) => String(Math.round(n * 100) / 100);` **-> killed by ENG-S09h**

### packages/infra/src/sandbox/capacity.js

killed 27, survived 3, timeout 1, invalid 0

- `M0263` line 43 int (not executed by any Docker-free check): `1` -> `2` in `const left = (map.get(key) ?? 1) - 1;` **-> equivalent: `drop` runs only for a reference that `take` registered, and `take` sets both map keys to at least 1; the `?? 1` fallback is unreachable (release is idempotent)**
- `M0240` line 92 drop-element: `              "capacity",` -> `(removed)` in `"capacity",` **-> killed by ENG-S14c**
- `M0245` line 99 eq: `===` -> `!==` in `if (queue.length === 0 && fits(r)) {` **-> equivalent: the `queue.length === 0` guard is a shortcut; `pump()` grants in FIFO order with skipping after every push and release, so a waiter that fits is granted at once either way and a waiter behind blocked ones is granted by the pump; the observable order and timing are the same**

### packages/infra/src/sandbox/cli-runtime.js

killed 27, survived 5, timeout 0, invalid 0

- `M0269` line 122 int: `65536` -> `65537` in `const r = await call(args, { maxBuffer: 65536, timeoutMs: config.cliTimeoutMs });`
- `M0294` line 126 drop-element (not executed by any Docker-free check): `        "container runtime binary not found",` -> `(removed)` in `"container runtime binary not found",`
- `M0280` line 144 int: `262144` -> `262145` in `const r = await call(["info"], { maxBuffer: 262144, timeoutMs: config.cliTimeoutMs });`
- `M0295` line 180 drop-element (not executed by any Docker-free check): `          "container runtime binary not found",` -> `(removed)` in `"container runtime binary not found",`
- `M0274` line 304 drop-jump: `continue;` -> `;` in `continue;` **-> equivalent: `o` is declared inside the loop and stays `undefined` when the parse throws; the next statement `if (!o || ...) continue;` makes the same jump**

### packages/infra/src/sandbox/config.js

killed 29, survived 1, timeout 0, invalid 0

- `M0318` line 105 quantifier: `every` -> `some` in `if (!Array.isArray(forbidden) || !forbidden.every(isSafeAbsolutePath))`

### packages/infra/src/sandbox/errors.js

killed 1, survived 0, timeout 0, invalid 0


### packages/infra/src/sandbox/fake-runtime.js

killed 25, survived 5, timeout 0, invalid 0

- `M0338` line 40 return-undefined: `return this;` -> `return undefined;` in `return this;`
- `M0332` line 91 int: `125` -> `126` in `if (outcome.runtimeFault) return result({ status: "runtime_error", exitCode: 125 });`
- `M0356` line 98 drop-call: `clearTimeout(timer);` -> `;` in `clearTimeout(timer);`
- `M0341` line 136 int: `1000` -> `1001` in `const wall = setTimeout(() => finish("timeout"), spec.limits.wallClockSeconds * 1000);` **-> equivalent for the product: `fake-runtime.js` is a test double used only by the suite; the 0.1 percent longer fake wall clock changes no production behaviour**
- `M0342` line 144 negation: `!` -> `(removed)` in `if (!c) return;`

### packages/infra/src/sandbox/image-catalog.js

killed 27, survived 4, timeout 0, invalid 0

- `M0384` line 94 logic: `||` -> `&&` in `if (!lock || typeof lock !== "object" || Array.isArray(lock))` **-> killed by ENG-S02d**
- `M0366` line 129 quantifier: `every` -> `some` in `!e.roles.every((r) => typeof r === "string" && r.length > 0 && r.length <= 40)` **-> killed by ENG-S02d**
- `M0376` line 132 quantifier: `every` -> `some` in `if (!Array.isArray(e.scanTypes) || !e.scanTypes.every((s) => SCAN_TYPES.includes(s)))` **-> killed by ENG-S02d**
- `M0387` line 305 logic (not executed by any Docker-free check): `&&` -> `||` in `if (production && isPlaceholderDigest(e.digest)) return refuse("placeholder_digest");` **-> killed by ENG-S02d**

### packages/infra/src/sandbox/janitor.js

killed 17, survived 2, timeout 0, invalid 0

- `M0405` line 59 int (not executed by any Docker-free check): `1` -> `2` in `failed += 1;`
- `M0406` line 60 drop-call (not executed by any Docker-free check): `onError({ name: c.name, code: err?.code ?? "error" });` -> `;` in `onError({ name: c.name, code: err?.code ?? "error" });`

### packages/infra/src/sandbox/policy.js

killed 8, survived 2, timeout 0, invalid 0

- `M0414` line 19 drop-element: `  "GRYPE_DB_VALIDATE_AGE",` -> `(removed)` in `"GRYPE_DB_VALIDATE_AGE",`
- `M0415` line 20 drop-element: `  "GRYPE_CHECK_FOR_APP_UPDATE",` -> `(removed)` in `"GRYPE_CHECK_FOR_APP_UPDATE",` **-> killed by ENG-S09h**

### packages/infra/src/sandbox/run-spec.js

killed 29, survived 2, timeout 0, invalid 0

- `M0423` line 77 string-method: `startsWith` -> `endsWith` in `if (p === "--" || CONTROL.test(p) || p.includes("\\") || p.startsWith("/")) return false;`
- `M0447` line 101 logic (not executed by any Docker-free check): `||` -> `&&` in `const task8 = spec.labels.taskId.replace(/[^A-Za-z0-9]/g, "").slice(0, 8) || "task";`

### packages/infra/src/sandbox/runner.js

killed 8, survived 2, timeout 0, invalid 0

- `M0451` line 32 eq: `===` -> `!==` in `if (started.get(key)?.size === 0) started.delete(key);`
- `M0457` line 60 drop-call (not executed by any Docker-free check): `failed.push(name);` -> `;` in `failed.push(name);`

### packages/infra/src/sandbox/runtime.js

killed 0, survived 4, timeout 1, invalid 0

- `M0458` line 35 drop-element: `  "exited",` -> `(removed)` in `"exited",` **-> killed by ENG-S09h**
- `M0459` line 36 drop-element: `  "timed_out",` -> `(removed)` in `"timed_out",`
- `M0460` line 37 drop-element: `  "aborted",` -> `(removed)` in `"aborted",`
- `M0461` line 38 drop-element: `  "output_limit",` -> `(removed)` in `"output_limit",`

### packages/shared/src/scan-engines/constants.js

killed 13, survived 2, timeout 0, invalid 0

- `M0010` line 24 int: `4` -> `5` in `export const SEVERITY_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, info: 0 });`
- `M0015` line 26 int: `2` -> `3` in `export const CONFIDENCE_RANK = Object.freeze({ low: 0, medium: 1, high: 2 });` **-> equivalent: `CONFIDENCE_RANK` is used only as a sign (`merger.js` 81, 308) and in `Math.min(rank + 1, 2)` (`severity.js` 161); `high: 3` instead of `2` gives the same result**

### packages/shared/src/scan-engines/cvss.js

killed 25, survived 4, timeout 1, invalid 0

- `M0019` line 44 bound: `>` -> `>=` in `if (typeof vector !== "string" || vector.length > MAX_VECTOR_LENGTH) return null;`
- `M0028` line 64 bound: `>` -> `>=` in `if (typeof vector !== "string" || vector.length > MAX_VECTOR_LENGTH) return null;`
- `M0034` line 66 logic: `||` -> `&&` in `if (parts.length < 9 || parts.length > 23) return null;`
- `M0041` line 66 bound: `>` -> `>=` in `if (parts.length < 9 || parts.length > 23) return null;`

### packages/shared/src/scan-engines/db-mirror.js

killed 25, survived 4, timeout 1, invalid 0

- `M0046` line 24 drop-element: `  "integrity_mismatch",` -> `(removed)` in `"integrity_mismatch",` **-> killed by ENG-S09h**
- `M0056` line 25 drop-element: `  "integrity_unverified",` -> `(removed)` in `"integrity_unverified",`
- `M0070` line 27 drop-element: `  "empty",` -> `(removed)` in `"empty",`
- `M0075` line 28 drop-element: `  "too_small",` -> `(removed)` in `"too_small",`

### packages/shared/src/scan-engines/finding.js

killed 28, survived 2, timeout 0, invalid 0

- `M0078` line 43 logic: `||` -> `&&` in `if (typeof value !== "string" || value.length === 0 || value.length > L.path) return false;`
- `M0081` line 44 string-method: `startsWith` -> `endsWith` in `if (value.startsWith("/") || value.includes("\\") || CONTROL.test(value)) return false;` **-> equivalent: a leading `/` leaves an empty first segment, which `every((s) => s !== "")` on the next line refuses; the same holds for a trailing `/`**

### packages/shared/src/scan-engines/json-size.js

killed 26, survived 0, timeout 0, invalid 0


### packages/shared/src/scan-engines/rollup.js

killed 29, survived 1, timeout 0, invalid 0

- `M0145` line 120 bound: `>` -> `>=` in `errorClass: broken.length > 0 && transient ? "transient" : "permanent",`

### packages/shared/src/scan-engines/severity.js

killed 30, survived 0, timeout 0, invalid 0


### packages/shared/src/scan-engines/tool-dto.js

killed 1, survived 9, timeout 0, invalid 0

- `M0192` line 28 drop-element: `  "complete",` -> `(removed)` in `"complete",`
- `M0193` line 29 drop-element: `  "partial",` -> `(removed)` in `"partial",`
- `M0194` line 30 drop-element: `  "partial_tools",` -> `(removed)` in `"partial_tools",`
- `M0195` line 31 drop-element: `  "gaps",` -> `(removed)` in `"gaps",` **-> killed by ENG-S09h**
- `M0196` line 32 drop-element: `  "nothing_to_scan",` -> `(removed)` in `"nothing_to_scan",`
- `M0198` line 49 drop-element: `  "cpp",` -> `(removed)` in `"cpp",`
- `M0199` line 50 drop-element: `  "csharp",` -> `(removed)` in `"csharp",`
- `M0200` line 51 drop-element: `  "dart",` -> `(removed)` in `"dart",`
- `M0201` line 52 drop-element: `  "elixir",` -> `(removed)` in `"elixir",` **-> killed by ENG-S09h**

## 4. Triage round of 2026-11-23 (owner decision, option B)

### 4.1 Decision, scope and method

- **Decision (owner, 2026-11-23, option B):** triage NOW the security-relevant groups of 3.2 (secret masking boundaries, hostile archive parsing, engine wiring gates and capacity, the placeholder digest rule and the image catalog, and the Secrets mapping), plus a deterministic sample of about 20 percent of the remaining survivors; keep the whole backlog; **full triage (A) stays required before general availability** (gate G-7 of `LIVE_TEST_PLAN.md`). No existing check was edited or weakened (the only edit to an earlier check file is the `export` keyword on eleven constants of `ensemble-evidence-checks.js` that the new checks reuse).
- **Groups triaged in full (75 survivors):** `evidence/mask.js`, `evidence/secret-preview.js` and `evidence/snippet.js` (secret masking and the code excerpt caps, 20); everything under `secrets/` (the Secrets mapping, 24); `archive/tar.js` and `archive/tree.js` (hostile archive parsing, 13); `engine/wiring.js` and `sandbox/capacity.js` (engine wiring gates and capacity, 14); `sandbox/image-catalog.js` (the placeholder digest rule and the catalog validation, 4). The image lock loader is `catalog/index.js` (no survivor) over `image-catalog.js`.
- **Sample (29 survivors):** the 141 survivors outside those files were sorted by file path, then line, then id, and **every fifth one (positions 0, 5, 10, and so on) was taken** (141 / 5 rounded up = 29, 20.6 percent). The same rule reproduces the sample from section 3.3.
- **Verification:** each new check was first run alone on the unmutated sources (it passes), then every mutant of its survivors was applied IN MEMORY (`node scripts/mutation-sweep.js one --file F --line N --only REGEX`, a new command of the sweep tool that re-runs the mutants of one line; the working tree is never written) and must make a check fail. The disposition names the check that failed. The 3 repository SBOM download survivors of 3.1b are not triaged.
- **Two findings about the sweep tool:** (1) a survivor marked "not executed by any Docker-free check" can still be killed by a check that the coverage map does not attribute to the line; the triage re-ran such mutants against the whole Docker-free set. (2) The mutator can produce a no-op mutant: `M0537` replaces `return undefined;` by `return undefined;` (identical text); the sweep was left unchanged so its seed and numbering stay reproducible.

### 4.2 The new checks (11; each names its mutants in its description)

| Check | Covers | Kills |
|---|---|---|
| `ENG-S13g` | the line mask boundaries (300 character cap, the entropy rule of a token run, the known-prefix window, the operator tolerance and the left widening of a reported span) | `R0136`, `R0137`, `R0141`, `R0143`, `R0144`, `R0145`, `R0146` |
| `ENG-S13h` | the secret line index and the evidence caps (the 2000 line range limit, what the index ignores, the cap figures of SPEC 5.13.2, the line and byte caps of the code snippet) | `R0121`, `R0163`, `R0165` to `R0171`, `R0173`, `R0175`, `R0177`, `R0185`, `R0187`, `R0188` |
| `ENG-S05g` | the Secrets mapping and parsers (end line, rule name length, hostile report records, the 27 detect-secrets labels, the confidence table, the tool limits, the tree inventory walk, a run of tools that did not run) | `R0418`, `R0419`, `R0421`, `R0423`, `R0426`, `R0429`, `R0436`, `R0442`, `R0448`, `R0450`, `R0457`, `R0458`, `R0459`, `R0461` to `R0463`, `R0473`, `R0476`, `R0477`, `R0478`, `R0484`, `R0488`, `R0489` |
| `ENG-S07e` | the hostile archive parser (a pax record that is too small, too large or not a number, the end-of-archive marker, the ustar prefix and its magic, the default caps, the fixed error texts, the strict `null` of the name guard) | `M0464`, `M0469`, `M0474`, `M0476`, `M0479`, `M0481`, `M0483`, `M0486`, `M0488`, `M0494`, `M0495`, `M0499` |
| `ENG-S14c` | the capacity refusal names its rule and no id | `M0240` |
| `ENG-S16h` | the wiring gates (the database readiness warning, the fork share arithmetic, the orphan warning, the wait for capacity of the wired SBOM, SAST and Secrets engines, the Secrets coverage notes) | `R0090` to `R0093`, `R0095`, `R0098`, `R0099`, `R0101` to `R0103`, `R0060` |
| `ENG-S02d` | the image catalog rules (a hostile lock never throws, one bad role or scan type refuses the entry, the placeholder digest rule differs between development and production) | `M0366`, `M0376`, `M0384`, `M0387` |
| `ENG-S13i` | the evidence readers and guards (a trailing newline, the 2000 character link cap, CWE labels, the rule pack check, the excerpt budget order) | `R0130`, `R0150`, `R0196`, `R0217`, `R0278` |
| `ENG-S09h` | the fixed limits and word lists of the sandbox layer (the container limits of five tools, the environment allowlist, the run, reject and coverage words, the CPU flag, the canary id length) | `R0114`, `R0271`, `R0395`, `R0501`, `M0046`, `M0195`, `M0201`, `M0202`, `M0415`, `M0458` |
| `ENG-S06o` | the parse and merge steps (the duplicate adapter text, a fractional file error count, the provenance order, a credential-shaped row) | `M0630`, `M0773`, `M0833` |
| `ENG-S13j` | the extractor fallback counts of the SAST coverage statement (SPEC 17.ac; not a kill check, it covers the new `coverage.evidence`) | none (new behaviour) |

All 11 live in `apps/api/test/security/helpers/ensemble-triage-checks.js`.

### 4.3 Totals after the triage round

| | Part M sweep | Triage round | After |
|---|---|---|---|
| Checks (`pnpm test:security` reports 19 more tests than checks) | 898 | +11 | 909 |
| Mutants in the sample | 1426 | 0 | 1426 |
| Killed | 1191 | +88 | **1279** |
| Timeouts (a kill by the clock) | 12 | 0 | 12 |
| Survived | 219 | -88 | **131** |
| Invalid | 4 | 0 | 4 |
| **Kill rate** (killed plus timeouts over the 1422 valid mutants) | 84.6 percent | | **90.8 percent** (1291 / 1422) |

Of the 131 survivors: **14 are equivalent with a proof** (4.5), **2 are deferred** (4.6), and **115 are not triaged** (112 in the files of 3.3 plus the 3 of 3.1b). Counting the 14 equivalents out of the valid mutants the rate is 91.7 percent (1291 / 1408). The sample is a bounded one (1426 of 4367 candidates), so this is not a statement about the whole population (2.3 still applies).

### 4.4 Disposition per group

| Group | Survivors | Killed (check) | Equivalent (proof) | Deferred |
|---|---|---|---|---|
| Secret masking boundaries (`mask.js` 8, `secret-preview.js` 7, `snippet.js` 5) | 20 | 19 (`ENG-S13g`, `ENG-S13h`) | 1 (`R0149`) | 0 |
| Secrets mapping and hostile records (`secrets/*`) | 24 | 23 (`ENG-S05g`) | 1 (`R0424`) | 0 |
| Hostile archive parsing (`tar.js` 12, `tree.js` 1) | 13 | 12 (`ENG-S07e`) | 1 (`M0467`) | 0 |
| Engine wiring gates and capacity (`wiring.js` 11, `capacity.js` 3) | 14 | 11 (`ENG-S16h`, `ENG-S14c`) | 2 (`M0263`, `M0245`) | 1 (`R0100`) |
| Placeholder digest rule and image catalog (`image-catalog.js`) | 4 | 4 (`ENG-S02d`) | 0 | 0 |
| **Security-relevant groups** | **75** | **69** | **5** | **1** |
| Sample, every fifth of the other 141 | 29 | 19 (`ENG-S13i`, `ENG-S09h`, `ENG-S06o`, `ENG-S16h`) | 9 (`M0717`, `R0016`, `M0689`, `M0537`, `R0332`, `M0341`, `M0274`, `M0015`, `M0081`) | 1 (`R0244`) |
| **Total triaged** | **104** | **88** | **14** | **2** |

The placeholder digest rule (3.2 item 6): the survivor `M0387` (`production && isPlaceholderDigest(...)` turned into `||`, so that a placeholder digest was also refused in development) is killed by `ENG-S02d`, which also asserts that a production lock with registry digests resolves every adopted entry to `repository@digest`. The production rule itself is asserted by `ENG-S02b` (the resolver cannot even be built from a placeholder lock in production, so the `resolve` guard is a second line of defence).

### 4.5 The equivalent mutants (proofs)

Each proof is also on the survivor's line in 3.3. An equivalent mutant is NOT removed from the totals above.

| Survivor | Why no check can observe it |
|---|---|
| `R0149` `mask.js` 103 | the default start column 1 against 2 only feeds `Math.max(0, a - 1)`; both give 0 (also for the UTF-8 reading) |
| `R0424` `secrets/common.js` 59 | the titles are a frozen table, the longest has 49 characters; `slice(0, 200)` and `slice(0, 201)` are the same |
| `M0467` `tar.js` 62 | `data.indexOf(0x20, data.length)` is -1, so the extra iteration breaks at once |
| `M0263` `capacity.js` 43 | `drop` runs only after `take` set both keys to 1 or more; the `?? 1` is unreachable |
| `M0245` `capacity.js` 99 | the `queue.length === 0` shortcut and `pump()` grant the same waiter at the same time (FIFO with skipping) |
| `M0717` `merger.js` 317 | needs two members of one tool in one finding; merging is cross-tool only (SE-12), shown for four scan types |
| `R0016` `run-manifest.js` 15 | needs two equal tool ids; the adapter registry refuses a duplicate (`ENG-S06o`) |
| `M0689` `merger.js` 54 | `cmp` is read only as a sign |
| `M0537` `inspect.js` 53 | the replacement text equals the original |
| `R0332` `sbom-lite.js` 25 | the next line refuses any path over 1024 characters, so 1100 against 1101 changes nothing |
| `M0341` `fake-runtime.js` 136 | a test double, not shipped |
| `M0274` `cli-runtime.js` 304 | `o` stays `undefined` and the next line makes the same jump |
| `M0015` `constants.js` 26 | the rank is used as a sign and in `Math.min(rank + 1, 2)` |
| `M0081` `finding.js` 44 | the empty first segment of a leading `/` is refused by the next line |

### 4.6 The deferred survivors

- `R0100` (`engine/wiring.js` 74): the capacity wait of the SCA engine (`waitSeconds * 1000` against `1001`). The same expression is killed for the SBOM and SAST engines (`ENG-S16h` arms the capacity timer and reads its delay); the SCA engine reaches that timer only with a promoted database snapshot (a mirror object, a snapshot row and a cache directory). **Deferred to full triage A.**
- `R0244` (`sast/languages.js` 164): the dropped sort of directory entries decides which entries survive a truncating cap; no filesystem seam exists to fix the order of `readdir`. **Deferred to full triage A.**

### 4.7 What remains

- 115 survivors are not triaged: 112 in the files of 3.3 outside the groups above and the sample, and the 3 repository SBOM download survivors of 3.1b. They are the lines of 3.3 without a `->` note. **Full triage (A) before general availability** (gate G-7).
- The limits of 2.3 still apply (database-only code was swept by sampling; `ENG-S02a` and `ENG-S09d` are load sensitive at 12 workers). The new checks are not load sensitive except the timer based ones (`ENG-S16h` uses 20 to 200 millisecond waits on a fake runtime and a 7 second configured wait that is never waited out).
