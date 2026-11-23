# Scan engines: rollout plan (Part N)

Status: **written 2026-11-22, documentation only, nothing in it was executed; the staging decision (section 1) and the two operations decisions (section 5, section 2) were recorded 2026-11-23.** The live checks are in `LIVE_TEST_PLAN.md` (gate register, section 4); this file is the staged enablement, the provisioning index, monitoring, rollback and the list of what is not verified. Where a statement comes from reading code rather than running it, it says "from the code".

## 1. What the flag really is (read first: two findings)

1. **There is ONE worker-wide switch, not a flag per scan type or per tenant.** `SCAN_ENGINES_ENSEMBLE_ENABLED` (`apps/workers/src/config.js`, default `false`, strictly `"true"`) is read by the scan worker (`apps/workers/src/scan/index.js`) and by the pipeline worker's engine registry (`buildPipelineEngineRegistry`, `apps/workers/src/execution/registry.js`). Turning it on replaces the SBOM engine `sbom/default` with the ensemble and makes SCA, SAST and Secrets tasks real instead of `unsupported`, **for every tenant served by those workers, all four types at once.** The per-type flags `SCAN_ENGINE_SBOM|SCA|SAST|SECRETS` and the canary tenant allowlist of SPEC SE-28 / OQ-18 are **decided to be built (2026-11-23) in the deferred task `rollout-hardening`, and are not built yet** (a code search of `apps` and `packages` finds none; from the code).
2. **Decision (owner, 2026-11-23, SPEC 17.ac (3); replaces the two options written by Part N):** the worker-wide `SCAN_ENGINES_ENSEMBLE_ENABLED` is **fine for non-production end-to-end validation** (stage 1: the team's own repositories in a non-production environment). **For the first production customer rollout the per-type flags `SCAN_ENGINE_SBOM|SCA|SAST|SECRETS` and a tenant allowlist are to be BUILT** (SE-28, OQ-18), in a separate task named **`rollout-hardening`**, which is **deferred**: it is not built yet and is a pre-production gate (G-14 of `LIVE_TEST_PLAN.md`). The allowlist is preferred over routing canary tenants to dedicated worker queues, which has its own unknowns (today the queues are `scan` and `scan-untrusted`, not per tenant, and whether production queues can be split per tenant is unverified).
   - **What `rollout-hardening` must contain (the scope the owner approved; a task, not a design):** the four per-type flags and a tenant allowlist, Zod-validated at worker start (a tenant id that is not a UUID, or a list over a stated size, stops the worker); the registry and the scan worker read them, with the single switch kept as the master (everything off when it is `false`); the tenant allowlist is a tenant-isolation control, so it gets checks in the security suite (ADR-008 area 18: a tenant that is not on the list never reaches an ensemble engine, the allowlist is never taken from a request or a message, an empty list means nobody when the flag asks for an allowlist); rollback stays the master switch. **Not decided here and left to that task:** where the allowlist lives (worker environment or a platform setting), whether a change needs a restart, and the exact canary tenant names (the owner names them when stage 3 starts).
   - **Until `rollout-hardening` exists** the stages below hold only by environment: stage 1 (non-production) and stage 2 for the owner's own tenant on dedicated workers; stage 3 (canary customers) and stage 4 must not start without it.

The stages below name the tenant, the tenants or the environment that is affected; stages 3 and 4 need the per-type flags and the allowlist.

## 2. Prerequisites by flag

| Setting | Required when | Notes (all names exist in `apps/workers/src/config.js`) |
|---|---|---|
| `SCAN_ENGINES_ENSEMBLE_ENABLED=true` | the ensemble is wanted | on the **scan worker and the pipeline worker**, same value |
| `SANDBOX_ARCHIVE_ROOT` | ensemble on | absolute, not a system or home path; where trees are extracted |
| `SANDBOX_RULES_DIR` | ensemble on **and** when `SCAN_DB_REFRESH_ENABLED=true` | absolute; holds the platform tool configuration (`syft.yaml`, `trivy.yaml`, `osv-scanner.toml`, `canary.cdx.json`, rule packs); the dbrefresh worker's canary reads `canary.cdx.json` and `osv-scanner.toml` from it (SPEC 17.u, D-25 (5)) |
| `SANDBOX_RUNTIME_BIN`, `SANDBOX_USER`, `SANDBOX_USERNS_MODE`, `SANDBOX_UIDMAP`, `SANDBOX_GIDMAP`, `SANDBOX_SECCOMP_PROFILE` | ensemble on | the values proven by ENG-L18; defaults (`podman`, `65534:65534`) are **not** a verified rootless configuration |
| `SCAN_DB_REFRESH_ENABLED=true` | any SCA use | the dbrefresh role; also needs `DATABASE_URL`, `SCAN_DB_MIRROR_ROOT`, `SCAN_DB_CACHE_ROOT` (absolute, different from each other) |
| `SCAN_DB_MIRROR_ROOT`, `SCAN_DB_CACHE_ROOT` | on the dbrefresh worker and, for the SCA engine, on the **scan worker** | without both, every SCA tool is `unavailable` (`apps/workers/.env.example`) |
| `SCAN_RUNNER_MAX_CONTAINERS` (4), `..._PER_TENANT` (2, must not exceed the total), `SCAN_UNTRUSTED_CAPACITY_SHARE` (50), `SCAN_ENGINE_TOOL_PARALLELISM` (2), `SCAN_RUNNER_JANITOR_SECONDS` (60) | ensemble on | defaults are starting points, calibrated by ENG-L10 |
| a **real downloader** for the vulnerability databases | production SCA | **does not exist**; Part F ships a fake one (SPEC 17.p) and OQ-29 (integrity anchor) is deferred to the build of the real downloader, with trust on first use as the default approach (17.ac (6)). Until it exists, snapshots are hand-built bundles (`ENG_L21_RUNBOOK.md` section 2) |
| production image lock | production | `loadImageLock({ production: true })` must pass: needs the three own-built digests (gate G-3) |

SCA also needs a promoted snapshot per tool; with none, every SCA task fails closed with `db_unavailable` and **no container starts** (SPEC 5.12; verification in ENG-L09).

## 3. Stages

Each stage has an entry condition (gates from `LIVE_TEST_PLAN.md` section 4) and an exit condition. A stage is never skipped. No stage is entered by this documentation.

| Stage | Flag | Who is affected | Entry condition | What to watch and exit condition |
|---|---|---|---|---|
| 0. Off (today) | `SCAN_ENGINES_ENSEMBLE_ENABLED=false` (default) | everyone gets SBOM-lite; SCA, SAST and Secrets are `unsupported` | none | n/a. This is the rollback target |
| 1. Non-production, internal | `true` in a non-production environment (development, staging) | the team's own test repositories only | live phases 0 to 4 and ENG-L11/L14 passed there (G-2 evidence, G-10); local own-built images accepted for this stage only | every scan type produces one real result; `incomplete` and `degraded` reasons explained; no orphan containers; no secret value in any store (ENG-L14); T-29 checked by a human (G-9). Exit: G-10 and G-9 DONE |
| 2. Internal tenant in production | `true` for the owner's own tenant (dedicated workers until `rollout-hardening` provides the allowlist) | internal users only | **all gates G-1 to G-6 and G-12 DONE**, G-3 specifically so `loadImageLock({ production: true })` passes; G-4 (real downloader and the OSV hash source) DONE if SCA is included; legal sign-off (G-1) in writing | one to two weeks of normal use (duration is a Recommendation, not a decided number): failure ratio per tool, DB snapshot age tiers, janitor reaps, capacity waits, run durations against the calibrated limits. Exit: no unexplained failure, G-8 DONE |
| 3. Canary tenants | `true` for a short, owner-chosen list | named customers who agreed | stage 2 exit; **G-14 (`rollout-hardening`: per-type flags and the tenant allowlist built and checked)**; G-7 (mutation backlogs; the full triage of `MUTATION_BACKLOG.md`) worked or explicitly waived by the owner; G-13 (a suppression path) understood: while it is missing, inline suppressions are ignored and developers have no path (OQ-16) | same signals plus support tickets about findings that look wrong; compare findings against the previous engine where both ran. Exit: owner decision |
| 4. General | `true` for all | everyone | stage 3 exit, owner decision | continue monitoring; keep the rollback below ready for at least the first release cycle |

Per-type enablement (for example SCA last, because it depends on the database operation) is **not possible** with the current single flag (section 1); it is part of `rollout-hardening` (G-14).

## 4. Image and database provisioning: runbook index

| Task | Where |
|---|---|
| What each image is, its digest, licence, flags | `IMAGES.md` sections 1 to 4, `images.lock.json` under `apps/workers/src/execution/engines/ensemble/catalog/` |
| Choose, review, mirror by digest, load into the runtime store, run with `--pull=never` | `IMAGE_CATALOG.md` section 3 |
| Build the three own-built images (Opengrep, detect-secrets, block extractor), record the registry digest, approvals, signature, self-scan | `IMAGES.md` sections 8, 9, 10; `IMAGE_CATALOG.md` sections 3 to 6; gate G-3 and G-12 |
| Confirm images present and digests equal the lock | `node apps/workers/scripts/eng-l20/capture.js images --check`; `ENG_L20_RUNBOOK.md` section 1 |
| Download and mirror the Trivy DB and the four OSV archives; the layout the tools read at `/db` | `ENG_L21_RUNBOOK.md` sections 0 to 2 (the mirror bundle is a tar.gz with one top directory) |
| Platform tool configuration and rule packs in `SANDBOX_RULES_DIR` | the files under `apps/workers/src/execution/engines/ensemble/sbom/rules/` (including `qm-sast/`); copy them to the configured directory (the destination is an operations choice) |
| Verify data cleanliness (quarantine markers) | `ENG_L21_RUNBOOK.md` section 3; gate G-1 |
| Rootless runtime configuration | `LIVE_TEST_PLAN.md` ENG-L18; the `SANDBOX_*` values |

## 5. Monitoring and alerts

From SPEC 12 (observability). **No metrics backend exists yet** ("Pino-derived counters now, a metrics backend later", Open), so these are log and audit signals to read by hand or to alert on once a backend exists. The alert thresholds below are Recommendations with placeholders, none is decided.

- **Quarantine block (the only built alert):** a refresh rejected as `quarantined_source` writes one platform audit entry (`scan_db.quarantine_denied`, visible to Root Console administrators with `platform.audit_log.view` at `GET /api/v1/platform/audit-logs`) and one warn log line (SPEC 17.s). No paging or notification channel exists. **Decision 2026-11-23 (17.ac (4)): a watcher is deferred to pre-production operations**, when a visible operator surface is built and an owner is assigned (gate G-5); until then the platform audit log query is the interim way to see a blocked refresh, and nobody is assumed to watch it.
- **Database snapshot age per tool** against the tiers 3, 14 and 30 days (`SCAN_DB_STALE_*` env, defaults in `config.js`); `db_stale` and `db_unavailable` results; refresh failure reasons (`integrity_*`, `canary_failed`, size, age).
- **Per tool:** start and end log lines with status, reason code, duration and counts; failure ratio; `output_too_large`, `out_of_memory`, `timeout`, `image_unavailable` (this one means a digest is missing from the lock or the store: alert on any occurrence in production).
- **Containers:** count of containers with the label `qm.scan=1` on each scan host (`RUNTIME ps --filter label=qm.scan=1`) should return to zero when idle; janitor reaping more than a small number per interval indicates crashing workers; **any container started from a non-catalog digest must be zero** (SPEC 12).
- **Capacity:** waits on `SCAN_RUNNER_WAIT_SECONDS`, fork-pool share use.
- **Roll-up outcomes:** share of `incomplete` and `degraded` task results; `run_manifest_sha256` changes without an `ensembleVersion` or image change would indicate non-determinism (ENG-L11).
- **Disk:** `SANDBOX_ARCHIVE_ROOT`, `SCAN_DB_MIRROR_ROOT`, `SCAN_DB_CACHE_ROOT` (a snapshot is up to about 1.7 GiB for Trivy and about 280 MB for OSV on 2026-11-21; `SCAN_DB_MAX_BYTES` default 4 GiB).
- **Never in logs or alerts:** tool stdout, secret values, tenant repository content (SE-39, SPEC 12).

## 6. Rollback

1. Set `SCAN_ENGINES_ENSEMBLE_ENABLED=false` on the scan worker **and** the pipeline worker and restart them (the flag is read at start). From the code: the registry then falls back to the built-in SBOM-lite engine, and SCA, SAST and Secrets are `unsupported` again, exactly the stage-0 behaviour. It is **SBOM-lite for SBOM only**, not a fallback for the other three types.
2. Set `SCAN_DB_REFRESH_ENABLED=false` if SCA was the cause (the refresh job is then neither scheduled nor handled).
3. **Orphan containers:** the janitor runs only while the ensemble flag is on (`onReady` in `apps/workers/src/scan/index.js`, from the code), so after switching off, remove leftovers by hand: `RUNTIME ps --filter label=qm.scan=1` then `RUNTIME rm -f` them (UNVERIFIED as written). Do this after the workers have stopped.
4. In-flight tasks are retried or fail through the normal task lifecycle; results already stored by the ensemble stay (`engine_version` `ensemble-<type>/<version>`) and remain readable. New runs are not comparable with them (SE-26: different manifests). This was **not tested** (ENG-L05 covers kill and janitor, not a mid-run flag change).
5. No schema rollback is needed: the Part D migrations are additive and nothing in Parts G to J added a migration (SPEC 17.u to 17.z). Existing SBOM downloads and DTO fields keep working with SBOM-lite results (UNVERIFIED in the live app).

## 7. What is NOT verified

- Everything in `LIVE_TEST_PLAN.md`: no live item has been run on the owner's machine for this plan; the sandbox runs (ENG-L20 once, the L21, L22, L23 and Part J scripts once each, rootful Docker 29.1.3, 2026-11-20 to 2026-11-22) are the only real-tool evidence.
- Rootless Podman and Docker, uid mapping, the platform seccomp profile, gVisor and Kata, a production scan-runner service, other operating systems and architectures.
- Large repositories, the limits of SPEC 5.8 under load, the real downloader, a real promotion with real data, real staleness behaviour over days.
- The T-29 screen, the SBOM download button and the Secrets coverage note in a real browser, with a screen reader.
- Any per-tenant or per-type staging (it does not exist; `rollout-hardening` builds it, G-14), and whether production workers can be split per tenant (not needed once the allowlist exists).
- A mid-run rollback, and behaviour of stored ensemble results after the flag is turned off.
- The mutation backlog (`MUTATION_BACKLOG.md`) is built and partly triaged (909 checks, 104 of 219 survivors triaged, 2026-11-23); 115 survivors are not triaged and the full triage is gate G-7.
- Legal acceptability of any data licence (a lawyer's decision, OQ-26).
