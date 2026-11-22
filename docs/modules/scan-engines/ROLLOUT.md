# Scan engines: rollout plan (Part N)

Status: **written 2026-11-22, documentation only, nothing in it was executed.** The live checks are in `LIVE_TEST_PLAN.md` (gate register, section 4); this file is the staged enablement, the provisioning index, monitoring, rollback and the list of what is not verified. Where a statement comes from reading code rather than running it, it says "from the code".

## 1. What the flag really is (read first: two findings)

1. **There is ONE worker-wide switch, not a flag per scan type or per tenant.** `SCAN_ENGINES_ENSEMBLE_ENABLED` (`apps/workers/src/config.js`, default `false`, strictly `"true"`) is read by the scan worker (`apps/workers/src/scan/index.js`) and by the pipeline worker's engine registry (`buildPipelineEngineRegistry`, `apps/workers/src/execution/registry.js`). Turning it on replaces the SBOM engine `sbom/default` with the ensemble and makes SCA, SAST and Secrets tasks real instead of `unsupported`, **for every tenant served by those workers, all four types at once.** The per-type flags `SCAN_ENGINE_SBOM|SCA|SAST|SECRETS` and the canary tenant allowlist of SPEC SE-28 / OQ-18 are **Recommended, not built, and OQ-18's canary list is still Open** (a code search of `apps` and `packages` finds none; from the code).
2. **Consequence for the plan "off, internal tenant, canary tenants, general":** with the current code that sequence cannot be done by tenant inside one deployment. Two ways to realise the stages, for the owner to choose (nothing here is decided):
   - **Option A (no code change, recommended for v1):** stage by **environment**. Stage 1 is a non-production environment with its own workers (and its own database copy or schema); stage 2 is a production deployment where the scan and pipeline workers that serve only the canary tenants run with the flag on. This needs a way to route canary tenants to separate workers, which is an operations question this repository does not answer (UNVERIFIED that queues can be split per tenant; today the queues are `scan` and `scan-untrusted`, not per tenant).
   - **Option B (a code change, a separate work item):** implement SE-28's per-type flags and a tenant allowlist, Zod-validated at start, with tests in the security suite (the allowlist is a tenant-isolation-relevant control, ADR-008 area 18). Larger, but is what the original staged plan assumed.

The stages below are written so they hold under either option; "tenant" in a stage means "tenant or environment".

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
| a **real downloader** for the vulnerability databases | production SCA | **does not exist**; Part F ships a fake one (SPEC 17.p) and OQ-29 (integrity anchor) is Open. Until it exists, snapshots are hand-built bundles (`ENG_L21_RUNBOOK.md` section 2) |
| production image lock | production | `loadImageLock({ production: true })` must pass: needs the three own-built digests (gate G-3) |

SCA also needs a promoted snapshot per tool; with none, every SCA task fails closed with `db_unavailable` and **no container starts** (SPEC 5.12; verification in ENG-L09).

## 3. Stages

Each stage has an entry condition (gates from `LIVE_TEST_PLAN.md` section 4) and an exit condition. A stage is never skipped. No stage is entered by this documentation.

| Stage | Flag | Who is affected | Entry condition | What to watch and exit condition |
|---|---|---|---|---|
| 0. Off (today) | `SCAN_ENGINES_ENSEMBLE_ENABLED=false` (default) | everyone gets SBOM-lite; SCA, SAST and Secrets are `unsupported` | none | n/a. This is the rollback target |
| 1. Non-production, internal | `true` in a non-production environment (development, staging) | the team's own test repositories only | live phases 0 to 4 and ENG-L11/L14 passed there (G-2 evidence, G-10); local own-built images accepted for this stage only | every scan type produces one real result; `incomplete` and `degraded` reasons explained; no orphan containers; no secret value in any store (ENG-L14); T-29 checked by a human (G-9). Exit: G-10 and G-9 DONE |
| 2. Internal tenant in production | `true` for the owner's own tenant (Option A: dedicated workers; Option B: allowlist) | internal users only | **all gates G-1 to G-6 and G-12 DONE**, G-3 specifically so `loadImageLock({ production: true })` passes; G-4 (real downloader and the OSV hash source) DONE if SCA is included; legal sign-off (G-1) in writing | one to two weeks of normal use (duration is a Recommendation, not a decided number): failure ratio per tool, DB snapshot age tiers, janitor reaps, capacity waits, run durations against the calibrated limits. Exit: no unexplained failure, G-8 DONE |
| 3. Canary tenants | `true` for a short, owner-chosen list | named customers who agreed | stage 2 exit; G-7 (mutation backlogs) worked or explicitly waived by the owner; G-13 (a suppression path) understood: while it is missing, inline suppressions are ignored and developers have no path (OQ-16) | same signals plus support tickets about findings that look wrong; compare findings against the previous engine where both ran. Exit: owner decision |
| 4. General | `true` for all | everyone | stage 3 exit, owner decision | continue monitoring; keep the rollback below ready for at least the first release cycle |

Per-type enablement (for example SCA last, because it depends on the database operation) is **not possible** with the current single flag (section 1). If the owner wants it, that is Option B.

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

- **Quarantine block (the only built alert):** a refresh rejected as `quarantined_source` writes one platform audit entry (`scan_db.quarantine_denied`, visible to Root Console administrators with `platform.audit_log.view` at `GET /api/v1/platform/audit-logs`) and one warn log line (SPEC 17.s). No paging or notification channel exists; someone must be assigned to look (gate G-5).
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
- Any per-tenant or per-type staging (it does not exist), and whether production workers can be split per tenant.
- A mid-run rollback, and behaviour of stored ensemble results after the flag is turned off.
- The existence and content of the scan-engines mutation backlog from Part M (built in parallel; this file does not cite its numbers).
- Legal acceptability of any data licence (a lawyer's decision, OQ-26).
