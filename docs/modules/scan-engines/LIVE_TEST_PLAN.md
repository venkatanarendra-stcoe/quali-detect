# Scan engines: live test plan and pre-production gate register (Part N)

Status: **written 2026-11-22 (Part N, documentation only).** Nothing in this file was executed by its author: the author had no container runtime for this work item and ran only read-only checks (`ls`, `grep`) to confirm that each script path below exists. Every expected result is copied from the runbooks, `IMAGES.md` and SPEC 17.*; where a result was observed in the development sandbox (rootful Docker 29.1.3) it says so, and anything on rootless runtimes, other architectures or large repositories is **UNVERIFIED**.

This is the single checklist for the owner's Docker machine. Rollout is in `ROLLOUT.md`. The suite (`pnpm test:security`) never starts a container; everything here is by hand.

## 0. How to use this file

1. Work top to bottom through section 3 (the order is the dependency order). Each item has: purpose, prerequisites, commands, expected result, pass/fail, what to paste back, and a class: **GATE** (required before production, also listed in section 4) or **INFO** (informational, feeds calibration or a decision).
2. Paste the "paste back" material into the session (or the tracker) so results can be recorded in `docs/development/PROGRESS_TRACKER.md` and the SPEC 16.2 status cells. Never paste a token, a real secret or private repository content.
3. Where this plan says "no script exists", that is a fact: ENG-L01 to L05, L08, L12, L14, L15 and L16 have **no automated driver** in the repository (Part N may not invent commands). The plan gives the procedure and the standard runtime commands to use; those runtime commands are **UNVERIFIED as written** (not run by the author) and the item's first step is to print the platform's real `buildRunArgs` output so you probe the production flags, not a copy.

### Conventions

- Run from the repository root, Node 22.22 or newer, `pnpm install` done. Use a work directory under `/tmp` (the sandbox policy refuses mounts below `/home`).
- `RUNTIME` below is `docker` or `podman`; run the whole plan once per runtime that is to be supported (rootless Podman is the development adapter default, `SANDBOX_RUNTIME_BIN=podman`; rootless Docker is the alternative).
- Images are identified by digest, never by tag. Own-built images (Opengrep, detect-secrets, block-extractor) have **no registry digest yet**; the scripts accept the locally built image as `repo@sha256:<local image id>` through script-only options (the worker never does).

## 1. Script inventory (every path verified to exist in this checkout with `ls`)

| Path | Used by | Needs |
|---|---|---|
| `apps/workers/scripts/eng-l20/capture.js` (`images`, `prepare`, `run`, `--dry-run`) | L01 (prints the production argv), L02, L03, L06, L07, L15, L20 | Docker or Podman, the pinned Syft and Trivy images |
| `apps/workers/scripts/eng-l20/compare.js`, `compare-lib.js`, `lock.js`, `sample-tree.js` | L20 (offline comparison; no Docker) | the `capture.js run` output directory |
| `apps/workers/scripts/eng-l21/run-sca.js` | L09, L19, L21 | Trivy and OSV-Scanner images, the two downloaded databases |
| `apps/workers/scripts/eng-l22/run-sast.js` | L10 (SAST), L22 | Bandit image, locally built Opengrep image |
| `apps/workers/scripts/eng-l23/run-secrets.js` | L10 (secrets), L23 | Gitleaks image, locally built detect-secrets image |
| `apps/workers/scripts/eng-j/run-evidence.js` | L14 (partial: canary on the evidence path), L17 (links printed), Part J live run | Gitleaks, detect-secrets, Opengrep and extractor images |
| `apps/workers/scripts/dev.js` | local dev stack only (not a live-test driver) | |

Runbooks: `ENG_L20_RUNBOOK.md`, `ENG_L21_RUNBOOK.md` (also covers L09 and L19), `ENG_L22_RUNBOOK.md`, `ENG_L23_RUNBOOK.md`; result record of the sandbox run: `ENG_L20_RESULT.md`; image facts: `IMAGES.md` sections 1 to 10; provisioning: `IMAGE_CATALOG.md` section 3.

## 2. Order and dependencies at a glance

```
Phase 0  provision      images by digest + local own builds (section 3.0)
Phase 1  runtime gate   L18 (rootless, uid map, seccomp, gVisor) --> L01 --> L02 --> L03 --> L04 --> L05
Phase 2  hostile input  L06, L07, L08  (need L01 flags confirmed)
Phase 3  real tools     L20 (SBOM) --> L21 (SCA, needs DBs) --> L22 (SAST) --> L23 (Secrets) --> Part J run (evidence)
Phase 4  data/DB        L09 + L19 (mirror, canary, stale tiers, data cleanliness)  [needs L21]
Phase 5  scale          L10 (calibration), then L22(b) and L23(b) large-repo runs
Phase 6  platform       L11 (end to end, flag ON in a non-production environment), L12 (fork), L14 (canary sweep), L15 (pull never, digest), L16 (only if gVisor/Kata), L17 (permalinks)
Phase 7  humans         T-29 browser and screen-reader check, SBOM download button, security review of the rule pack, legal sign-off
```

Rule: a failure in Phase 1 stops everything after it (the later results would be about an unsafe runtime). L18 is first because the answer (rootless, uid map, seccomp profile) changes the flags L01 to L08 must be run with.

## 3. The items

### 3.0 Phase 0: provisioning (prerequisite of everything)

- **Purpose:** have every locked image in the local store of the runtime that will run the scans, as the user that runs it (rootless stores are per user, `IMAGE_CATALOG.md` section 3 step 4).
- **Commands:** `node apps/workers/scripts/eng-l20/capture.js images` prints the pull commands for Syft and Trivy; `docker pull` the other digests of `IMAGES.md` section 1 (OSV-Scanner `ghcr.io/google/osv-scanner@sha256:a70ffffc...`, Bandit `ghcr.io/pycqa/bandit/bandit@sha256:b405a808...`, Gitleaks: copy the digest from `IMAGES.md` section 1, not from memory). Then `node apps/workers/scripts/eng-l20/capture.js images --check` (prints `OK`, `UNKNOWN` or `MISSING` per image; `UNKNOWN` means the store reports no RepoDigests, which the containerd image store sometimes does).
- **Own builds:** build Opengrep, detect-secrets and the block extractor from their recipes (`IMAGES.md` sections 8, 9 and 10; the extractor Containerfile is under `apps/workers/src/execution/engines/ensemble/evidence/extractor-image/`) and note each local image id for the `--*-local` options.
- **Pass:** every pinned image `OK`; three local image ids written down. **Paste back:** the `images --check` output and the three local ids.

### ENG-L18: rootless isolation gate (first; GATE, OQ-27, D-20)

- **Purpose:** prove the sandbox works with a rootless runtime, with the uid mapping of the `0755/0644` tree, the platform seccomp profile and (if chosen) gVisor. The Part A spike used rootful Docker only.
- **Prerequisites:** rootless Podman and/or rootless Docker installed for a non-root user; the worker's `.env` fields `SANDBOX_RUNTIME_BIN`, `SANDBOX_USER` (default `65534:65534`), `SANDBOX_USERNS_MODE` (`keep-id`, `auto` or `nomap`), `SANDBOX_UIDMAP`, `SANDBOX_GIDMAP`, `SANDBOX_SECCOMP_PROFILE` (all exist in `apps/workers/src/config.js`). Decide the production values and use exactly those.
- **Commands:**
  1. `RUNTIME info` and confirm it reports rootless (Podman: `podman info --format '{{.Host.Security.Rootless}}'`; Docker: `docker info --format '{{.SecurityOptions}}'` contains `rootless`). UNVERIFIED as written.
  2. Repeat Phase 0 as that user, then the whole of `ENG_L20_RUNBOOK.md` sections 1 to 4 with `--runtime podman` where the script option exists (`capture.js` accepts `--runtime`; confirm with `node apps/workers/scripts/eng-l20/capture.js` usage output).
  3. Run L01 to L05 and L08 under each runtime to be supported (SPEC 16.2 L18). For gVisor: install `runsc`, add it as an OCI runtime and repeat (this is also L16).
- **Expected:** a non-root container user reads the extracted tree (L02), the seccomp profile named in `inspect` is the platform profile (not the default), no mapping leaves the tree world-writable on the host.
- **Pass/fail:** PASS only if L01 to L05 and L08 all pass under every supported runtime and the `inspect` shows rootless. FAIL if any needs a rootful fallback: then rootless is not supported and the production design (dedicated scan-runner, ADR-014) must be reconsidered. **Paste back:** runtime versions, `info` lines, the `SANDBOX_*` values used, per-item results.

### ENG-L01: the live container matches the generated invocation (GATE)

- **Purpose:** the flags the code generates are the flags the runtime actually applies.
- **Prerequisites:** Phase 0; L18 settings.
- **Commands:** `node apps/workers/scripts/eng-l20/capture.js prepare --work /tmp/qm-l01 --sample` then `node apps/workers/scripts/eng-l20/capture.js run --work /tmp/qm-l01 --dry-run` (prints every production argv; runs nothing). Start one long-lived probe with the same argv (copy a printed command, replace the tool command with `sleep 300`, drop `--rm` only if you need to inspect after exit), then `RUNTIME inspect <name>` (UNVERIFIED as written; no script automates this).
- **Expected (SPEC 16.2, 6.2):** network mode `none`, read-only rootfs, `CapDrop` ALL, `no-new-privileges`, the seccomp profile, user `65534:65534`, pids/memory/cpu limits, every mount read-only, no socket mount, labels `qm.scan=1` and the deadline label.
- **Pass/fail:** every listed property present; any missing or extra (a writable mount, a socket, `--privileged`, a network) is FAIL. **Paste back:** the `inspect` JSON (contains local paths, no secrets).

### ENG-L02: non-root user reads the tree (GATE)

- **Purpose:** uid mapping makes the `0755/0644` tree readable and not writable by the container user, and hides the host home and the worker's other temp dirs.
- **Commands:** with the L01 probe argv, run `ls -ln /src`, `cat` of one file, a write attempt into `/src`, `ls /home`, `ls /tmp` inside the container (UNVERIFIED as written). `eng-l20/capture.js run` already exercises the read as the user (`syft-sealed` exit 0 on a populated tree).
- **Pass:** read succeeds, write fails (read-only), no host home or other temp content visible. **Paste back:** the command outputs.

### ENG-L03: no network, including host loopback and metadata (GATE)

- **Purpose:** T5 (exfiltration): DNS, public TCP, host loopback services (PostgreSQL, Redis, RabbitMQ ports), the container gateway and the metadata address `169.254.169.254` all fail from inside a probe.
- **Prerequisites:** the dev stack running (so loopback ports are really open). Do not stop it.
- **Commands:** from the L01 probe image use a tool present in the image (the pinned scan images are minimal; if none has a client, add a temporary probe image **outside the lock**, never used by the worker). Test `nslookup`/`getent hosts`, a TCP connect to a public IP, to `127.0.0.1:5432`, `:6379`, `:5672`, to the gateway, and to `169.254.169.254:80` (UNVERIFIED as written; no script).
- **Pass:** every attempt fails (no interface, no route). One success is FAIL and blocks production. **Paste back:** each attempt and its error text.

### ENG-L04: resource bombs (GATE)

- **Purpose:** memory bomb is OOM-killed (`out_of_memory`), a fork bomb is stopped by the pids limit, a CPU spin is killed at the wall clock, a tmpfs fill stops at its size, a stdout flood is capped, and the host stays healthy.
- **Commands:** `eng-l20/capture.js run` already runs `syft-oom` and `trivy-oom` (`--memory=8m`, expected exit 137 and empty output, INFO there). The fork bomb, CPU spin, tmpfs fill and stdout flood have **no script**; run them as a probe command under the L01 argv (UNVERIFIED as written), watching the host with `docker stats`/`top` in another terminal.
- **Pass:** each is contained and the host never degrades; the worker classification is `out_of_memory` and the like (SPEC 5.3). **Paste back:** exit codes, durations, peak host memory.

### ENG-L05: abort, SIGKILL and the janitor (GATE)

- **Purpose:** no orphans: abort kills and removes containers, `kill -9` of the worker mid-run leaves containers that the janitor removes within `SCAN_RUNNER_JANITOR_SECONDS` (default 60), a reclaimed attempt does not collide.
- **Prerequisites:** a worker started with `SCAN_ENGINES_ENSEMBLE_ENABLED=true` in a **non-production** environment (needs ROLLOUT step 1 settings and a scan that takes long enough, e.g. a large tree).
- **Commands:** start a scan; cancel it from the UI/API and run `RUNTIME ps --filter label=qm.scan=1`; start another, `kill -9` the worker, run `RUNTIME ps --filter label=qm.scan=1` again after the janitor interval (UNVERIFIED as written; no script).
- **Pass:** the list is empty after cancel and after the janitor interval; the retried task succeeds. **Paste back:** both `ps` outputs and the worker log lines.

### ENG-L06: repository code is never executed (GATE)

- **Purpose:** planted `postinstall`/`prepare` scripts, `setup.py`, Maven/Gradle plugins, `go:generate`, a Makefile, `.git/hooks` and `.pre-commit-config.yaml` never run under any tool.
- **Commands:** build a tree with markers (each script writes a marker file or prints a unique string), then run every tool over it: `eng-l20/capture.js prepare --work W --tarball <your planted tarball>` and `run`, then `eng-l21/run-sca.js`, `eng-l22/run-sast.js`, `eng-l23/run-secrets.js` with `--tree` (their `--tree`/work options are in the runbooks; the tool scripts use fixed fixture trees by default, so confirm the option with each script's usage output before relying on it: UNVERIFIED).
- **Pass:** no marker in stdout or stderr, no marker file, no package-manager child process. **Paste back:** greps for the markers and the tool exit codes.

### ENG-L07: configuration planting (GATE; partly run in the sandbox)

- **Purpose:** repository configuration and inline suppressions cannot change results.
- **Commands and status:** already built into the scripts and **run once in the sandbox**: SBOM planted (`capture.js run`, rows `syft-planted`/`trivy-planted`, compared by `compare.js`), SCA planted (`run-sca.js`, `.trivyignore`, `trivy.yaml`, `osv-scanner.toml`), SAST planted (`run-sast.js`: `.semgrepignore`, `.gitignore`, `.semgrep.yml`, `.opengrep/`, `.bandit`, `setup.cfg`, `pyproject.toml`, `nosemgrep`, `nosec`), Secrets planted (`run-secrets.js`: allow-all config, ignore file, baseline). Re-run all four on the owner machine and on one real repository copy. `.grype.yaml` is out of scope (Grype is deferred, D-21).
- **Pass:** every line `PASS`, exit 0, the planted run equals the clean run (the Secrets deny list applied; without it Gitleaks finding nothing is the documented INFO). **Paste back:** the four scripts' full output.

### ENG-L08: hostile archives against the real extractor and tools (GATE)

- **Purpose:** bombs, links, traversal, one million tiny files, deep trees, giant lines, bidi/NFC names stay bounded in time and memory, with the expected codes, and the worker stays alive.
- **Commands:** the extractor is `extractTarGz` (used by `eng-l20/capture.js prepare --tarball`). Build hostile tarballs yourself (no generator script exists for the live test; the suite covers the logic with Docker-free fixtures, `ENG-S07`), run `prepare` on each and watch time and memory; for the tools use `eng-l20/capture.js run`. UNVERIFIED as written.
- **Pass:** bounded, expected rejection codes (SPEC 11.2), no crash. **Paste back:** per hostile case the code, time and peak memory.

### ENG-L20: SBOM real-output fidelity (INFO for gating, DONE once in the sandbox)

- **Purpose:** adapters agree with real Syft 1.57.2 and Trivy 0.76.2 output. Already run on 2026-11-20 and reconciled (SPEC 17.n, `ENG_L20_RESULT.md`); re-run on the owner machine (rootless runtime, your architecture).
- **Commands:** `ENG_L20_RUNBOOK.md` sections 1 to 4 verbatim: `capture.js images`, `docker pull` the two digests, `capture.js images --check`, `capture.js prepare --work "$W" --sample`, `capture.js run --work "$W" --dry-run`, `capture.js run --work "$W" --out "$OUT"`, `compare.js "$OUT" --tree "$W/trees/clean" --json /tmp/eng-l20-report.json`.
- **Pass:** `compare.js` exit 0 (no `MISMATCH`), `UNKNOWN` items explained. **Paste back:** the report JSON, `$OUT/manifest.json`, stderr of any `MISMATCH`/`UNKNOWN` (runbook section 5).

### ENG-L21: SCA real run (INFO for gating; feeds L09 and L19)

- **Commands:** `ENG_L21_RUNBOOK.md` section 1: download the Trivy DB and the four OSV archives with the two `docker run` lines, `capture.js prepare --work $W --sample`, then `node apps/workers/scripts/eng-l21/run-sca.js --work $W --tree $W/trees/clean --trivy-db $W/trivy-db --osv-db $W/osv-db`.
- **Expected:** both tools `succeeded`, nothing dropped, roll-up row 5 `complete`, the planted run equal to the clean run, every line `PASS`, exit 0. Counts depend on the day (58 findings per tool on 2026-11-21).
- **Paste back:** the full output and the DB sizes.

### ENG-L22: SAST real run and rule-pack review (INFO for the run; the review is a GATE)

- **Commands:** `ENG_L22_RUNBOOK.md` section 2: `cp -r apps/api/test/security/fixtures/scan-engines/sast/tree $W/tree`, `node apps/workers/scripts/eng-l22/run-sast.js --work $W --tree $W/tree --opengrep-local qm-spike-opengrep@sha256:<local image id>`.
- **Expected (2026-11-21, Opengrep 2.0.0, Bandit 1.9.4):** Opengrep 26, Bandit 13, 33 merged of which 6 carry both tools, row 5 complete, planted equals clean, every line `PASS`, exit 0.
- **Paste back:** full output; for the rule pack review see gate G-6 (section 4).

### ENG-L23: Secrets real run (INFO for the run)

- **Commands:** `ENG_L23_RUNBOOK.md` section 2: `node apps/workers/scripts/eng-l23/run-secrets.js --work /tmp/qm-engl23 --detect-secrets-local qm-spike-detect-secrets@sha256:<local image id>`. Never place a real secret in the tree.
- **Expected (Gitleaks 8.30.1, detect-secrets 1.5.0):** Gitleaks 9, detect-secrets 15, merged 15 (9 with both), row 5 complete, planted equals clean, no fake value in the canary line, every line `PASS`, exit 0. The default-allowlist gap (Gitleaks skips `node_modules`, lock files, `go.sum`, images) is accepted (D-27 (2)): verify the coverage note text appears on a real Secrets task in the UI (gate G-9).
- **Paste back:** full output.

### Part J evidence run (INFO; also covers part of L14)

- **Command:** `node apps/workers/scripts/eng-j/run-evidence.js --work /tmp/qm-engj --detect-secrets-local <ref> --opengrep-local <ref> --extractor-local <ref>`.
- **Expected (2026-11-22 sandbox):** 15 of 15 secret findings with a masked preview and no fake value or SHA-1 in any row or log line; 33 SAST findings with 27 blocks and 6 windows, extractor `ok`.
- **Pass:** canary clean, every preview masked. **Paste back:** the output. **Not covered:** very large files, the real 5 s extractor timeout (UNVERIFIED).

### ENG-L09 and ENG-L19: mirror, canary, stale tiers, data cleanliness (GATE for L19 with OQ-26/OQ-29)

- **Purpose:** the real downloader does not exist yet (Part F ships a fake one, SPEC 17.p). L09 verifies promotion, rejection and staleness with hand-built bundles; L19 verifies the data is free of quarantined records.
- **Commands:** follow `ENG_L21_RUNBOOK.md` sections 2 and 3 exactly (hand-build `trivy.tar.gz` and `osv.tar.gz`, promote through the repository functions as the Part F checks do, set `SCAN_DB_MIRROR_ROOT`, `SCAN_DB_CACHE_ROOT`, `SANDBOX_RULES_DIR`, run an SCA scan with the host network disabled; change `upstreamBuiltAt` to test the 3, 14 and 30 day tiers; empty cache gives `db_unavailable`, no container started without a snapshot). For L19, run `inspectSnapshotArchive`/`classifyRecord` over the four real OSV archives (the runbook names them; **no wrapper script exists**, so this is a small ad hoc call by the operator: UNVERIFIED) and grep for `chainguard`, `wolfi`, `cgr.dev`, `CGA-`.
- **Expected:** a good candidate is promoted; a corrupted one is rejected (`canary_failed` or `integrity_*`); the canary expects `CVE-2021-23337` / `GHSA-35jh-r3h4-6jhm` for lodash 4.17.20; attribution text visible on T-29; zero quarantined records.
- **Known open problem:** the Trivy DB is an opaque bbolt file the record check cannot see inside; it also carries distro vendor ratings the platform never reads (ENG-S06j). This is a **legal** question (gate G-1), not a technical pass/fail.
- **Paste back:** promoted/rejected outcomes, the record counts, the T-29 screenshot of the DB column and attribution (no tenant data).

### ENG-L10: calibration and sizes (INFO; feeds SPEC 5.8, 7.3, OQ-10, OQ-21)

- **Purpose:** measure wall clock, peak memory (`docker stats` or `/usr/bin/time -v` around the script), stdout size and image/DB sizes on a small (hundreds of files), a medium (10 000 files) and a large (100 000 files with a committed `node_modules` or `vendor`) repository, per tool.
- **Commands:** the same scripts (`run-sca.js`, `run-sast.js`, `run-secrets.js`, `capture.js run`) over your trees; the points to settle per tool are in `ENG_L22_RUNBOOK.md` section 3 and `ENG_L23_RUNBOOK.md` section 3 (vendored dirs, Bandit 32 MiB output cap, minified/over-1 MB files, tree-walk time, `errors[]` making a run `partial`, Gitleaks 1 GiB, decode depth). No dedicated L10 script exists.
- **Pass:** no limit of SPEC 5.8 (Opengrep 2 CPU/3 GiB/600 s/64 MiB; Bandit 1 CPU/1 GiB/240 s/32 MiB; Gitleaks and detect-secrets 1 CPU/1 GiB/300 s/32 MiB) is hit on a medium repository; for the large one record what is hit and decide new numbers. It is a GATE only for "large-repo performance is acceptable" (G-8). **Paste back:** a table per tool and size.

### ENG-L11: end to end per scan type with the flag ON (GATE, non-production environment)

- **Purpose:** one real result per scan type through the whole platform (webhook or manual run, pipeline, scan worker, DB, API, T-29), determinism (two runs give identical findings and `run_manifest_sha256`), and for SBOM the real Syft/Trivy agreement.
- **Prerequisites:** ROLLOUT steps 1 and 2; for SCA a promoted snapshot (L09); for SAST and Secrets the local own-built images are **not resolvable by the worker** (the production lock refuses them and the development lock has no digest), so the engine reports them `image_unavailable` and the task `degraded` until digests are recorded (gate G-3). Decide: do the end-to-end in a non-production lock with the mirror digests recorded, or accept the degraded result as the observed behaviour.
- **Commands:** by the UI/API on a test repository; no script. Run the same execution twice and compare findings and the manifest hash.
- **Pass:** per type the expected tool statuses, coverage, findings and no secret value anywhere. **Paste back:** the task DTO of `GET /executions/{id}` (redacted if needed) and screenshots of T-29.

### ENG-L12: fork pull request (GATE)

- **Purpose:** an `untrusted_fork` run has no credential in the container environment, runs from the `scan-untrusted` pool, and honours the fork share (`SCAN_UNTRUSTED_CAPACITY_SHARE`, default 50) and tighter limits.
- **Commands:** open a fork PR on the test repository with the flag ON; `RUNTIME inspect` a running container (`Config.Env` has no token). No script. UNVERIFIED.
- **Pass:** no credential in `inspect`, correct pool, limits honoured. **Paste back:** the `inspect` env block (redacted) and the worker log lines.

### ENG-L13: Windows (WSL2) and macOS smoke (INFO, deferred)

Deferred by the owner (D-12: Linux dev only). Do not run; listed so the register is complete.

### ENG-L14: canary secrets sweep (GATE)

- **Purpose:** a canary secret seeded in a repository appears nowhere: database, task logs, events, outbox, RabbitMQ messages, Redis, Socket.IO frames, API responses, error bodies, stored evidence (and encodings).
- **Commands:** `eng-j/run-evidence.js` and `eng-l23/run-secrets.js` already check the stored rows and log lines of the engine path (sandbox-verified). The platform-wide sweep (DB dump, RabbitMQ and Redis inspection, Socket.IO capture) has **no script**; seed the canary in a test repository, run a Secrets scan with the flag ON, then search each store for the canary and its base64/hex forms. UNVERIFIED.
- **Pass:** zero hits. **Paste back:** the list of stores searched and the counts (not the canary values if real).

### ENG-L15: fail closed and image provenance (GATE for the mirror part)

- **Purpose:** a missing image is `unavailable` and never pulled (`--pull=never`); a digest mismatch is refused; the image signature and self-scan results are recorded.
- **Commands:** remove one pinned image from the store and run `capture.js run` for it (expected failure, no network); `capture.js images --check` reports `MISSING`; for the production lock run `node -e` with `loadImageLock({production:true})` (exported by `apps/workers/src/execution/engines/ensemble/catalog/index.js`) and confirm it passes only after gate G-3 is done and refuses before (UNVERIFIED as written; do it from the repository root with ESM `--input-type=module`). Signing (cosign) and the self-scan are deferred to production (D-4); record whatever is done in the lock entry.
- **Pass:** fail closed; the production lock loads. **Paste back:** the outputs.

### ENG-L16: gVisor or Kata (GATE only if chosen)

Repeat L01 to L08 under the chosen runtime (see L18). Skip, and mark "not supported", if only plain rootless runc is used.

### ENG-L17: permalink range format (INFO, GitHub only is wired)

- **Purpose:** the GitHub `#L<start>-L<end>` link highlights the range, using the installation token against a real repository. GitLab and Bitbucket formats stay documentation until those providers are wired (Part J owner decision: `scmRef.provider` is GitHub only).
- **Commands:** `eng-j/run-evidence.js` prints the links it builds; open three of them in a browser on a repository whose commit exists (the script uses a fixture commit sha, so for a real check use the UI of a real execution). No token is read by the script. UNVERIFIED on a real repository.
- **Pass:** the range is highlighted at the right lines, private repository links need the viewer's access. **Paste back:** which links were opened and what was highlighted.

## 4. Pre-production gate register

Status vocabulary: **OPEN** (not done), **PARTIAL** (some evidence, gate not met), **DONE**. Nothing is DONE at the time of writing. The ENG-L reference says where the evidence is produced.

| Gate | What must be true before production | Evidence and owner action | Source | Status |
|---|---|---|---|---|
| G-1 | **Legal sign-off of the vulnerability-data licences and attribution** (GHSA CC-BY-4.0 with attribution, NVD, OSV per-source terms, the Trivy DB including the mirrored distro-vendor ratings `redhat`, `ubuntu`, `azure`, `bitnami` that the platform never reads, Chainguard non-commercial data kept out). Alternative: restrict the data further or require the v2 own-built database | Written legal review; ENG-L19 counts and the L21 runbook section 3 question put to the lawyer; attribution text on T-29 reviewed | OQ-26, D-15, D-25 (6), SE-48 | OPEN. **LEGAL NOTE (2026-11-23, E2E evidence, `E2E_RESULT.md` section 6 B7): Chainguard `CGA-` identifiers ARE present in the real OSV data the E2E loaded.** 966 of 9 989 OSV Go records carry a Chainguard `CGA-` id in the `related` field (967 occurrences), and some records mention Chainguard in text (npm 16, Maven 2). The platform's quarantine check did NOT inspect real record contents: `record_counts` of both real active snapshots was `records 0`, and `classifyRecord` looks at the record id, not `related`, so it allowed a sample of 50 such records. What is known about the stored findings: a read-only check of the E2E result dump (`/tmp/qm-e2e/e2e-results-data.sql`, 108 distinct CVE/GHSA/GO ids across the stored items) found **0** occurrences of `CGA-` (and no `chainguard` or `wolfi` text), and none of the stored ids matches any of the 966 Go records with a `CGA-` related id; so, for that run, `CGA-` data reached the loaded snapshot but **not** the stored findings. UNVERIFIED: the Trivy database (opaque bbolt file, never inspected, may carry other non-commercial data); the OSV npm, PyPI and Maven archives were not scanned for `related` references; other repositories and other days will pull other records; whether merely loading and querying the data (without storing or showing it) is itself a licence question. **This needs legal review independent of the code fix** (B7, gate G-21): fixing `classifyRecord` does not answer whether data already downloaded to developer machines or snapshot stores is acceptable. |
| G-2 | **Rootless isolation verified**: rootless Podman/Docker, uid mapping, platform seccomp profile applied, gVisor if chosen; L01 to L05 and L08 pass under every supported runtime; `SANDBOX_*` values recorded | ENG-L18 (plus L01 to L05, L08, L16) | OQ-27, D-20, ADR-014 | OPEN |
| G-3 | **Mirror registry and recorded digests for the three own-built images** (Opengrep, detect-secrets, block-extractor) so `loadImageLock({ production: true })` passes (today it refuses them: local build, no registry digest) | Build, push by digest to the mirror, record `repository@digest` in `images.lock.json` (one reviewed entry per image, `IMAGE_CATALOG.md` section 3), approval fields, then ENG-L15 | D-14, D-27 (4), OQ-12 | OPEN |
| G-4 | **OSV sha256 source decided and the real downloader built** (the integrity anchor of the OSV zips). **Decision 2026-11-23 (SPEC 17.ac (6)): OQ-29 is deferred to the build of the real downloader; the default approach is trust on first use (fetch the archive, hash it, pin the sha256, verify it on every later fetch) unless OSV publishes a trusted checksum at that time.** | The real downloader implements the pin and the verification and a changed pin is a refresh failure that needs an operator (the pin, the first fetch and who may reset a pin are part of that build); then ENG-L09 on real data | OQ-29, D-24 (f), 17.ac (6) | OPEN (decision recorded, code missing) |
| G-5 | **Quarantine operator surface and watcher (pre-production operations gate)**: a quarantine-blocked refresh is one platform audit entry (`scan_db.quarantine_denied`) plus a warn log. **Decision 2026-11-23 (SPEC 17.ac (4)): the watcher is deferred to pre-production operations**: build a visible operator surface and assign an owner then; until then the platform audit log query is the interim way to see it and nobody is assumed to be watching | Trigger a quarantined candidate in a non-production environment, find the entry in Root Console platform audit logs (`platform.audit_log.view`); then, before production: the operator surface exists, someone is named who gets it, and that person has seen one | SPEC 17.s, 17.ac (4), SE-39 | OPEN (deferred by decision) |
| G-6 | **Security review of the platform SAST rule pack** (23 rules, JavaScript/TypeScript, Python, Go; false positives, false negatives, severity and CWE, licence statement in each file header); the comprehensive pack stays an ongoing deliverable | Security team review of `apps/workers/src/execution/engines/ensemble/sbom/rules/qm-sast/`; ENG-L22 (c); results recorded in OPEN_DECISIONS | OQ-25, D-16, D-26 | OPEN |
| G-7 | **Mutation backlogs worked**: the Executions mutation sweep backlog (122 survivors, `docs/modules/executions/MUTATION_SWEEP_BACKLOG.md`) and the scan-engines mutation backlog (`docs/modules/scan-engines/MUTATION_BACKLOG.md`: 219 survivors; **104 triaged on 2026-11-23, 115 not triaged**; the security-relevant groups are done, the **full triage (A) is still required before general availability**) | Each remaining survivor killed with a stronger check, or justified as equivalent, in the owner's weekly security-test slot | ADR-008, Executions 17.ai, SPEC 17.ac | PARTIAL (Executions open; scan engines 104 of 219 triaged) |
| G-8 | **Large-repository performance accepted**: limits of SPEC 5.8 calibrated or confirmed on a 10 000 and a 100 000 file repository for every tool (Bandit's 32 MiB cap, vendored directories, Gitleaks memory) | ENG-L10, ENG-L22 (b), ENG-L23 (b) | OQ-10, OQ-21, 7.3 | OPEN |
| G-9 | **Human UI check**: T-29 (tools list, coverage line, notices, DB column and attribution, the Secrets coverage note) and the SBOM download button in a real browser, dark theme, keyboard only and a screen reader (SCREENS verification matrix) | By hand; screenshots and a pass/fail line per matrix row | Part L, SCREENS, D-24 (e) | OPEN. 2026-11-23: T-29 was **machine-checked only** in headless Chrome against the real tenant-web and API (`E2E_RESULT.md` section 5); no human review, no screen reader, no mobile width, no light theme, no other roles; this does not meet G-9 |
| G-10 | **One real ensemble result per scan type end to end with `SCAN_ENGINES_ENSEMBLE_ENABLED=true` in a non-production environment**, including determinism (two runs, same manifest hash) and no secret value in any store | ENG-L11, ENG-L14, ENG-L12 | SPEC 14, D-12 | **PARTIAL 2026-11-23: MET on the FIXTURE path, real-GitHub path PENDING repo content.** Evidence `E2E_RESULT.md`: a local sample tree served through the real worker path (real API, pipeline, scan and outbox workers, real tools in the Docker sandbox, real DB snapshots, flag ON in an isolated stack) gave one real result per scan type (SBOM 19, SCA 58, SAST 36, Secrets 20 items), two runs with the identical manifest hash, and 0 secret needles in the dump, logs and DTOs. The real-GitHub path (`STCOE-TESTING/qm-test-2-renamed`) produced almost nothing (6 SBOM components, nothing else: the repository has only a `package.json`, no lockfile) and is pending repository content. The fixture path needed a dev-only own-built image workaround (B2) and the real data load needed the B1 cap raised in a reverted working tree; both are open gate items below. Not verified: L12 fork PR, permalink resolution, SBOM document 27 versus 19 items |
| G-11 | **Gitleaks default-allowlist coverage note confirmed**: the accepted gap (`node_modules`, lock files, `go.sum`, images) is visible to users in the Secrets coverage statement and the legal/security owners accept it | G-9 screenshot of the note; decision stays ACCEPTED for v1 (D-27 (2)); no custom ruleset is forked | D-27 (2), ENG-L23 (c) | OPEN (note built, display unverified) |
| G-12 | **Image provenance**: owner approval fields, signature check (cosign) and self-scan recorded per lock entry, or an explicit owner waiver for v1 (signing deferred to production, D-4) | ENG-L15; lock entries | D-4, IMAGE_CATALOG 4 and 5 | OPEN |
| G-13 | **Suppression workflow exists before release** so developers have a path when inline suppressions are ignored (OQ-16) | Findings module (does not exist yet, SPEC 0.1) | OQ-16 | OPEN (blocked by another module) |
| G-14 | **`rollout-hardening` built**: the per-type flags `SCAN_ENGINE_SBOM|SCA|SAST|SECRETS` and a tenant allowlist (Zod-validated at start, with security-suite checks for the allowlist as a tenant-isolation control), so that the first production customer rollout can enable one scan type for named tenants only. Decided 2026-11-23 (SPEC 17.ac (3)); the worker-wide switch alone is acceptable only for non-production end-to-end validation | The task itself (a work item with its own spec, plan and checks); then ENG-L12 with the allowlist on and off in a non-production environment | SE-28, OQ-18, ROLLOUT.md section 1, 17.ac (3) | OPEN (deferred task, not built) |
| G-15 | **FIXED 2026-11-25 (verified live)**: per-tool snapshot caps (`SNAPSHOT_ARCHIVE_CAPS_BY_TOOL`, Trivy 4 GiB single file; only the vulnerability-database snapshot, repository archives untouched); the real 1.82 GB `trivy.db` was promoted through the real refresh job including the sandbox canary. Test: `ENG-S12c`. **B1, HIGHEST PRIORITY, blocks real SCA: the real Trivy database is rejected as `archive_hostile`.** `DEFAULT_SNAPSHOT_ARCHIVE_CAPS.maxFileBytes` is 512 MiB (`packages/infra/src/dbmirror/inspect.js`), `trivy.db` is about 1.7 GiB; `refreshTool` passes no caps, so every real Trivy refresh is rejected and the rejected digest is permanent (trigger `guard_scan_db_snapshot` forbids deletes). Real SCA cannot work until fixed. Proposed fix: raise `maxFileBytes` (4 GiB, or a per-tool cap: Trivy 2 GiB, OSV 512 MiB); `maxTotalBytes` 8 GiB and ratio 200 were fine (bundle 143 MB, ratio 12). Design tension: a legitimately large DB can become a permanently rejected digest, so an operator "clear rejected digest" path may be needed (OPEN_DECISIONS, rollout-hardening) | `E2E_RESULT.md` section 6 B1; `inspectSnapshotArchive` on the same file: default caps `archive_hostile`, 4 GiB cap `ok`; then re-run the real refresh and ENG-L09/L19 on real data | E2E B1, SPEC 5.12, OQ-29 | OPEN (HIGHEST) |
| G-16 | **FIXED 2026-11-25 (verified live)**: `SCAN_ENGINES_LOCAL_IMAGES` (development only, refused in production) resolves the own builds from the local container store. Test: `ENG-S02b` (image lock loader). **B2, high: no dev path for the three own-built images.** A `null` digest gives `no_registry_digest` even with `NODE_ENV=development`; only the ENG-L22/L23 scripts patch the lock in memory, although ROLLOUT stage 1 says local own-built images are accepted. Proposed fix: a dev-only mechanism refused when `NODE_ENV=production`, for example `SCAN_ENGINES_LOCAL_IMAGES` (key to `repo@sha256:<local id>`) read where `loadImageLock` is called. G-3 still covers production | `E2E_RESULT.md` section 6 B2 (the lock was patched in a working tree and reverted) | E2E B2, ROLLOUT stage 1, G-3 | OPEN |
| G-17 | **FIXED 2026-11-25 (verified live)**: every lock call connects the Redis client first (`connectedBefore`). Test: the dbrefresh worker wiring check (`workerExtra` of the mirror checks). **B3, high: the dbrefresh Redis lock cannot connect.** `createRedisClient` is `lazyConnect` with `enableOfflineQueue: false`; `buildDbRefreshDeps` never connects it, so `lock.acquirePlatform` throws "Stream isn't writeable" whenever `REDIS_URL` is set (reproduced through the unmodified `buildDbRefreshDeps` and `refreshTool`; the real `dbrefresh` worker was not run). Proposed fix: `await pingRedis(redis)` (or `redis.connect()`) in `buildDbRefreshDeps` before returning | `E2E_RESULT.md` section 6 B3 | E2E B3, SPEC 17.p | OPEN |
| G-18 | **FIXED 2026-11-25 (verified live)**: `createInfrastructure` connects Redis at API startup and `ready()` waits for it (bounded, default 5 s; the API listens only afterwards). On a restart, 30 login requests from the first instant gave connection refused until the API listened and then only 200s, no 500. Test: `BRK-002`. **B4, medium: API login answers 500 until `GET /ready` was called** (same lazy Redis root cause: the rate limiter fails before the readiness probe connects the client). Seen on the dev API (3000) and a fresh API (3100). Proposed fix: connect Redis at API start (`pingRedis` in startup), not only in the readiness probe. Touches the HTTP pipeline, so `pnpm test:security` must pass | `E2E_RESULT.md` section 6 B4 | E2E B4 | OPEN |
| G-19 | **B5, low (visual): T-29 SCA card attribution URLs are clipped at 1440 px** instead of wrapping. Proposed fix: `overflow-wrap: anywhere` on that paragraph | `E2E_RESULT.md` section 6 B5 (screenshot under `/tmp/qm-e2e`, not durable); re-check under G-9 | E2E B5 | OPEN |
| G-20 | **B6, low (to confirm): the masked Secrets preview rewrites `=` as `:`** (`var password = "<value>"` is stored as `var password: [REDACTED]`). Whether this is the intended masking format was not checked against the SPEC. No fix proposed until confirmed | `E2E_RESULT.md` section 6 B6 | E2E B6, SE-43 | OPEN (question) |
| G-21 | **B7 (the owner's B7b), HIGHEST PRIORITY, legal and data hygiene: the quarantine check never ran on real data, and Chainguard `CGA-` ids are in the real OSV data.** Platform inspection records `records 0` for both real snapshots (OSV `all.zip` and `trivy.db` are opaque to it); 966 of 9 989 OSV Go records carry `CGA-` ids in `related` (967 occurrences), which `classifyRecord` allows because it checks the record id only. Proposed fix: extend `classifyRecord` to `related` if the owner wants it, and make inspection count real records; **plus independent legal review (see G-1 and the OQ-26 note: `CGA-` data reached the loaded snapshot, not the stored findings of the E2E run, which contained 0 `CGA-` strings)** | `E2E_RESULT.md` section 6 B7; the read-only dump check is recorded in G-1 | E2E B7, OQ-26, D-15, D-21 | OPEN (HIGHEST) |
| G-22 | **B8, low (operational): two stacks on one broker.** A second set of workers with the flag off steals messages and leaves `engine_not_registered` rows that look like a product defect. The fix is procedural: run the gate on its own broker or stop the dev workers first (add to the ENG-L11 prerequisites) | `E2E_RESULT.md` section 6 B8 | E2E B8 | OPEN |

Informational (not gates): ENG-L13 (Windows/macOS, deferred), ENG-L17 beyond GitHub (GitLab and Bitbucket not wired), ENG-L20 re-run on other architectures, the Part J items listed under "Not verified" (very large files, the real 5 s extractor timeout, Ruby/PHP/C# grammars).

## 5. What to hand back and where it goes

Paste results per item as above. They are recorded in `docs/development/PROGRESS_TRACKER.md` (one entry per phase of section 2) and in the "Status" cells of SPEC 16.2. A gate changes status only when its evidence is pasted and read; this plan is not evidence.

## 6. What is NOT verified (honest list)

Everything in sections 3 and 4 is unrun on the owner's machine. Specifically **UNVERIFIED**: every runtime command written here for L01 to L05, L08, L12, L14, L15 (the author ran none of them; they are standard runtime CLI usage, not repository scripts); rootless Podman and Docker, uid mapping, seccomp, gVisor, Kata, the production scan-runner; other operating systems and architectures; large repositories; the real downloader and real database promotion; the T-29 screen in a real browser; the existence of `MUTATION_BACKLOG.md`.
