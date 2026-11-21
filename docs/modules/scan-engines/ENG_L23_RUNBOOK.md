# ENG-L23 runbook: the real Secrets run, performance on a large repository and the coverage gap

Status: **written 2026-11-21 (Part I).** The command lines, output shapes, failure behaviour and the configuration-planting results were verified for real in the development sandbox on 2026-11-21 (`IMAGES.md` section 9). Nothing here is automated by the security suite (it is Docker-free by design).

## 1. Images

Gitleaks: the lock digest (resolvable). detect-secrets is OWN-BUILT and has no registry digest in the lock yet (the engine reports it `unavailable` / `image_unavailable`, the task degraded, until the mirror digest is recorded). For a development run the script takes `--detect-secrets-local qm-spike-detect-secrets@sha256:<local image id>`; this exists in the script only.

## 2. ENG-L23 (a): the sealed run

```sh
W=/tmp/qm-engl23
node apps/workers/scripts/eng-l23/run-secrets.js --work $W --detect-secrets-local qm-spike-detect-secrets@sha256:<local image id>
```

Expected (Gitleaks 8.30.1, detect-secrets 1.5.0): Gitleaks 9, detect-secrets 15, merged 15 (9 with both tools), roll-up row 5 complete; the planted run (allow-all config, ignore file, baseline, ...) with the extraction deny list applied equals the clean run; WITHOUT the list Gitleaks finds nothing (informational); the incremental run gives the findings of the changed files; the canary line reports no fake value. Every line `PASS`, exit 0. Never put real secrets in the tree the script builds.

## 3. ENG-L23 (b): performance and limits

Measure per tool (wall clock, peak memory, stdout size) on a small, a medium (10 000 files) and a large (100 000 files, with a committed `node_modules` or `vendor`) repository, against SPEC 5.8 (1 CPU, 1 GiB, 300 s, 32 MiB each). Settle: the cost of scanning vendored directories (decided: scanned); decode depth (`--max-decode-depth`, default 5) on a base64-heavy tree; the 5 MB per-file cap; whether Gitleaks needs more than 1 GiB.

## 4. ENG-L23 (c): the Gitleaks default-allowlist gap (owner)

The default configuration of Gitleaks skips `node_modules`, lock files, `go.sum` and images; detect-secrets covers `node_modules`. Decide whether to keep an own copy of the default rule file without that allowlist (MIT; a platform-owned `/rules/gitleaks.toml` with no `useDefault`), which closes the gap at the cost of maintaining the rules.
