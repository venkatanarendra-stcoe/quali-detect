# ENG-L22 runbook: the real SAST run, performance on a large repository and rule pack quality

Status: **written 2026-11-21 (Part H).** The SAST command lines, output shapes, failure behaviour and the configuration-planting results were verified for real in the development sandbox on 2026-11-21 (`IMAGES.md` section 8). What remains for the owner's machine: the production-shaped run, large repositories, and the review of the rule pack. Nothing here is automated by the security suite (it is Docker-free by design).

## 1. The images

- Bandit: `ghcr.io/pycqa/bandit/bandit@sha256:b405a808f5d50156aee921a77fb17c044d69d90ecef6499447a037678967c936` (in the lock file, resolvable).
- Opengrep is OWN-BUILT (SPEC D-14) and has NO registry digest in the lock file yet, so the engine reports it `unavailable` / `image_unavailable` and the SAST task is degraded and incomplete until the image is pushed to the mirror registry and its digest recorded (`IMAGE_CATALOG.md`). For a development run the script accepts the locally built image by its digest reference (the containerd image store accepts `repo@sha256:<image id>`): `--opengrep-local qm-spike-opengrep@sha256:20b0e7d34daebcbab52bbf3255407f923e2d8ecd3b9211c44cf47e596a511754`. This option exists in the script only, never in the worker.

## 2. ENG-L22 (a): the sealed SAST run, planted configuration and explicit targets

```sh
W=/tmp/qm-engl22; mkdir -p $W && chmod 755 $W
cp -r apps/api/test/security/fixtures/scan-engines/sast/tree $W/tree && chmod -R a+rX $W
node apps/workers/scripts/eng-l22/run-sast.js --work $W --tree $W/tree --opengrep-local qm-spike-opengrep@sha256:<local image id>
```

Expected on the fixture tree (Opengrep 2.0.0, Bandit 1.9.4, 2026-11-21): Opengrep 26 findings, Bandit 13, 33 merged findings of which 6 carry both tools, roll-up row 5 complete; the PLANTED run (`.semgrepignore`, `.gitignore`, `.semgrep.yml`, `.opengrep/`, `.bandit`, `setup.cfg`, `pyproject.toml`, `nosemgrep` and `nosec` comments on every line) gives exactly the same findings; the explicit-targets run gives the findings of those files only. Every line `PASS`, exit 0. Run it on YOUR repositories too (copy a tree under `/tmp`): the planted run must still equal the clean run.

## 3. ENG-L22 (b): performance and limits on a large repository

Measure per tool (wall clock, peak memory with `docker stats` or `/usr/bin/time -v` around the script, stdout size): a small (hundreds of files), a medium (10 000 files) and a large (100 000 files, with a committed `node_modules` or `vendor` directory) repository. Record against SPEC 5.8: Opengrep 2 CPU, 3 GiB, 600 s, 64 MiB stdout; Bandit 1 CPU, 1 GiB, 240 s, **32 MiB stdout**. Points to settle:

- **Vendored directories are scanned** (no default exclusion once the ignore files are disabled, verified). Decide whether the platform adds `--exclude` for `node_modules` and `vendor`, or relies on the pipeline's `exclusions.paths`.
- **Bandit's JSON lists every scanned file in `metrics`**: a very large Python tree can exceed the 32 MiB cap (the tool is then `failed` / `output_too_large`). Measure the output size per 10 000 Python files and raise the cap if needed.
- Minified files (`*.min.js`) are skipped by Opengrep and files over 1 MB (`--max-target-bytes`) are skipped silently: both are coverage the result does not report.
- Time the tree walk of the engine (language detection) on the large tree; it is bounded (1 000 000 entries, 200 000 paths) and yields to the event loop.
- Whether the number of files the tools could not process (`errors[]`: a syntax error, a rule timeout) is acceptable: **any such file makes the tool run `partial` and the result incomplete** (never resolution eligible). If real repositories hit this constantly, decide whether to count only timeouts and out-of-memory.

## 4. ENG-L22 (c): rule pack quality (the security team)

The pack under `apps/workers/src/execution/engines/ensemble/sbom/rules/qm-sast/` (three files, 23 rules) is a SMALL starter set written for this platform (SPEC D-16, OQ-25). The security team reviews it: false positives on real code (the pack has not been run on a real code base beyond the fixture tree and a small sample), false negatives (only intra-file patterns and intra-file taint; no cross-file flow), severity and CWE assignments, and the licence statement in the header of every file (platform-owned, original; the licence question is recorded for review in `OPEN_DECISIONS.md`). The comprehensive pack, leveraging QualiSec rules where the licence is compatible, stays an ongoing security-team deliverable.

## 5. Not covered here

gosec (HELD, SPEC phase 4b), tree-sitter evidence (Part J), rootless runtimes (ENG-L18), the registry digest of the own-built Opengrep image (owner pre-production task).
