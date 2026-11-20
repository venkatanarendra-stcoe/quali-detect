# ENG-L20 runbook: real Syft and Trivy output versus the Part E adapters

Status: **procedure written 2026-11-20; RUN once on 2026-11-20 in the development sandbox (rootful Docker 29.1.3), results in `ENG_L20_RESULT.md`.** The build environment of the original writing had no container runtime; the owner then authorised a run in the sandbox. This document stays the procedure for the owner's own machine (rootless Docker or Podman, other operating systems, an ARM host), which has NOT been run. The goal is to learn whether the SBOM adapters of Part E (`apps/workers/src/execution/engines/ensemble/sbom/*`) agree with what the real tools emit. Items the comparison reports as `UNKNOWN` stay unverified and Part K holds the work listed in SPEC 17.i that depends on them.

What you run: two small Node scripts of the repository (`apps/workers/scripts/eng-l20/capture.js`, `compare.js`). The capture script builds every `docker run` command with the repository's own `buildRunArgs`, so the sandbox flags are the production ones, not a hand-written copy: `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--user=65534:65534`, a `noexec,nosuid,nodev` tmpfs on `/tmp`, `--workdir=/tmp`, `--pull=never`, resource limits, and read-only bind mounts of the tree (`/src`) and of the platform rules (`/rules`) only. The comparison runs offline, reads only the captured files and executes nothing from them.

## 0. Prerequisites

- Linux, Docker (or Podman with `--runtime podman`; rootless Podman and uid mapping are a different gate, ENG-L18, not this one), Node 22.22 or newer, `pnpm install` done in the repository root. Run every command from the repository root.
- A working directory **under `/tmp`**, not under `/home` (the sandbox policy forbids mounting host system and home paths, so a work directory below `/home` is refused on purpose).
- Do not stop or touch your development stack; this procedure starts only short-lived containers named `qm-engl20-*` and removes them (`--rm`). The containers carry the label `qm.scan=1`; if you run a janitor against the same Docker daemon, expect it to ignore them (their deadline label is one hour ahead).

## 1. Pull the two pinned images (the ONLY step that uses the network)

The digests are the ones in `apps/workers/src/execution/engines/ensemble/catalog/images.lock.json` (the same as `IMAGES.md` section 1). Print the commands, run them, then verify:

```sh
node apps/workers/scripts/eng-l20/capture.js images
docker pull anchore/syft@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a
docker pull aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
node apps/workers/scripts/eng-l20/capture.js images --check
```

`images --check` must print `OK` for both (it reads `docker image inspect` RepoDigests). If a line says `UNKNOWN` your image store reports no RepoDigests (the containerd store sometimes does this): check with `docker image inspect anchore/syft@sha256:e97e... --format '{{.Id}} {{.RepoDigests}}'` and write down what you see. `MISSING` means the pull failed. The scan runs with `--pull=never`, so a missing image fails closed. Digests are the identity: do not use tags.

## 2. Prepare the tree (pick ONE option)

The tree is extracted by the same function as production (`extractTarGz`): the top directory GitHub adds is stripped, `.git` is never extracted, directories are `0755`, files `0644`, inside a private `0700` parent. The script makes two copies: `trees/clean` and `trees/planted` (the same files plus the repository configuration files `.syft.yaml`, `trivy.yaml` and `.trivyignore`, used by the "repository configuration is ignored" experiment).

**Option A, the bundled sample tree (no token, no network):**

```sh
W=$(mktemp -u /tmp/eng-l20-work.XXXXXX)
node apps/workers/scripts/eng-l20/capture.js prepare --work "$W" --sample
```

The sample is a tiny inert repository: two npm lockfiles (scoped `@babel/core`, a dev dependency), `requirements.txt` with `Django`, `PyYAML`, `typing_extensions`, `zope.interface`, `Requests` (mixed case, `_` and `.` in names), `go.mod`/`go.sum` with `github.com/BurntSushi/toml v1.3.2` (upper case, `v` prefix), a Maven `pom.xml`, a Debian `var/lib/dpkg/status` with `etc/os-release`, and an Alpine `lib/apk/db/installed`.

**Option B, your repository `STCOE-TESTING/qm-test-2-renamed` (needs your token):**

```sh
T=$(mktemp -d /tmp/eng-l20-dl.XXXXXX)
read -rs GH_TOKEN   # paste the token, press Enter; it stays in this shell only
curl -sSL -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
  -o "$T/repo.tar.gz" https://api.github.com/repos/STCOE-TESTING/qm-test-2-renamed/tarball/main
unset GH_TOKEN
W=$(mktemp -u /tmp/eng-l20-work.XXXXXX)
node apps/workers/scripts/eng-l20/capture.js prepare --work "$W" --tarball "$T/repo.tar.gz"
```

Replace `main` with the default branch or a commit SHA. The scripts never read, print or store the token; the token is only in the `curl` line. Use the sample tree (Option A) first: it is the one that exercises every purl family on purpose. Run Option B as a second capture into another output directory.

## 3. Inspect the commands, then run

```sh
node apps/workers/scripts/eng-l20/capture.js run --work "$W" --dry-run     # prints every docker command, runs nothing
OUT=$(mktemp -u /tmp/eng-l20-out.XXXXXX)
node apps/workers/scripts/eng-l20/capture.js run --work "$W" --out "$OUT"
```

`run` executes these containers one after the other (each prints `exit <code> in <ms> ms`). The sealed command lines are the spike's (`IMAGES.md` section 2) and the adapters' constants, verbatim: Syft `-c /rules/syft.yaml dir:/src -o cyclonedx-json` with `SYFT_CHECK_FOR_APP_UPDATE=false`; Trivy `fs --config /rules/trivy.yaml --scanners license --format cyclonedx /src` with `TRIVY_SKIP_VERSION_CHECK=true TRIVY_DISABLE_TELEMETRY=true TRIVY_CACHE_DIR=/tmp/c`; both with the working directory `/tmp`, `HOME=/tmp`.

| Run id | What it is | What the comparison expects |
|---|---|---|
| `syft-version`, `trivy-version` | `--version` of each tool | the locked versions 1.57.2 and 0.76.2 |
| `syft-sealed`, `trivy-sealed` | the sealed scan of `trees/clean` with the platform rules `rules/syft.yaml`, `rules/trivy.yaml` | exit 0, a CycloneDX 1.x document on stdout, well inside the wall clock (180 s Syft, 300 s Trivy) |
| `syft-planted`, `trivy-planted` | the same sealed command on `trees/planted` (repository `.syft.yaml`, `trivy.yaml`, `.trivyignore` that try to exclude everything) | the same packages as the clean run: repository configuration must not be read |
| `syft-config-missing`, `trivy-config-missing` | the same command with `-c`/`--config` pointing at `/rules/missing.yaml` | a non-zero exit: proves the config option is really read, so "the placeholder was accepted" means something |
| `syft-config-unknown-key`, `trivy-config-unknown-key` | the platform rules directory replaced by `rules-bad` (an unknown key `qm-no-such-key`) | informational: a non-zero exit shows the tool validates the file; a zero exit shows unknown keys are ignored |
| `syft-unknown-flag`, `trivy-unknown-flag` | the sealed vector plus `--qm-no-such-flag` | a non-zero exit: a misspelt flag in our argument vectors would be caught by the tool |
| `syft-nolock`, `trivy-nolock` | the sealed command on `trees/nolock` (a README and a text file, nothing to catalog) | informational (added 2026-11-20): exit 0 and a document without packages (Syft omits `components`, Trivy writes an empty list) |
| `syft-jar`, `trivy-jar` | the sealed command on `trees/jar` (one `.jar` with Maven metadata) | informational: Syft catalogs the archive, Trivy in licence mode does not and needs no Java database |
| `syft-oom`, `trivy-oom` | the sealed command with `--memory=8m` (the limits are the only change) | informational: the exit code of a memory kill (137) and an empty output |
| `trivy-vuln-nodb`, `trivy-vuln-skipdb` | `--scanners vuln` instead of `license`, without a database (and with `--skip-db-update --skip-java-db-update`) | informational: the exact failure text of Trivy's vulnerability mode without a database (exit 1), recorded for Part G |
| `trivy-fallback-skipdb`, `trivy-fallback-offline` | only if `trivy-sealed` failed: the same command with `--skip-db-update --skip-java-db-update` (and `--offline-scan`) | evidence for the database question below |

### Trivy and its database

IMAGES.md section 2 records that Trivy in SBOM mode (`--scanners license`) needs no vulnerability database, so the sealed run uses `--network=none` and no `/db` mount. If Trivy nevertheless tries to download a database or the Java index (typical text: "failed to download", "db", "java-db", "unable to initialize"), `trivy-sealed` exits non-zero, the stderr is saved as evidence in `$OUT/trivy-sealed.stderr`, and the script automatically runs the two fallbacks above. Report which one worked; do **not** add a network or a database mount to make it pass. If the sealed run needs the Java DB because the tree contains `.jar` or `.war` files, say so (the sample tree has none). Whatever happens, the evidence is the saved stderr and exit code, nothing is hidden.

## 4. Compare (offline, no Docker, no network)

```sh
node apps/workers/scripts/eng-l20/compare.js "$OUT" --tree "$W/trees/clean" --json /tmp/eng-l20-report.json
```

The table prints one line per assumption with `PASS`, `MISMATCH` (with the impact: `degraded` = the adapter copes but loses information, `breaks` = it would not work) or `UNKNOWN` (the capture cannot decide it), then the purl normalization table (raw purl, canonical purl, which rule changed it). Exit code 0 means no `MISMATCH`, 1 at least one, 2 unusable input. It only reads files in `$OUT` (regular files, no symbolic links, size caps), writes nothing there, and redacts credential-shaped text; the `--json` file must lie outside `$OUT`. `--tree` lets it check that each reported path exists in the tree (a part K `pathExists` filter would drop a record whose path does not).

It checks: image digests against the lock file; the reported tool versions; exit codes, wall time and stderr of the sealed runs; whether Trivy needed a database; the config-acceptance experiments (config read, unknown key, unknown flag, planted repository configuration changes nothing); per tool the CycloneDX `bomFormat` and `specVersion`, component types, `bom-ref` uniqueness, `scope` values, the property names the adapters read (`syft:location:<n>:path`, `syft:package:foundBy`, `evidence.occurrences[].location`, `aquasecurity:trivy:FilePath`), Trivy's lockfile `application` components and `dependencies` graph, path forms (leading slash, `./`, bare relative, a leaked `/src/` prefix), purl parsing, version agreement and normalization (run through the real normalizer, before and after), component counts and duplicates, the real adapters' verdict on the document, and across the two tools the OQ-5 list (PyPI `.`/`_`, Go lower-casing and the `v` prefix, npm scope, Maven, deb/rpm/apk namespace and `distro` qualifier) plus the cross-tool merge.

## 5. Send back

1. The JSON report `/tmp/eng-l20-report.json` and the table text.
2. `$OUT/manifest.json` (exit codes, wall times, the full docker arguments, image digests; it contains local paths but no secrets) and, for any `MISMATCH` or `UNKNOWN` you want explained, the matching `$OUT/<run id>.stderr`.
3. If you are willing, `$OUT/syft-sealed.stdout` and `$OUT/trivy-sealed.stdout` of the sample tree (they describe an inert public sample, nothing private); these become the recorded fixtures that replace the hand-written ones.
4. Which option you used (A or B) and anything surprising.

## 6. Clean up

```sh
rm -rf "$W" "$OUT" "$T" /tmp/eng-l20-report.json     # $T only if you used option B
```

Containers are removed by `--rm`. Nothing else was written outside `/tmp`.

## 7. What the answers decide (SPEC 17.i)

A clean report (no `MISMATCH`, the `UNKNOWN` items explained) releases the held part K items: the `pathExists` tree filter, the incremental scope narrowing that depends on tool path forms and any change to the Part E adapters. A `MISMATCH` goes to the adapters first (fix, then replace the hand-written fixtures with the recorded output), never to the comparison. The comparison script is itself covered by the Docker-free checks `ENG-S15a` to `ENG-S15e`, which run it against the hand-written fixtures and against a deliberately mismatched capture.
