# ENG-L09, ENG-L19 and ENG-L21 runbook: the real vulnerability databases and the real SCA run

Status: **written 2026-11-21 (Part G).** The SCA command lines, the output shapes and the failure texts were verified for real in the development sandbox on 2026-11-21 (`IMAGES.md` section 7, `ENG_L20_RESULT.md` section 9); what remains for the owner's machine is the production-shaped procedure below: the refresh job with a real downloader, the real mirror, the sealed run from the mirror's cache directory and the data-licence check. Nothing here is automated by the security suite (it is Docker-free by design).

## 0. What database to mirror and what the tools read under `/db`

| Tool | Source (the ONLY network use) | Bundle layout the tool reads at `/db` (one directory per snapshot, mounted read-only) | Size seen on 2026-11-21 |
|---|---|---|---|
| Trivy | `trivy image --cache-dir <dir> --download-db-only` (pulls `mirror.gcr.io/aquasec/trivy-db:2`; add `--db-repository` only if the owner chooses another mirror) | `db/trivy.db` and `db/metadata.json` (`Version 2`, `UpdatedAt`, `NextUpdate`); `TRIVY_CACHE_DIR=/db`. The Java index database is NOT needed (`--skip-java-db-update`; `pom.xml` lockfiles work without it) | 136 MiB download, 1.7 GiB unpacked |
| OSV-Scanner | `osv-scanner scan source --offline-vulnerabilities --download-offline-databases -r <tree>` with `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<dir>` (archives of `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`) | `osv-scalibr/npm/all.zip`, `osv-scalibr/PyPI/all.zip`, `osv-scalibr/Go/all.zip`, `osv-scalibr/Maven/all.zip` (ALL FOUR must exist: a missing or corrupt archive is exit 127 and the tool is `unavailable` / `db_unavailable`) | 222 MB, 38 MB, 13 MB, 10.5 MB |

The upstream build time that decides the staleness tier (SE-38) is the Trivy `UpdatedAt` (and, for OSV, the newest `modified` of the archive: the real downloader of Part F must derive it; **open until the real downloader exists, OQ-29 covers the integrity anchor**). The mirror bundle is a tar.gz with ONE top directory whose content is the layout above (`DbMirrorStore` materializes it into `<SCAN_DB_CACHE_ROOT>/<tool>/<sha256>/`, mode 0555/0444, and the scan path mounts that directory at `/db`).

## 1. ENG-L21: the sealed SCA run against real data

```sh
W=/tmp/qm-engl21; mkdir -p $W && chmod 755 $W
# 1. the databases (network only here; separate containers that mount no repository content)
mkdir -p $W/trivy-db $W/osv-db && chmod 777 $W/trivy-db $W/osv-db
docker run --rm --user $(id -u):$(id -g) -e HOME=/tmp -v $W/trivy-db:/db aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb image --cache-dir /db --download-db-only
docker run --rm --user $(id -u):$(id -g) -e HOME=/tmp -e OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db -v $W/osv-db:/db -v <some-tree>:/src:ro ghcr.io/google/osv-scanner@sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde scan source --offline-vulnerabilities --download-offline-databases -r /src --format json > /dev/null
# 2. a tree, extracted like production (see ENG_L20_RUNBOOK.md section 2): prepare --work $W --sample, or your own tarball; the tree is $W/trees/clean
node apps/workers/scripts/eng-l20/capture.js prepare --work $W --sample
# 3. the live run (the images are the locked digests; --pull=never)
node apps/workers/scripts/eng-l21/run-sca.js --work $W --tree $W/trees/clean --trivy-db $W/trivy-db --osv-db $W/osv-db
```

Expected: both tools `succeeded`, nothing dropped, the roll-up row 5 (`complete`), the two tools agreeing on most findings, and the planted-configuration run (a hostile `.trivyignore`, `trivy.yaml` and `osv-scanner.toml`) giving exactly the findings of the clean run (`PASS` for every line, exit 0). The counts depend on the day's data; on 2026-11-21 the ENG-L20 sample tree gave 58 findings per tool. Record the output in the tracker.

## 2. ENG-L09: the mirror, the refresh job and the sealed scan from the mirror

1. Build the two bundles of section 0 into the mirror with the real downloader (**not built yet; Part F ships a fake downloader**), or hand-build a bundle: `tar czf trivy.tar.gz trivy/` where `trivy/db/trivy.db` and `trivy/db/metadata.json` exist, and `osv.tar.gz` holding `osv/osv-scalibr/<eco>/all.zip`; promote them through the repository functions as the Part F checks do. Set `SCAN_DB_MIRROR_ROOT`, `SCAN_DB_CACHE_ROOT` and `SANDBOX_RULES_DIR` (the canary scan reads `canary.cdx.json` and `osv-scanner.toml` from it) for the dbrefresh worker, and `SCAN_ENGINES_ENSEMBLE_ENABLED=true` plus the same two DB roots for the scan worker.
2. The canary command lines of the promotion gate (SE-35) are the verified ones of `IMAGES.md` section 7 (a platform file at `/rules/canary.cdx.json`): confirm a candidate with the real database is promoted, a candidate whose archive is corrupted is rejected (`canary_failed` or `integrity_*`), and that the canary expects `CVE-2021-23337` / `GHSA-35jh-r3h4-6jhm` for lodash 4.17.20.
3. Run an SCA scan with the host network disabled (`--network=none` is in the sealed flags; additionally disconnect the machine): the result must show the snapshot sha and build date on both tools (T-29 "DB" column), a fresh snapshot gives a complete result, a snapshot older than 3, 14 and 30 days (change `upstreamBuiltAt` of the active row or wait) gives `partial` / `db_stale`, an incomplete result and a succeeded execution, an empty cache gives `unavailable` / `db_unavailable` and a failed task with the transient class that is retried within the budget, and **no container is started without a snapshot**.
4. The attribution text of `ADVISORY_ATTRIBUTION` is shown on T-29 whenever a tool run has database provenance (check on the real screen; SE-47, still subject to the legal gate OQ-26).

## 3. ENG-L19: is the data clean?

- Unpack the four OSV archives and grep every record for the quarantine markers (`chainguard`, `wolfi`, `cgr.dev`, `CGA-`, a non-commercial `license`): `classifyRecord` of Part F does this per record (`inspectSnapshotArchive`); run it over the real bundle and expect no quarantined record (record the counts, one rejection quarantines the whole snapshot, 17.p).
- **Trivy database (open, flagged by Part G):** the file is an opaque bbolt database; the record-level check cannot see inside it. Its language-ecosystem findings carry `SeveritySource` `ghsa` (or none for Go), but the SAME file holds the ratings of distribution vendors for the same CVEs (`redhat`, `ubuntu`, `azure`, `bitnami`, `ruby-advisory-db` in `VendorSeverity` and `CVSS`). The platform never reads them (the mapper keeps only Trivy's own `Severity` and the `ghsa` and `nvd` CVSS entries; `ENG-S06j` proves no vendor rating reaches a finding), but they ARE in the file the platform mirrors and mounts: a lawyer must decide whether mirroring that file is acceptable (OQ-26) or whether the v2 own-built database (D-24) is required first. Confirm also that no `os-pkgs` result can appear: `--pkg-types library` is in the sealed vector and the adapter drops any result of another class.
