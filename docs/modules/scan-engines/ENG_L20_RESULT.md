# ENG-L20 result: real Syft and Trivy output versus the Part E adapters

Status: **RUN 2026-11-20 in the development sandbox (rootful Docker 29.1.3, containerd image store, Linux x86_64, Node 22.22.2), owner authorised.** This file records what the procedure of `ENG_L20_RUNBOOK.md` produced. Section 1 is the comparison BEFORE any adapter change (commit "ENG-L20 real run results"); sections 2 onward are completed by the two commits that follow (reconcile, release of the held items). Not yet verified anywhere: rootless Docker/Podman, another operating system, an ARM host (what remains for the owner's machine is listed in section 6).

## 0. What was run

- Images: the locked digests were already in the local store (pulled by the spike). `capture.js images --check` printed `OK` for both (the containerd store reports RepoDigests, so the identity proof is the RepoDigest equal to the digest of `images.lock.json` and `IMAGES.md`): `anchore/syft@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a` (image id `sha256:e97e20b6e6d1...`), `aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb`. No pull was needed.
- Tools: `syft 1.57.2`, `Trivy Version: 0.76.2`.
- Tree A: the bundled sample tree (11 files). Tree B: a second small tree generated locally with REAL lockfiles (`web/package-lock.json` lockfile v3 from `npm install --package-lock-only` with dependencies, a dev dependency, an optional dependency, a peer dependency and an `npm:` alias; `svc/go.mod` and `svc/go.sum` from `go mod tidy`; `java/pom.xml` with a test-scope dependency; `py/requirements.txt` and `py/poetry.lock`). Both were extracted by the production `extractTarGz` (`prepare --tarball`). No token was used and no network was used by the scans (`--network=none`).
- Runs: 20 sealed or experiment containers on tree A (12 of the runbook plus the experiments added now: `*-nolock` tree without anything to catalog, `*-jar` a tree with one `.jar`, `*-oom` the sealed command with `--memory=8m`, `trivy-vuln-nodb`, `trivy-vuln-skipdb`), 12 on tree B. Containers carry the names `qm-engl20-<tool>-<n>`, were started with `--rm` and none remained afterwards. No other container or image was touched.
- Recorded outputs (small, real, trimmed only by compacting the JSON): `apps/api/test/security/fixtures/scan-engines/sbom/real/{sample,treeB}/*.cdx.json` and `real/facts.json` (exit codes, wall times, stderr).

## 1. Comparison before reconciliation (`compare.js`, exit code 1)

Tree A: `PASS 47, MISMATCH 5, UNKNOWN 9`. Tree B: `PASS 51, MISMATCH 1, UNKNOWN 9`.

```
ENG-L20 comparison: MISMATCH  (PASS 47, MISMATCH 5, UNKNOWN 9)

STATUS   CHECK                   TOOL   ASSUMPTION  =>  OBSERVED
PASS     IMG-syft                syft   the captured image is the locked digest  =>  sha256:e97e20b6e6d1
PASS     VER-syft                syft   the tool reports version 1.57.2  =>  syft 1.57.2
PASS     EXIT-syft               syft   the sealed run exits 0 (adapter acceptedExitCodes = [0])  =>  exit 0, no timeout, output not cut
PASS     TIME-syft               syft   the sealed run finishes inside the 180 s wall clock  =>  2.2 s
UNKNOWN  ERR-syft                syft   the sealed run writes nothing alarming to stderr  =>  1 line(s): read them (redacted head: [0000]  WARN no explicit name and version provided for directory source, deriving artifact ID from …)
PASS     CFG-read-syft           syft   the --config/-c file is actually read (a missing file is an error)  =>  missing config: exit 1
UNKNOWN  CFG-keys-syft           syft   the tool validates keys of the platform config (so the placeholder is parsed)  =>  an unknown key is silently ignored
PASS     FLAG-syft               syft   an unknown flag is rejected (flag spelling in the sealed argv is checked by the tool)  =>  unknown flag: exit 1
PASS     DOC-parse-syft          syft   the sealed stdout is a bounded CycloneDX JSON document  =>  22801 bytes
PASS     DOC-format-syft         syft   bomFormat CycloneDX, specVersion 1.x (the hand-written fixtures use 1.6)  =>  CycloneDX 1.7
PASS     DOC-components-syft     syft   components is a non-empty array  =>  26 components
PASS     DOC-types-syft          syft   packages are library, framework or application with a purl; nothing else carries a purl  =>  types: {"file":7,"library":18,"operating-system":1}
PASS     DOC-purl-syft           syft   every package component has a parseable purl  =>  18 package components, all with a purl
PASS     DOC-bomref-syft         syft   bom-ref is unique and (Trivy) present on every library  =>  unique
UNKNOWN  DOC-scope-syft          syft   scope values are required, optional or excluded  =>  no component carries a scope: the mapping is unexercised, every component is scope unknown
PASS     PATH-src-syft           syft   locations come from syft:location:<n>:path or evidence.occurrences  =>  syft:location=18, evidence.occurrences=0, trivy:FilePath=0, lockfile-graph libraries=0
PASS     PROP-foundby-syft       syft   Syft writes syft:package:foundBy (provenance rule id)  =>  18 components
PASS     PATH-form-syft          syft   paths are relative to the scanned root (optional one leading / or ./)  =>  18 locations: {"leading-slash":18}
PASS     PATH-exists-syft        syft   every normalized path exists in the extracted tree (a part K pathExists filter would keep it)  =>  all paths exist
PASS     PURL-norm-syft          syft   purls parse and the normalization is idempotent  =>  18 purls, 2 changed by normalization, 0 unparseable
PASS     PURL-ver-syft           syft   the component version equals the purl version (the adapter reads the purl)  =>  agree
PASS     ADAPTER-syft            syft   the real adapter accepts the document (runToolParse succeeded, nothing dropped)  =>  17 records from 18 package components
MISMATCH DUP-syft                syft   a tool reports a package once (SE-12 premise); repeats are folded by the adapter  =>  1 repeated purl entry (the adapter folds them; the SE-12 premise is wrong for this tool)  [impact: degraded]
PASS     COUNT-syft              syft   package components produce records  =>  18 package components produce 17 records
PASS     IMG-trivy               trivy  the captured image is the locked digest  =>  sha256:8f6bb947dbc5
PASS     VER-trivy               trivy  the tool reports version 0.76.2  =>  Version: 0.76.2
PASS     EXIT-trivy              trivy  the sealed run exits 0 (adapter acceptedExitCodes = [0])  =>  exit 0, no timeout, output not cut
PASS     TIME-trivy              trivy  the sealed run finishes inside the 300 s wall clock  =>  0.6 s
UNKNOWN  ERR-trivy               trivy  the sealed run writes nothing alarming to stderr  =>  8 line(s): read them (redacted head: 2026-11-20T17:08:17Z INFO Loaded file_path="/rules/trivy.yaml" | 2026-11-20T17:08:17Z INFO [license] License scanning is enabled | 2026-11-20T17:08:17Z WARN [pip] Unable
PASS     DB-trivy                trivy  Trivy SBOM mode (--scanners license) needs no vulnerability database offline  =>  sealed run succeeded with --network=none and no DB
PASS     CFG-read-trivy          trivy  the --config/-c file is actually read (a missing file is an error)  =>  missing config: exit 1
UNKNOWN  CFG-keys-trivy          trivy  the tool validates keys of the platform config (so the placeholder is parsed)  =>  an unknown key is silently ignored
PASS     FLAG-trivy              trivy  an unknown flag is rejected (flag spelling in the sealed argv is checked by the tool)  =>  unknown flag: exit 1
PASS     DOC-parse-trivy         trivy  the sealed stdout is a bounded CycloneDX JSON document  =>  13893 bytes
PASS     DOC-format-trivy        trivy  bomFormat CycloneDX, specVersion 1.x (the hand-written fixtures use 1.6)  =>  CycloneDX 1.7
PASS     DOC-components-trivy    trivy  components is a non-empty array  =>  23 components
PASS     DOC-types-trivy         trivy  packages are library, framework or application with a purl; nothing else carries a purl  =>  types: {"application":5,"library":17,"operating-system":1}
MISMATCH DOC-purl-trivy          trivy  every package component has a parseable purl  =>  3 without a purl, 0 unparseable (dropped by the adapter)  [impact: degraded]
PASS     DOC-bomref-trivy        trivy  bom-ref is unique and (Trivy) present on every library  =>  unique
UNKNOWN  DOC-scope-trivy         trivy  scope values are required, optional or excluded  =>  no component carries a scope: the mapping is unexercised, every component is scope unknown
PASS     PATH-src-trivy          trivy  locations come from aquasecurity:trivy:FilePath or the lockfile application graph  =>  syft:location=0, evidence.occurrences=0, trivy:FilePath=0, lockfile-graph libraries=11
PASS     PROP-foundby-trivy      trivy  Syft writes syft:package:foundBy (provenance rule id)  =>  not applicable to Trivy
MISMATCH PATH-graph-trivy        trivy  lockfile application components list their libraries in dependencies[].dependsOn  =>  11 of 17 libraries obtain a path (11 lockfile applications)  [impact: degraded]
PASS     PATH-form-trivy         trivy  paths are relative to the scanned root (optional one leading / or ./)  =>  11 locations: {"bare-relative":11}
PASS     PATH-exists-trivy       trivy  every normalized path exists in the extracted tree (a part K pathExists filter would keep it)  =>  all paths exist
PASS     PURL-norm-trivy         trivy  purls parse and the normalization is idempotent  =>  14 purls, 1 changed by normalization, 0 unparseable
PASS     PURL-ver-trivy          trivy  the component version equals the purl version (the adapter reads the purl)  =>  agree
MISMATCH ADAPTER-trivy           trivy  the real adapter accepts the document (runToolParse succeeded, nothing dropped)  =>  status partial, reason output_invalid, 3 dropped of 16  [impact: degraded]
MISMATCH DUP-trivy               trivy  a tool reports a package once (SE-12 premise); repeats are folded by the adapter  =>  1 repeated purl entry (the adapter folds them; the SE-12 premise is wrong for this tool)  [impact: degraded]
PASS     COUNT-trivy             trivy  package components produce records  =>  17 package components produce 13 records
PASS     CFG-repo-syft           syft   planted repository configuration (.syft.yaml, trivy.yaml, .trivyignore) does not change the result  =>  18 purls in both runs
PASS     CFG-repo-trivy          trivy  planted repository configuration (.syft.yaml, trivy.yaml, .trivyignore) does not change the result  =>  14 purls in both runs
PASS     PURL-cross              both   both tools normalize the same package to the same canonical purl  =>  12 shared packages, all agree after normalization
PASS     OQ5-pypi                both   OQ-5 PyPI: case, '_' and '.' map to '-' so the tools agree  =>  5 package(s) agree after normalization (4 already identical raw: the rule is doing work)
PASS     OQ5-golang              both   OQ-5 Go: lower-casing the module path and keeping the v prefix make the tools agree  =>  2 package(s) agree after normalization (1 already identical raw: the rule is doing work)
PASS     OQ5-npm                 both   OQ-5 npm: scope and name lower case, %40 for @  =>  3 package(s) agree after normalization (3 already identical raw: the rule is not needed for this data)
PASS     OQ5-maven               both   OQ-5 Maven: group/artifact case kept  =>  2 package(s) agree after normalization (2 already identical raw: the rule is not needed for this data)
UNKNOWN  OQ5-deb                 both   OQ-5 deb: vendor namespace and distro qualifier agree  =>  no such package seen in both tools
UNKNOWN  OQ5-rpm                 both   OQ-5 rpm: vendor namespace and distro qualifier agree  =>  no such package seen in both tools
UNKNOWN  OQ5-apk                 both   OQ-5 apk: vendor namespace and distro qualifier agree  =>  no such package seen in both tools
PASS     ENS-merge               both   two tools agreeing merge into one finding with two provenance entries  =>  18 findings, 12 confirmed by both tools, 6 by one

purl normalization (changed purls only, 3 row(s)):
  syft  pkg:golang/github.com/BurntSushi/toml@v1.3.2  ->  pkg:golang/github.com/burntsushi/toml@v1.3.2  [golang-lowercased]
  syft  pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl  ->  pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12  [qualifiers-dropped]
  trivy pkg:pypi/zope.interface@5.5.2  ->  pkg:pypi/zope-interface@5.5.2  [pypi-name-normalized]
```

Tree B, every line that is not PASS:

```
ENG-L20 comparison: MISMATCH  (PASS 51, MISMATCH 1, UNKNOWN 9)

STATUS   CHECK                   TOOL   ASSUMPTION  =>  OBSERVED
UNKNOWN  ERR-syft                syft   the sealed run writes nothing alarming to stderr  =>  1 line(s): read them (redacted head: [0000]  WARN no explicit name and version provided for directory source, deriving artifact ID from …)
UNKNOWN  CFG-keys-syft           syft   the tool validates keys of the platform config (so the placeholder is parsed)  =>  an unknown key is silently ignored
UNKNOWN  DOC-scope-syft          syft   scope values are required, optional or excluded  =>  no component carries a scope: the mapping is unexercised, every component is scope unknown
UNKNOWN  ERR-trivy               trivy  the sealed run writes nothing alarming to stderr  =>  6 line(s): read them (redacted head: 2026-11-20T17:06:57Z INFO Loaded file_path="/rules/trivy.yaml" | 2026-11-20T17:06:57Z INFO [license] License scanning is enabled | 2026-11-20T17:06:57Z INFO [npm] Run "n
UNKNOWN  CFG-keys-trivy          trivy  the tool validates keys of the platform config (so the placeholder is parsed)  =>  an unknown key is silently ignored
UNKNOWN  DOC-scope-trivy         trivy  scope values are required, optional or excluded  =>  no component carries a scope: the mapping is unexercised, every component is scope unknown
MISMATCH PATH-graph-trivy        trivy  lockfile application components list their libraries in dependencies[].dependsOn  =>  14 of 22 libraries obtain a path (14 lockfile applications)  [impact: degraded]
UNKNOWN  OQ5-deb                 both   OQ-5 deb: vendor namespace and distro qualifier agree  =>  no such package seen in both tools
UNKNOWN  OQ5-rpm                 both   OQ-5 rpm: vendor namespace and distro qualifier agree  =>  no such package seen in both tools
UNKNOWN  OQ5-apk                 both   OQ-5 apk: vendor namespace and distro qualifier agree  =>  no such package seen in both tools

purl normalization (changed purls only, 3 row(s)):
  syft  pkg:golang/github.com/BurntSushi/toml@v1.6.0  ->  pkg:golang/github.com/burntsushi/toml@v1.6.0  [golang-lowercased]
  syft  pkg:golang/github.com/Masterminds/semver/v3@v3.5.0  ->  pkg:golang/github.com/masterminds/semver/v3@v3.5.0  [golang-lowercased]
  trivy pkg:pypi/zope.interface@6.0  ->  pkg:pypi/zope-interface@6.0  [pypi-name-normalized]
```

## 2. Measured facts

| Fact | Syft 1.57.2 | Trivy 0.76.2 (`fs --scanners license`) |
|---|---|---|
| Sealed run, tree A / B | exit 0, 2.1 s / 2.1 s | exit 0, 0.5 s / 0.5 s |
| CycloneDX | `bomFormat` CycloneDX, `specVersion` **1.7** (hand-written fixtures said 1.6) | `specVersion` **1.7** |
| Config file | `-c /rules/syft.yaml` read (missing file: exit 1, `invalid application config: file does not exist`); an unknown key is silently ignored (exit 0) | `--config /rules/trivy.yaml` read (missing file: exit 1, `FATAL ... config file ... loading error`); an unknown key is silently ignored (exit 0) |
| Repository configuration (`.syft.yaml`, `trivy.yaml`, `.trivyignore` planted) | not read, output identical | not read, output identical |
| Unknown flag | exit 1 | exit 1, prints the usage on stdout |
| Memory limit 8 MiB (`--memory=8m`) | **exit 137**, no stdout, no stderr | **exit 137**, no stdout, no stderr |
| Tree with nothing to catalog | exit 0, document with NO `components` key | exit 0, `"components": []` plus the root in `dependencies` |
| Tree with one `.jar` (`pom.properties`) | catalogs it: `pkg:maven/invalid.example/demo@1.2.3`, `java-archive-cataloger`, location `/lib/demo.jar` | licence mode finds nothing, no database request, exit 0 |
| Network or database in SBOM mode | none | **none**: `--scanners license` ran with `--network=none`, no `/db`, empty `TRIVY_CACHE_DIR=/tmp/c`, also with a `.jar` in the tree |
| Vulnerability mode without a database (`--scanners vuln`) | n/a | exit 1 after 4.7 s: `[vulndb] Need to update DB`, `Downloading vulnerability DB...`, then `FATAL Fatal error run error: init error: DB error: failed to download vulnerability DB: ... failed to download artifact from mirror.gcr.io/aquasec/trivy-db:2 ... network is unreachable` |
| `--skip-db-update` on an empty cache | n/a | exit 1 after 0.6 s: `[vulndb] The first run cannot skip downloading DB` / `DB error: database error: --skip-db-update cannot be specified on the first run` |

## 3. What the real output showed (differences from the adapters' assumptions)

1. **Specification version 1.7** (accepted by the `1.x` rule; the hand-written fixtures said 1.6).
2. **Syft path form: a leading slash** (`/package-lock.json`, `/py/requirements.txt`), always in `syft:location:0:path`. `evidence.occurrences` is never written. **Trivy path form: bare relative** (`package-lock.json`, `web/package-lock.json`) and only as the NAME of the lockfile `application` component; the property `aquasecurity:trivy:FilePath` never appears for these package types.
3. **Trivy lockfile graph is deeper than assumed.** The application component lists its direct packages, but for Go and Maven the application lists the ROOT module or project, which in turn lists the dependencies (`go.mod` -> `example.invalid/sample` -> `toml`, `text`; `pom.xml` -> `sample` -> `log4j-core`). The adapter's "direct dependsOn of an application only" gave no path to those packages (`PATH-graph-trivy`).
4. **Trivy purl-less packages.** The operating-system packages (`curl`, `libssl3`, `busybox`) carry NO `purl` (`Detected OS family="none"`, `PkgType none`) even though `etc/os-release` is present in the tree: filesystem mode does not detect the OS. The adapter counted them as invalid records (`status partial`, `output_invalid`). Syft writes `pkg:deb/debian/...` and `pkg:apk/debian/...` purls for the same packages.
5. **A package repeated per lockfile is a real case.** `lodash` is listed once per lockfile by both tools (two components with the same purl and different `bom-ref`), so the SE-12 premise "a tool never reports a component twice" is wrong; the adapter already folds repeats, only the comment and the comparison expectation were wrong.
6. **The root project is a package.** Syft lists the project itself as a library (`pkg:npm/eng-l20-sample@1.0.0`, `pkg:maven/invalid.example/sample@1.0.0`, `pkg:npm/web@1.0.0`), Trivy only for Go and Maven. They are recorded as components (an SBOM contains its own subject); both tools agree for Maven.
7. **Dev dependencies are left out by both tools by default**, Syft silently, Trivy with `Suppressing dependencies for development and testing. To display them, try the '--include-dev-deps' flag.` (the `@types/node` dev entry of tree A is in neither document). Syft's CycloneDX output has no `scope` on any component and neither has Trivy's, so the `scope` mapping (`required`, `optional`, `excluded`) is never exercised by real output of these tools (`DOC-scope` stays unverified).
8. **Purl forms (OQ-5, section 5).** PyPI: Syft already writes the normalized name (`zope-interface`, `pyyaml`, `django`), Trivy keeps the declared spelling in the purl (`zope.interface`, but lower-cased `django`, `pyyaml`, `requests`, `typing-extensions`); Go: Syft keeps the case (`github.com/BurntSushi/toml`), Trivy lower-cases (`github.com/burntsushi/toml`), both keep the `v` prefix; npm: `%40babel/core` in both; Maven in both `pkg:maven/<group>/<artifact>`.
9. **Exit code 137 and an empty output on a memory kill; exit 1 with a text on stderr for every startup error.** Nothing was ever written on stdout in a failing run except the Trivy usage text after an unknown flag.
10. **stderr is informational on success.** Syft: one `WARN no explicit name and version provided for directory source` line. Trivy: `INFO`/`WARN` lines (`Loaded`, `License scanning is enabled`, `[npm] Run "npm install" ...`, `[pip] Unable to find python site-packages directory. License detection is skipped.`, `Detected OS`, `Number of language-specific files`). None indicates a failure.

## 4. Reconciliation (commit "reconcile Syft/Trivy adapters to real output")

Comparison after the changes below, tree A: `PASS 61, MISMATCH 0, UNKNOWN 5`; the five UNKNOWN are the two `scope` checks (no real component carries a scope) and the three OQ-5 rows deb, rpm and apk (Trivy writes no purl for operating-system packages, so there is nothing to compare across the tools).

| What the real output showed | Change |
|---|---|
| Trivy lockfile graph is deeper than direct `dependsOn` (Go root module, Maven project) | `trivyRefPaths` walks each lockfile transitively (never through another lockfile application, a node once, a visit cap of 2,000,000 per document); `PATH-graph-trivy` now PASS (14 of 14 libraries with a purl on tree A) |
| Trivy writes no purl for OS packages in fs mode | a purl-less library of the Trivy adapter is skipped (`purlOptional`), not counted as invalid: the 3 dropped records and the `partial` / `output_invalid` status are gone. Syft keeps the strict rule (a purl-less Syft library stays invalid) |
| A package listed once per lockfile | the adapter already folded repeats; the SE-12 wording of the comparison and the adapter comments were corrected (`DUP-*` is an observation) |
| Both tools ignore an unknown key of the platform config; only a missing file is an error | `CFG-keys-*` is an informational PASS; the placeholder files are kept minimal and checked by our own suite |
| The informational stderr of both tools | `ERR-*` is PASS when every line is of the known informational kind (Syft one WARN; Trivy INFO and WARN lines), an ERROR or FATAL line stays UNKNOWN |
| CycloneDX 1.7 | no change (the `1.x` rule accepts it); fixtures supplemented, not replaced (see below) |
| Sealed command lines, flags, config acceptance | **no change**: both ran as written (IMAGES.md section 2 and the adapters agree, `ENG-S03c`) |

Fixtures: the three hand-written documents stay (they are the only inputs that exercise `scope`, `evidence.occurrences` and `aquasecurity:trivy:FilePath`, which real output never wrote, and the hostile and hand-built cases); the real documents under `fixtures/scan-engines/sbom/real/` supplement them and are asserted by the new check `ENG-S15f` (counts, path forms, cross-tool agreement, empty and archive results, the recorded exit codes and failure texts). The comparison tool gained checks for the new experiments (`EXP-oom-*`, `EXP-nolock-*`, `EXP-vulndb-trivy`); they appear only when the capture contains the run.

Differences between the tools that are real and are kept: Syft lists the project roots (`pkg:npm/web@1.0.0`) and test-scope Maven dependencies (`junit`), Trivy omits both and lists the Go root module (`pkg:golang/example.invalid/svc`, no version); both omit npm dev dependencies by default.

## 5. OQ-5 purl rules against real output

VERIFIED = both real tools were compared and the rule is needed or confirmed; UNVERIFIED = no real output exercised the rule.

| Rule | Status | Evidence |
|---|---|---|
| PyPI: lower case, `_` and `.` to `-` | **VERIFIED** | Trivy `pkg:pypi/zope.interface@5.5.2`, Syft `pkg:pypi/zope-interface@5.5.2`; `_` was already normalized by both (`typing-extensions`) |
| Go: lower-case namespace and name | **VERIFIED** | Syft `github.com/BurntSushi/toml`, Trivy `github.com/burntsushi/toml` (the purl specification lowercases; the caveat that Go module paths are case sensitive stays a design risk) |
| Go: the `v` prefix kept | **VERIFIED** | both write `@v1.3.2` |
| npm: scope encoded `%40` | **VERIFIED** | both write `pkg:npm/%40babel/core@7.20.0` |
| npm: name and scope lower case | UNVERIFIED | all captured npm names were already lower case |
| npm and PyPI: a leading `v` stripped | UNVERIFIED | no such version appeared |
| Maven: case kept, `group/artifact` | **VERIFIED** | both `pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1` |
| Maven: qualifiers `type`, `classifier` kept | UNVERIFIED | none emitted |
| deb and apk: vendor namespace and the kept qualifiers `arch`, `distro`; other qualifiers dropped | Syft side **VERIFIED**, cross-tool UNVERIFIED | Syft `pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl` (`upstream` is dropped, `+` in a version is written `%2B`); Trivy writes no purl for these packages in fs mode |
| rpm | UNVERIFIED | no rpm database in the captured trees |
| `package-id` qualifier | not seen in a purl | Syft puts `?package-id=` only in `bom-ref`; the rule that drops every other qualifier is unaffected |

## 6. What remains for the owner's machine

Rootless Docker or Podman (`--userns` mapping, ENG-L18), a second operating system or an ARM host, a repository with rpm, Python virtual-environment and `.jar` content, a real private repository tree (Option B of the runbook needs a token and was not run), Trivy and Syft in newer versions than the locked ones, calibration of limits and timing under load (ENG-L10), cancellation of a real container (ENG-L05).

## 7. Held items of SPEC 17.i after this run (commit "release held part K items confirmed by ENG-L20")

| Held item | Outcome |
|---|---|
| (a) `pathExists` and path-based filtering | **Released.** `createTreePathExists` is installed by the worker wiring; real paths are `/<relative>` (Syft) and `<relative>` (Trivy) and all of them exist in the tree |
| (b) incremental scope narrowing | **Settled for SBOM: whole tree** (SPEC 5.9); `scope.kind` stays `full`. `targets`, `full_filtered`, the SE-24 filter and SE-27 file targets stay held for SAST and secrets (their output was not part of this run) |
| (c) change of the Part E adapters | **Done** (section 4) |
| (d) applicability, `no_applicable_files`, rows 3 and 4 | **Held.** Rows 3 and 4 are still Recommended (OQ-17); a name allowlist would miss what Syft really catalogs (`.jar`, OS databases); the empty-tree result (exit 0, empty document) is reported as `succeeded` / `complete` with no items |
| (d) exit 137 and out-of-memory | **Released.** Real: exit 137, no output (both tools); `classifyToolExit` gives `out_of_memory` |
| (d) real stderr | **Released** for the fixed-word classification (`config_invalid` from the recorded Syft and Trivy texts); stderr is never stored or returned |
| (d) Trivy database behaviour | **Settled for the SBOM role** (no database, no network); the failure texts of the vulnerability mode are recorded in `real/facts.json` for Part G, whose `db_unavailable` mapping stays held with it |

## 8. Include ALL components, run for real on 2026-11-21 (owner decision D-24 (a), reverses section 3 item 7 and 17.n decision 1)

Same sandbox (rootful Docker 29.1.3), same locked images, same production sandbox flags (`capture.js`), containers `qm-engl20-*` removed. Tools: Syft 1.57.2 (`-c /rules/syft.yaml` now with `javascript.include-dev-dependencies: true`), Trivy 0.76.2 (`--include-dev-deps` added to the sealed vector). Tree A is the bundled sample; tree C is new (the earlier tree B was not kept, its documents stay in `real/treeB` as the record of the default behaviour): npm (real lockfile v3 with dev, optional and peer entries, plus hand-written `pnpm-lock.yaml` and `yarn.lock`), a Maven pom with test, provided and optional dependencies, Python (`requirements.txt`, `requirements-dev.txt`, `Pipfile.lock` with a develop section, `poetry.lock` with a dev group and an optional extra; the Pipfile.lock and poetry.lock were written by hand, no Poetry was available) and a Go module with a test-only module.

Verified flags: Syft has NO command-line flag for this; the key is `javascript.include-dev-dependencies` (env form `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES`, also verified); Trivy `--include-dev-deps`. Coverage per ecosystem: `IMAGES.md` section 6.

Counts (distinct canonical-ish purls; a package listed by both tools counts once in the union):

| Tree | Syft before | Trivy before | Union before | Syft after | Trivy after | Union after | Components now present |
|---|---|---|---|---|---|---|---|
| A (sample) | 17 | 13 | 20 | 18 | 14 | 21 | `pkg:npm/%40types/node@18.0.0` (both tools) |
| C | 18 | 12 | 21 | 20 | 18 | 23 | Syft: `@types/node@20.11.0`, `undici-types@5.26.5` (npm dev, package-lock); Trivy additionally `is-odd@3.0.1`, `is-number@6.0.0` (pnpm and yarn dev), `pytest@7.0.0` (poetry dev) and `colorama@0.4.6` (poetry optional extra) |

(The union counts the Go module `BurntSushi/toml` once per spelling; the platform merge lower-cases it: tree C merges to 22 findings, ENG-S15f.) What the tools still do not agree on: Trivy never lists Maven `junit` (test), `javax.servlet-api` (provided) and `guava` (optional) and has no flag for them, and Syft alone lists the project roots; both are kept (D-24 (b)). Neither tool writes a `scope` (checked on every component), so every component is scope `unknown`. `compare.js` on both trees: tree A `PASS 63, MISMATCH 0, UNKNOWN 5` (was 61/0/5, the two new checks `DEV-included-syft` and `DEV-included-trivy` PASS), tree C `PASS 63, MISMATCH 0, UNKNOWN 5`. The remaining UNKNOWN are the two `scope` checks and OQ-5 deb, rpm and apk, as before. Fixtures: `real/sample/*-sealed.cdx.json` replaced by the new documents, `real/treeC/` (after) and `real/treeC/before/` added, `real/facts-dev.json`; `ENG-S15f` asserts the before and after counts.

