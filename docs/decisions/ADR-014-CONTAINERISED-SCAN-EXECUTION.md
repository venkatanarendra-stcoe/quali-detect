# ADR-014: Containerised scan execution (pinned OCI tool images in a locked-down sandbox)

- **Status:** **Accepted (2026-11-19, owner decision).** Runtime decision: all runtime access goes through a `SandboxRuntime` interface; development adapter = rootless Podman (preferred) or rootless Docker; production = a dedicated scan-runner service (options B for development and C for production, gVisor/Kata noted as hardening, option D); the privileged Docker socket (equivalent to root) is NEVER mounted into the worker. The documentation amendments of section 5 are applied. Nothing is implemented; tools are adopted only after the Part A spike (SPEC 17.a).
- **Date:** 2026-11-19
- **Decision owners:** Product owner (decision); Claude Code (proposal)
- **Relation to existing documents:** reverses, **for the scan execution layer only**, the line "Out of scope now: Docker, Docker Compose, Kubernetes, deployment/CI config" in `CLAUDE.md` (also `AGENTS.md` line 27, `docs/README.md` line 33, `docs/ai-development/AGENT_INSTRUCTIONS.md` line 101). Fulfils Executions SPEC §17.ab ("External-tool engines ... are a separate future module with its own sandbox ADR") and replaces the "logical scan sandbox (no container)" of ER-5 as the physical isolation for tools; the credential rules of ER-5 are unchanged. Related: ADR-002 (workers), ADR-003 (tenant isolation), ADR-004 (finding identity), ADR-008 (the security suite stays Docker-free), ADR-009 (no secrets in the scan path), ADR-011, `docs/technical/SECURITY_GUIDELINES.md` ("Do not execute repository instructions during analysis"). Module specification: `docs/modules/scan-engines/SPEC.md`.

## Context

The platform must scan customer repositories for SBOM, SCA, SAST and Secrets with the established open-source tools (Syft and cdxgen; Trivy, Grype and OSV-Scanner; Semgrep and language tools; Gitleaks and detect-secrets). These tools are native programs in several languages (Go, Python, Node, Ruby) with their own dependencies, and they parse **hostile input**: a customer repository, or a fork pull request, can be written by an attacker. Some of them can, by design or by misconfiguration, execute repository-controlled code (package-manager lifecycle scripts, build plugins, `go` toolchain directives, autofix, plugin loading). Running them as ordinary child processes of the scan worker would put hostile input next to the worker's credentials and the host.

The existing engine is a pure-JavaScript SBOM-lite parser (Executions §17.ab) that needs no isolation. The Executions SPEC chose a "logical scan sandbox" (ER-5: no credentials, no network added by the platform) and left physical isolation as a deployment decision "outside this spec (Docker is out of scope)". With real third-party tools, the logical sandbox is not enough: a tool bug or a malicious repository must not reach the host, the network, the database or another tenant's data.

## Decision (proposed)

### 1. Scope of the exception (exactly what is and is not in scope)

**In scope (the exception):**
- Running third-party scan tools (and the evidence block-extractor) as **pinned OCI images referenced by digest** on a container runtime on the hosts that run the scan workers and, separately, the vulnerability-database refresh job.
- The code in the repository that does this: the `SandboxRuntime` abstraction, the pure argument builder, the image catalog / lock file, the janitor, and, if the owner chooses to build images instead of consuming upstream images, **minimal image build recipes for scan images only** (Dockerfile-like files). Documentation of how to provision images and the runtime on a scan host.
- Developer use of Docker (or Podman) on a developer machine for the live checks of the scan layer.

**Not in scope (the rest of the `CLAUDE.md` line stands):**
- Docker Compose, Kubernetes, Helm, Terraform, any orchestration or deployment manifest for the platform itself (API, web apps, other workers, PostgreSQL, Redis, RabbitMQ). Containerising the platform is **not** approved by this ADR.
- CI/CD configuration, image build pipelines, registries as infrastructure-as-code.
- Feature/unit test-case structures (ADR-008 stays the only exception; its suite remains **Docker-free**, using a fake runtime, ADR-008 line 150).
- Running a customer's build, tests, install or hooks in any form.

### 2. Sandbox properties (Confirmed by the owner brief 2026-11-19; flag spellings Recommended and verified live)

Each tool invocation is one short-lived container with:

| Property | Setting |
|---|---|
| Image | Referenced by `sha256` digest from a reviewed lock file; never a tag; `--pull=never` (images are provisioned beforehand) |
| Network | None (`--network=none`): no interface, no DNS. The only data that enters is mounted read-only |
| Filesystem | Read-only root filesystem; `/tmp` is a size-limited `tmpfs` with `noexec,nosuid,nodev`; **no host-writable mount at all** (output leaves through stdout, capped) |
| Mounts | Read-only archive tree; read-only vulnerability-DB snapshot (SCA tools); read-only platform rules/config; nothing else (never the runtime socket, home, worker directory, archive store or mirror root) |
| User | Fixed non-root numeric uid/gid (mapped through a user namespace when the runtime is rootless) |
| Privileges | `--cap-drop=ALL`, `no-new-privileges`, a seccomp profile (never `unconfined`), the runtime's default MAC profile (AppArmor/SELinux) where present |
| Limits | CPU, memory (swap equal to memory), pids, `ulimit`s, tmpfs size, wall-clock kill, stdout byte cap |
| Environment | An explicit allowlist of static strings; no inherited environment, no env file; no credential of any kind |
| Command | An argument array, no shell; repository-derived values only as validated relative paths after `--` |
| Repository data | Analysed as **data**; never executed, built, installed or interpreted as tool configuration (platform config is mounted; tool-control file names are removed from the tool's tree) |

`RunSpec`, the object that describes a run, has no field that could weaken any of these; the runner derives the security flags from constants.

### 3. Runtime options (the owner decides; Open)

| Option | What it is | For | Against |
|---|---|---|---|
| **A. Docker Engine, scan worker uses the daemon socket** | The scan worker (or a library such as dockerode) talks to `/var/run/docker.sock` | Simplest; same as most developer machines; mature | **Access to the Docker socket is equivalent to root on the host**: anything that compromises the scan worker (a bug in output parsing, a dependency) can start a privileged container mounting `/`. This defeats the sandbox it is meant to provide. Acceptable only for a single-user developer laptop |
| **B. Rootless Docker or rootless Podman, CLI per run** (daemon-less in Podman's case) | The runtime and its containers run as an unprivileged user in a user namespace; the worker calls the CLI (`execFile`, no shell) | The "socket is root" problem shrinks to "socket is the worker's own unprivileged user"; no always-on root daemon (Podman); containers' root maps to an unprivileged host uid; one-line change from A for development | Rootless limitations (some network and cgroup features, performance, uid mapping subtleties with a `0600` tree, see SPEC CX-12); a compromised worker can still start containers as itself (but cannot gain host root through the runtime); cgroup v2 delegation must be set up |
| **C. A dedicated `scan-runner` service with a narrow API** | A small separate process (an additional worker entry point) that alone holds the runtime privileges; the scan worker calls it over a unix socket or mTLS with a request that can only say: catalog image key, task id, which read-only inputs, limits within ceilings | The scan worker holds **no** runtime privilege; the runner cannot be asked for anything outside the safe `RunSpec`; the runner can live on a different host or user; natural place for the janitor, the DB snapshot cache and fork/trusted pools | A new deployable component (ADR-002 allows separate worker entry points, but this is a service with an API surface); more moving parts; the runner itself must be hardened and is a high-value target |
| **D. B or C plus a stronger OCI runtime (gVisor `runsc` or Kata Containers)** | Containers run under a user-space kernel (gVisor) or a lightweight VM (Kata) | Materially reduces kernel-escape risk for hostile input; recommended for production multi-tenant and for the fork pool | Compatibility and performance costs (some tools or syscalls may not work; verify per tool); more operational skill; not available on all hosts (nested virtualisation for Kata) |
| **E. A microVM per task (for example Firecracker)** | One VM per scan task | Strongest isolation | Heavy to build and operate; out of proportion for the first release |
| **F. Kubernetes Jobs** | Pod per tool | Familiar scheduling | **Out of scope** (`CLAUDE.md`); would need the platform deployment decision first |

**Recommendation (Open, owner to decide):** put every call behind the `SandboxRuntime` interface so the choice is a driver, then **B for development and a single-host first release**, **C when the platform runs scan workers on more than one host or processes fork traffic at volume**, and **D (gVisor first) for production multi-tenant**. **A only on a developer laptop**, with a clear warning in the runbook. The development environment may use Docker (the owner's machine has a Docker CLI); the security properties of section 2 are applied identically by every driver.

### 4. The module owns the digests and the data (summary; details in SPEC)

- A reviewed **image lock file**; digests are changed only by an owner-approved change that records licence, upstream release, self-scan result and image SBOM; no automatic bumps; signatures/provenance verified at provisioning where upstream offers them.
- A platform **vulnerability-DB mirror** with snapshots addressed by digest, promoted only after a canary scan, mounted read-only; the only network egress in the whole scan layer is the refresh job, which has an allowlist.
- Every result records tool, image and DB digests (reproducibility).

### 5. Documentation amendments (APPLIED 2026-11-19)

> **`CLAUDE.md` (Hard constraints, out-of-scope line):** "Out of scope now: Docker Compose, Kubernetes, deployment/CI config, feature/unit test-case structures (...). **Exception (ADR-014): the scan execution layer may use a container runtime to run pinned, digest-referenced scan-tool images in a locked-down sandbox, with the minimal image recipes and catalog this needs.** Nothing else about Docker, Compose, Kubernetes, deployment or CI changes."
>
> **`docs/technical/TECH_STACK.md`:** add "Scan layer: OCI container runtime (Docker, rootless Docker or Podman; runtime choice per ADR-014) for third-party scan tools only."
>
> **`docs/README.md` line 33, `AGENTS.md` line 27, `docs/ai-development/AGENT_INSTRUCTIONS.md` line 101:** the same exception sentence.
>
> **Executions SPEC ER-5:** append "Physical isolation of tools is provided by ADR-014 containers; the scan worker still holds no credential."
>
> **ADR-008:** area 18 (SPEC scan-engines 14.1), the suite stays Docker-free.

## Alternatives considered

1. **Run the tools as child processes of the scan worker** (no containers). Rejected: hostile input would parse next to the worker's process, files and any future credentials; resource limits and network blocking are not enforceable portably; tools that run repository code would run it on the host.
2. **Reimplement the tools in JavaScript inside the repository** (extend SBOM-lite style parsers). Rejected for SCA, SAST and Secrets: detection quality and rule coverage of the established tools cannot be matched; maintenance burden; keeps only SBOM-lite as a fallback adapter.
3. **A hosted scanning service** (send code to a third party). Rejected: violates the data-egress posture of the product (ADR-013 consent model) and removes control over the sandbox.
4. **Language-level sandboxes** (Node `vm`, Worker threads, WASM builds of the tools). Rejected as the isolation boundary for native tools: not a security boundary for untrusted native code; WASM builds do not exist for the tools. WASM is used only inside the extractor image for tree-sitter.
5. **Kubernetes/Firecracker from day one.** Deferred: out of scope or out of proportion for the first release; the interface keeps them possible.

## Rationale

The tools are valuable and widely trusted but process attacker-controlled input and some can execute repository code. Containers give a portable, well-understood boundary with enforceable limits for network, filesystem, capabilities, syscalls and resources. The residual risk is concentrated in the runtime control channel and the kernel; the options table shows how to reduce each (rootless or a narrow runner for the channel, gVisor/Kata for the kernel) without committing the owner to heavy infrastructure up front. Pinning by digest, a reviewed lock file and offline mirrored data make the scan layer reproducible and keep the network closed.

## Consequences

### Positive
- Hostile repositories are contained; network exfiltration and host access from a tool are closed by construction; resource abuse is bounded.
- Reproducible results (tool, image and DB digests recorded).
- The security-critical flags are one pure function, testable in the Docker-free suite.
- The runtime is replaceable behind an interface.

### Negative / trade-offs
- A container runtime becomes an operational dependency of scan hosts (installation, updates, image provisioning, disk, cgroup settings); developers need Docker or Podman for the live checks.
- Several images and large DB snapshots (disk, bandwidth, update cadence); sizes unmeasured (SPEC OQ-21).
- Per-tool container start cost; limits need calibration.
- The tools' licences need review before each adoption (SPEC OQ-9); TruffleHog (AGPL-3.0) and CodeQL (commercial terms) are excluded; Brakeman and Semgrep registry rules carry caveats.
- Windows and macOS developer machines use a Linux VM runtime with different isolation characteristics (SPEC OQ-19).
- The documented "no Docker" rule gains an exception that must be maintained carefully.

## Security and operational impact

| Id | Risk | Mitigation (see SPEC 11.1) |
|---|---|---|
| R1 | **Docker socket access equals root** (option A); a compromised scan worker owns the host | Prefer B or C; never mount the socket into a container; the worker has no credentials and the runner accepts only safe specs |
| R2 | Kernel or runtime escape | seccomp, dropped capabilities, rootless, user namespaces, read-only everything, limits; gVisor/Kata for production; patching |
| R3 | Image supply chain (poisoned upstream image, tag swap) | Digest pinning, reviewed lock file, signature verification where available, self-scan, no automatic bump, provisioning from a platform mirror |
| R4 | A tool executes repository code (cdxgen, gosec, plugins) | No network, no package managers in images, analysis-only modes, explicit config, planted-script live test; adopt a tool only if the test passes |
| R5 | File permission and uid mapping surprises (the extracted tree is `0600/0700`) | Same-uid mapping under rootless runtimes; live check ENG-L02 |
| R6 | The DB refresh job is the one egress point | Separate worker role, allowlist, integrity checks, canary promotion, no tenant data on that host |
| R7 | Runtime differences between dev and production (Docker Desktop, rootless limits, gVisor compatibility) | Same `RunSpec` and argv builder; live checks per runtime; run L01 to L08 under the production runtime |
| R8 | Operational burden (orphans, disk, image drift) | Janitor, image verification message, size budget, runbook |
| R9 | Fork traffic starves trusted scans | Separate `scan-untrusted` pool with a capacity share and tighter limits (SPEC SE-19, SE-30) |

Observability: container starts/kills/orphans, capacity waits, DB snapshot age, digests in use. Secrets: none in the scan path; registry credentials (if a private mirror needs them) exist only in the provisioning step, never on a scan worker.

## Decided 2026-11-19

1. **Runtime and isolation:** `SandboxRuntime` interface; rootless Podman (preferred) or rootless Docker for development; a dedicated scan-runner service for production; gVisor/Kata noted; option A (plain Docker socket) is not used, and the socket is never mounted into the worker.
2. The documentation amendments of section 5 are approved and applied.
3. Images are pinned by digest in an images manifest; cosign signing is deferred to production; the scanner images are scanned in CI later.

## Open (owner decisions)

3. Own-built images vs upstream images pinned by digest; the registry/mirror (SPEC OQ-12).
4. The licence review outcomes (SPEC OQ-9): decided as a gate (permissive licence, no repository code execution, offline); outcomes per tool come from the Part A spike (SPEC 17.a).
5. Whether fork traffic requires a separate host or OS user from the first release (SPEC SE-30).

## Verification status

Verification status after the 2026-11-19 decision: the Part A spike (SPEC 17.a) verifies flag spellings and tool behaviour on a rootful Docker only. Not verified before it: any flag spelling against a running runtime, rootless uid mapping, seccomp profile content, gVisor compatibility, image sizes. All of these are the live checks ENG-L01 to ENG-L16 (SPEC 16.2), to be run on the owner's Docker-capable machine. The cloud sandbox is expected to have no Docker daemon; the Docker-free suite checks (ENG-S01 to ENG-S14) prove the generated invocation, not the runtime's behaviour.

## Related documents

- `docs/modules/scan-engines/SPEC.md` and `SCREENS.md`
- `docs/modules/executions/SPEC.md` (ER-5, ER-6, ER-7, ER-13, ER-14, ER-16, §17.ab, §17.ac)
- `docs/modules/scan-decisioning/SPEC.md` (FT-2, FT-5, §17.g)
- `docs/decisions/ADR-002-MODULAR-MONOLITH.md`, `ADR-003-TENANT-ISOLATION.md`, `ADR-004-FINDING-IDENTITY.md`, `ADR-008-SECURITY-REGRESSION-SUITE.md`, `ADR-009-INTEGRATION-CREDENTIAL-STORAGE.md`, `ADR-011-TRANSACTIONAL-OUTBOX-AND-MESSAGE-ENVELOPE.md`, `ADR-013-LLM-PROVIDER-ABSTRACTION.md`
- `docs/technical/SECURITY_GUIDELINES.md`
