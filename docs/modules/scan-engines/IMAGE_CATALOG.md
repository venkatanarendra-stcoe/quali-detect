# Scan engines: image catalog, lock file and provisioning (build part B)

Status: **as built in part B (2026-11-19).** Owner decisions behind it: SPEC D-4, D-13, D-14 (digests in a manifest, own-built Opengrep and detect-secrets images, a pinned platform mirror registry), D-15 (data quarantine), D-20 (no rootful assumption). Facts about each image come from the Part A spike (`IMAGES.md`, SPEC 17.a). **Nothing here was run against a container runtime:** no image was pulled, pushed, loaded or verified by this part, and every `approvedBy` / `approvedAt` / `signatureVerified` / `selfScan` / `imageSbomSha256` field of the lock file is still empty.

## 1. What the lock file is

`apps/workers/src/execution/engines/ensemble/catalog/images.lock.json` (the path proposed in SPEC 9.3). One entry per tool image, reviewed like code. It is **generated from `IMAGES.md` by hand-copy, never invented**: every digest in it appears in the `IMAGES.md` section 1 table, and the suite (`ENG-S02b`) checks the two documents against each other in both directions.

Fields of an entry (all required; the validator refuses unknown fields):

| Field | Meaning |
|---|---|
| `key` | The catalog key the runner is given (`^[a-z0-9][a-z0-9-]{0,31}$`). A repository, a tag or a reference is never a key |
| `imagesMdName` | The tool's name in the first column of the `IMAGES.md` table (used by the consistency check) |
| `toolId`, `roles`, `scanTypes` | Tool id (also the container label), what it does, and the scan types it may serve (`sbom`, `sca`, `sast`, `secrets`, `evidence`) |
| `repository`, `digest` | The registry repository and the `sha256:<64 hex>` digest, joined as `repository@digest`. Both `null` when no registry image exists (excluded tools, unpushed own builds) |
| `version`, `licence` | Tool version and **SPDX** licence identifier (`LicenseRef-...` for non-SPDX licences) |
| `user` | The numeric non-root `uid:gid` the tool ran as in the spike; `null` for entries that are not adopted |
| `status` | `ADOPTED` (the three criteria of D-3 held), `EXCLUDED`, `UNVERIFIED`. **Only ADOPTED entries with a registry digest resolve** |
| `source` | `upstream`, or `own_build` with `baseImageDigest`, `localImageId` (the spike's local image id, **not** a registry digest) and `binarySha256` where applicable |
| `flags` | `local_build_requires_registry_digest`, `own_build`, `data_licence_legal_gate`, `data_quarantined`, `mandatory_flags`, `not_selected` |
| `notes`, `sourceUrl` | Free text for reviewers; https URL of the project |
| `licenceReviewedAt`, `approvedBy`, `approvedAt` | Filled by the owner at approval; `null` until then (a non-ADOPTED entry never carries an approval) |
| `imageSbomSha256`, `selfScan`, `signatureVerified` | Review evidence, see sections 4 and 5 |

## 2. Loader, validator and resolver

- `packages/infra/src/sandbox/image-catalog.js` (pure, no file access): `validateImageLock(lock, { production })` returns `{ errors, warnings }`; `createImageResolver(lock, { production })` refuses to be created from a lock with errors and resolves a **key** to `repository@sha256:digest`; `resolveRunSpecImage(spec, resolver)` turns a spec that names `imageKey` (and no `image`) into a RunSpec whose `image` can only have come from the lock. The Part A builder still accepts only a digest reference, so a tag cannot enter through either door.
- `apps/workers/src/execution/engines/ensemble/catalog/index.js`: `loadImageLock()` reads and parses the file (bounded size) and returns the validated resolver; the lock file hash is returned for logging at worker start (SPEC 9.3).
- Rules the validator enforces: schema version 1; every field present and typed; unique `key`, `toolId` and digest; `digest` matches `sha256:[0-9a-f]{64}`; `repository` has no tag; SPDX licence; numeric non-root user for ADOPTED; an ADOPTED entry has a registry digest **or** is a flagged own build; EXCLUDED and UNVERIFIED entries carry no approval; unknown fields refused.
- **Warnings (never silent):** an ADOPTED entry not yet approved by an owner, without a signature check, without a self-scan record, flagged for the data-licence gate or the data quarantine, and **a locally built image with no registry digest** (`local_build_requires_registry_digest`). In **production mode** (`production: true`) the last one and any placeholder digest become **errors**, so a lock file with an unpushed own build cannot pass the production gate.
- **Resolver reasons** (stable codes in `image_unavailable` errors): `unknown_key`, `not_adopted` (EXCLUDED and UNVERIFIED are never resolvable), `scan_type`, `no_registry_digest` (an own build before it is pushed to the mirror), `placeholder_digest` (production), `malformed_reference`.
- **`--pull=never`:** the resolver result carries `pullPolicy: "never"` and the argument builder always emits `--pull=never` (audited). A resolved digest must already be in the runtime's local store (section 3).

## 3. Provisioning (operator procedure; nothing here is automated yet)

1. **Choose the digest.** From the upstream release (or from our own build), record `repository@sha256:digest` of the exact image. Prefer the digest of the multi-architecture index; record which platform was tested. Never copy a tag.
2. **Review.** A change edits exactly one entry. It must show: licence (SPDX) and review date, the upstream release notes link, the self-scan result (section 5), the image SBOM hash, and, where upstream publishes it, the signature or provenance check. The owner approves (`approvedBy`, `approvedAt`). No automatic digest bump.
3. **Mirror.** Copy the image **by digest** to the platform mirror registry (pinned, platform-controlled; the hostname and credentials belong to the provisioning step and never reach a scan worker). For the own-built images (Opengrep, detect-secrets): build from the vetted release binary (sha256 checked against the value in `source.binarySha256`) or the frozen `pip` set on a digest-pinned base, run as a numeric non-root user, push, then **record the registry digest and clear the `local_build_requires_registry_digest` flag**.
4. **Load into the runtime store.** On each scan host: `pull` by digest from the mirror, or `load` a tarball on an air-gapped host, with the runtime selected by `SANDBOX_RUNTIME_BIN`. Then confirm the stored digest equals the lock digest (a mismatch is refused, ENG-L15). Rootless runtimes keep a separate store per user: provision as the user that runs the scan worker (UNVERIFIED, ENG-L18).
5. **Run.** A scan always runs with `--pull=never`; a missing image fails closed as `unavailable` for that tool (SPEC 6.5), it never reaches a registry.

Verification of signatures (cosign) is deferred to production (D-4). The periodic `maintenance.scan_images.verify_requested` check (SPEC 9.2) is not built.

## 4. Records that are documentation and schema only

Nothing produces or consumes these yet; the validator checks their shape so that a human-entered record cannot be malformed.

- `signatureVerified: { verified: boolean, method: string | null }` (for example `cosign verify` with the key or identity used).
- `imageSbomSha256`: sha256 (64 hex) of the SBOM document generated for the image.

## 5. Self-scan record

The result of scanning the scanner image with our own SCA before approval. `selfScan` is `null` until done, then:

```json
{
  "scannedAt": "2026-11-19T12:00:00Z",
  "scanner": "trivy",
  "scannerVersion": "0.76.2",
  "dataSnapshotSha256": "sha256:<64 hex of the vulnerability data snapshot used>",
  "counts": { "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0 }
}
```

Only language-ecosystem data from the allowed sources may be used (SPEC 5.12.1); the policy for what counts as acceptable (for example no unreviewed critical finding) is an owner decision and is **not** set here.

## 6. State of the committed lock file (read before relying on it)

- 10 adopted or proposed entries and 5 excluded ones, copied from `IMAGES.md`. Seven entries carry a registry digest (Syft, Trivy, OSV-Scanner, Bandit, gosec, Gitleaks, and Grype, which is DEFERRED_V2) plus the excluded Semgrep OSS.
- **Opengrep and detect-secrets are own builds with no registry digest.** They are flagged, produce a validator warning, are not resolvable, and become validator errors in production mode until the mirror digest is recorded.
- **Grype is `DEFERRED_V2` (owner decision on OQ-24, 2026-11-19, SPEC D-21):** its aggregated DB licence is unstated, so it is not in the v1 SCA ensemble. The lock keeps the digest for traceability with the flags `deferred_v2` and `data_quarantined`; the resolver refuses it with the code `tool_deferred` (distinct from `image_unavailable`), and `runnableKeys()` omits it. v2 brings it back with an own-built DB from NVD + GHSA.
- **Own-built images:** recording the mirror registry digests of Opengrep and detect-secrets is a pre-production task of the owner; the production-mode error of the loader stays correct until then.
- No entry is approved by an owner, none has a signature check, an image SBOM or a self-scan. These are the owner's pre-production steps (ENG-L15).
- The block extractor is an ADOPTED own build as of Part J (2026-11-22): it carries the flags `own_build` and `local_build_requires_registry_digest` like Opengrep and detect-secrets, so the production lock has three own builds without a registry digest (a pre-production task).
