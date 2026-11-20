/**
 * Constants of the ensemble engine (docs/modules/scan-engines/SPEC.md 5.10 SE-25, D-22). The ensemble version changes when any
 * mapping or merge rule, the rule files or the catalog image set changes.
 */
export const ENSEMBLE_VERSION = "1";
/** The catalog engine id stays `default` (CX-11); only the version names the ensemble. */
export const ENGINE_ID = "default";
/** The ONE tool whose CycloneDX document is stored in the `sbom_document` class (owner decision D-22 (4)). */
export const SBOM_DOCUMENT_TOOL_ID = "syft";
/** Ceiling of one `sbom_document` (16 MiB, SPEC 7.3). A larger document is not stored (never a failure). */
export const SBOM_DOCUMENT_MAX_BYTES = 16 * 1024 * 1024;
/** How long a tool waits for capacity before it is `unavailable` / `capacity` (SE-20). */
export const DEFAULT_TOOL_WAIT_MS = 120_000;
/** Tools per task that may run at once (SE-16). */
export const DEFAULT_TOOL_PARALLELISM = 2;
