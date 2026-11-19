/**
 * Constants of the sandbox policy (SPEC 6.2, ADR-014 section 2). The security flags are derived from these constants by the pure
 * argument builder; nothing in a RunSpec can weaken them. Values here are the single source for the builder AND the audit
 * (`findRunArgsProblems`).
 */

/** Fixed container-side mount targets; every bind mount is read-only. */
export const MOUNT_TARGETS = Object.freeze({ archive: "/src", db: "/db", rules: "/rules" });

/** The only environment variable names a tool container may receive (static strings only, SE-29). */
export const ENV_ALLOWLIST = Object.freeze([
  "HOME",
  "SYFT_CHECK_FOR_APP_UPDATE",
  "TRIVY_SKIP_VERSION_CHECK",
  "TRIVY_DISABLE_TELEMETRY",
  "TRIVY_CACHE_DIR",
  "GRYPE_DB_CACHE_DIR",
  "GRYPE_DB_AUTO_UPDATE",
  "GRYPE_DB_VALIDATE_AGE",
  "GRYPE_CHECK_FOR_APP_UPDATE",
  "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
  "SEMGREP_ENABLE_VERSION_CHECK",
  "SEMGREP_SEND_METRICS",
  "SEMGREP_SETTINGS_FILE",
  "XDG_CACHE_HOME",
  "GOFLAGS",
  "GOPROXY",
  "CGO_ENABLED",
  "GOTOOLCHAIN",
  "GOCACHE",
  "GOPATH",
  "GOTELEMETRY",
  "GOENV",
]);

/** A safe value of an allowlisted variable: a short static string with no whitespace, quote, backslash or shell syntax. */
export const ENV_VALUE_PATTERN = /^[A-Za-z0-9_./:=,@+-]{0,256}$/;

/** `<repository>@sha256:<64 hex>`: a digest and nothing else (no tag, no tag+digest). */
export const IMAGE_DIGEST_PATTERN =
  /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*@sha256:[0-9a-f]{64}$/;

/** Label keys the runner writes (the janitor lists by `qm.scan=1`). */
export const LABEL_KEYS = Object.freeze({
  scan: "qm.scan",
  tenant: "qm.tenant",
  execution: "qm.execution",
  task: "qm.task",
  tool: "qm.tool",
  attempt: "qm.attempt",
  deadline: "qm.deadline",
});

/** Identifier shape for label values and the tool id (uuids and short ids). */
export const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const TOOL_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** Container names: `qm-<task8>-<tool>-<attempt>`. */
export const CONTAINER_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

/** Mount sources: absolute, a conservative character set (no comma, equals sign, quote, space or newline: they would inject mount options). */
export const MOUNT_SOURCE_PATTERN = /^\/[A-Za-z0-9._@+/-]{0,1000}$/;

/** Roots that are never a mount source or inside one (host system, runtime sockets, devices). */
export const DEFAULT_FORBIDDEN_MOUNT_ROOTS = Object.freeze([
  "/",
  "/proc",
  "/sys",
  "/dev",
  "/run",
  "/var/run",
  "/etc",
  "/root",
  "/boot",
  "/home",
  "/var/lib/docker",
  "/var/lib/containers",
]);

/** Security-relevant CLI flag names the builder is allowed to emit (anything else in an audited argv is refused). */
export const ALLOWED_FLAG_NAMES = Object.freeze([
  "--rm",
  "--init",
  "--interactive",
  "--name",
  "--label",
  "--pull",
  "--network",
  "--read-only",
  "--user",
  "--userns",
  "--uidmap",
  "--gidmap",
  "--cap-drop",
  "--security-opt",
  "--pids-limit",
  "--memory",
  "--memory-swap",
  "--cpus",
  "--ulimit",
  "--tmpfs",
  "--mount",
  "--env",
  "--workdir",
]);

/** Network purposes that may leave the sealed default (SE-34: only the refresh job). Named networks come from the runtime config. */
export const NETWORK_PURPOSES = Object.freeze(["db_refresh"]);

/** Allowed user-namespace modes (never `host`). */
export const USERNS_MODES = Object.freeze(["keep-id", "auto", "nomap"]);

export const RUNTIME_BINARIES = Object.freeze(["docker", "podman"]);
