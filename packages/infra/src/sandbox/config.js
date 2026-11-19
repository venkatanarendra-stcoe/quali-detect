import path from "node:path";
import { SANDBOX_ERROR_CODES, SandboxError } from "./errors.js";
import {
  DEFAULT_FORBIDDEN_MOUNT_ROOTS,
  MOUNT_SOURCE_PATTERN,
  NETWORK_PURPOSES,
  RUNTIME_BINARIES,
  USERNS_MODES,
} from "./policy.js";

/**
 * @typedef {{ cpus: number, memoryMiB: number, pids: number, wallClockSeconds: number, stdoutBytes: number, tmpfsMiB: number }} SandboxCeilings
 * @typedef {{
 *   runtimeBin: "docker" | "podman",
 *   containerUser: string,
 *   usernsMode: "keep-id" | "auto" | "nomap" | null,
 *   uidMap: string[], gidMap: string[],
 *   seccompProfile: string | null,
 *   mountRoots: { archive: string[], db: string[], rules: string[] },
 *   forbiddenMountRoots: string[],
 *   egressNetworks: Record<string, string>,
 *   ceilings: SandboxCeilings,
 *   stderrBytes: number, cliTimeoutMs: number, killGraceMs: number
 * }} SandboxConfig
 */

export const DEFAULT_CEILINGS = Object.freeze({
  cpus: 4,
  memoryMiB: 8192,
  pids: 2048,
  wallClockSeconds: 7200,
  stdoutBytes: 134217728,
  tmpfsMiB: 4096,
});

const MAP_PATTERN = /^\d{1,10}:\d{1,10}:\d{1,10}$/;
const NETWORK_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const RESERVED_NETWORKS = new Set([
  "none",
  "host",
  "bridge",
  "default",
  "private",
  "slirp4netns",
  "pasta",
]);

/**
 * @param {string} p a safe absolute path
 * @param {string[]} forbidden forbidden roots
 * @returns {boolean} `p` is a forbidden root or lies inside one ("/" only forbids itself)
 */
export function isUnderForbiddenRoot(p, forbidden) {
  return forbidden.some((f) => (f === "/" ? p === "/" : p === f || p.startsWith(`${f}/`)));
}

/** @param {unknown} v */
const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * @param {string} p
 * @returns {boolean} an absolute, normalized path made of safe characters only
 */
export function isSafeAbsolutePath(p) {
  return (
    typeof p === "string" &&
    MOUNT_SOURCE_PATTERN.test(p) &&
    path.posix.normalize(p) === p &&
    !p.split("/").includes("..") &&
    (p === "/" || !p.endsWith("/"))
  );
}

/**
 * Problems of a raw sandbox configuration (field names and rules only, never values). Pure.
 *
 * ROOTLESS NOTE (ADR-014, SPEC D-20, UNVERIFIED): nothing here assumes a rootful runtime. The binary (`docker` or `podman`), the
 * user-namespace mode and the uid/gid maps are configuration. Whether a given combination works on a rootless host (uid mapping of
 * the 0755/0644 tree, seccomp, gVisor) is the REQUIRED pre-production check ENG-L18; it has NOT been verified.
 * @param {unknown} raw
 * @returns {Array<{ field: string, message: string }>}
 */
export function sandboxConfigProblems(raw) {
  const problems = [];
  const bad = (field, message) => problems.push({ field, message });
  if (!isPlainObject(raw)) return [{ field: "(config)", message: "must be an object" }];
  const c = /** @type {Record<string, any>} */ (raw);
  if (!RUNTIME_BINARIES.includes(c.runtimeBin))
    bad("runtimeBin", `must be one of: ${RUNTIME_BINARIES.join(", ")}`);
  if (typeof c.containerUser !== "string" || !/^[1-9]\d{0,9}:[1-9]\d{0,9}$/.test(c.containerUser))
    bad("containerUser", "must be a numeric non-root uid:gid (both greater than 0)");
  if (c.usernsMode !== undefined && c.usernsMode !== null && !USERNS_MODES.includes(c.usernsMode))
    bad("usernsMode", `must be unset or one of: ${USERNS_MODES.join(", ")} (never host)`);
  for (const key of ["uidMap", "gidMap"]) {
    const list = c[key] ?? [];
    if (!Array.isArray(list) || list.length > 8 || !list.every((m) => MAP_PATTERN.test(m)))
      bad(key, "must be a list of at most 8 entries of the form n:n:n");
  }
  if (c.seccompProfile !== undefined && c.seccompProfile !== null) {
    if (!isSafeAbsolutePath(c.seccompProfile))
      bad("seccompProfile", "must be a safe absolute path");
    else if (/unconfined/i.test(c.seccompProfile)) bad("seccompProfile", "must not be unconfined");
  }
  const forbidden = c.forbiddenMountRoots ?? DEFAULT_FORBIDDEN_MOUNT_ROOTS;
  if (!Array.isArray(forbidden) || !forbidden.every(isSafeAbsolutePath))
    bad("forbiddenMountRoots", "must be a list of safe absolute paths");
  const roots = c.mountRoots ?? { archive: [], db: [], rules: [] };
  if (!isPlainObject(roots)) bad("mountRoots", "must be an object");
  else
    for (const kind of ["archive", "db", "rules"]) {
      const list = roots[kind] ?? [];
      if (!Array.isArray(list) || !list.every(isSafeAbsolutePath))
        bad(`mountRoots.${kind}`, "must be a list of safe absolute paths");
      else if (list.some((r) => isUnderForbiddenRoot(r, Array.isArray(forbidden) ? forbidden : [])))
        bad(`mountRoots.${kind}`, "must not be, or be inside, a forbidden root");
    }
  const egress = c.egressNetworks ?? {};
  if (!isPlainObject(egress)) bad("egressNetworks", "must be an object of purpose to network name");
  else
    for (const [purpose, net] of Object.entries(egress)) {
      if (!NETWORK_PURPOSES.includes(purpose)) bad("egressNetworks", "contains an unknown purpose");
      else if (
        typeof net !== "string" ||
        !NETWORK_NAME_PATTERN.test(net) ||
        RESERVED_NETWORKS.has(net.toLowerCase())
      )
        bad("egressNetworks", "must name a dedicated network (not none, host, bridge or a mode)");
    }
  const ceilings = { ...DEFAULT_CEILINGS, ...(isPlainObject(c.ceilings) ? c.ceilings : {}) };
  for (const [key, max] of Object.entries(DEFAULT_CEILINGS)) {
    const v = ceilings[key];
    if (!Number.isFinite(v) || v <= 0 || v > max * 16)
      bad(`ceilings.${key}`, "must be a positive number within sane bounds");
  }
  for (const [key, lo, hi] of [
    ["stderrBytes", 1024, 4194304],
    ["cliTimeoutMs", 1000, 600000],
    ["killGraceMs", 100, 120000],
  ]) {
    const v = c[key] ?? { stderrBytes: 65536, cliTimeoutMs: 30000, killGraceMs: 10000 }[key];
    if (!Number.isInteger(v) || v < lo || v > hi)
      bad(key, `must be an integer from ${lo} to ${hi}`);
  }
  return problems;
}

/**
 * Validates and normalizes a sandbox configuration (fail fast). The result is frozen.
 * @param {unknown} raw
 * @returns {Readonly<SandboxConfig>}
 * @throws {SandboxError} `invalid_config`, naming fields and rules, never values
 */
export function validateSandboxConfig(raw) {
  const problems = sandboxConfigProblems(raw);
  if (problems.length > 0)
    throw new SandboxError(
      SANDBOX_ERROR_CODES.invalidConfig,
      `Invalid sandbox configuration: ${problems.map((p) => `${p.field}: ${p.message}`).join("; ")}`,
      problems.map((p) => p.field),
    );
  const c = /** @type {Record<string, any>} */ (raw);
  return Object.freeze({
    runtimeBin: c.runtimeBin,
    containerUser: c.containerUser,
    usernsMode: c.usernsMode ?? null,
    uidMap: Object.freeze([...(c.uidMap ?? [])]),
    gidMap: Object.freeze([...(c.gidMap ?? [])]),
    seccompProfile: c.seccompProfile ?? null,
    mountRoots: Object.freeze({
      archive: Object.freeze([...(c.mountRoots?.archive ?? [])]),
      db: Object.freeze([...(c.mountRoots?.db ?? [])]),
      rules: Object.freeze([...(c.mountRoots?.rules ?? [])]),
    }),
    forbiddenMountRoots: Object.freeze([
      ...(c.forbiddenMountRoots ?? DEFAULT_FORBIDDEN_MOUNT_ROOTS),
    ]),
    egressNetworks: Object.freeze({ ...(c.egressNetworks ?? {}) }),
    ceilings: Object.freeze({ ...DEFAULT_CEILINGS, ...(c.ceilings ?? {}) }),
    stderrBytes: c.stderrBytes ?? 65536,
    cliTimeoutMs: c.cliTimeoutMs ?? 30000,
    killGraceMs: c.killGraceMs ?? 10000,
  });
}
