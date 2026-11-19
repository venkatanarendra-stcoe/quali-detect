import { findCredentials } from "../credential-guard.js";
import { isSafeAbsolutePath, isUnderForbiddenRoot } from "./config.js";
import { SANDBOX_ERROR_CODES, SandboxError } from "./errors.js";
import {
  ALLOWED_FLAG_NAMES,
  ENV_ALLOWLIST,
  ENV_VALUE_PATTERN,
  IMAGE_DIGEST_PATTERN,
  LABEL_KEYS,
  MOUNT_TARGETS,
  CONTAINER_NAME_PATTERN,
  USERNS_MODES,
} from "./policy.js";
import { containerNameOf, validateRunSpec } from "./run-spec.js";

/** Every flag is ONE argv element (`--flag=value`), so the audit never has to guess which token is a value. */
const fmt = (n) => String(Math.round(n * 100) / 100);

/**
 * Renders the runtime CLI arguments of one tool container (SPEC 6.2). PURE: the same spec and configuration always give the same
 * array; no I/O, no clock, no environment. The security flags come from constants and the runtime configuration, never from the
 * spec. The result is audited by {@link assertRunArgsSafe} before it is returned.
 *
 * The flag spellings follow the Docker CLI and the Podman CLI (compatible for these flags). They are UNVERIFIED against a running
 * runtime in the cloud sandbox (ENG-L01) and nothing here assumes a rootful runtime: `--userns`, `--uidmap` and `--gidmap` come
 * from configuration and their effect under rootless Podman/Docker is UNVERIFIED (ENG-L18).
 *
 * @param {unknown} rawSpec a {@link import("./run-spec.js").RunSpec}
 * @param {Readonly<import("./config.js").SandboxConfig>} config
 * @returns {readonly string[]} the arguments AFTER the runtime binary, starting with `run`
 * @throws {SandboxError} when the spec is invalid or asks for anything forbidden
 */
export function buildRunArgs(rawSpec, config) {
  const spec = validateRunSpec(rawSpec, config);
  const l = spec.limits;
  const name = containerNameOf(spec);
  const network = spec.networkPurpose ? config.egressNetworks[spec.networkPurpose] : "none";
  const args = [
    "run",
    "--rm",
    "--init",
    ...(spec.stdin !== undefined ? ["--interactive"] : []),
    `--name=${name}`,
    `--label=${LABEL_KEYS.scan}=1`,
    `--label=${LABEL_KEYS.tenant}=${spec.labels.tenantId}`,
    `--label=${LABEL_KEYS.execution}=${spec.labels.executionId}`,
    `--label=${LABEL_KEYS.task}=${spec.labels.taskId}`,
    `--label=${LABEL_KEYS.tool}=${spec.toolId}`,
    `--label=${LABEL_KEYS.attempt}=${spec.labels.attempt}`,
    `--label=${LABEL_KEYS.deadline}=${spec.labels.deadlineEpoch}`,
    "--pull=never",
    `--network=${network}`,
    "--read-only",
    `--user=${config.containerUser}`,
    ...(config.usernsMode ? [`--userns=${config.usernsMode}`] : []),
    ...config.uidMap.map((m) => `--uidmap=${m}`),
    ...config.gidMap.map((m) => `--gidmap=${m}`),
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    ...(config.seccompProfile ? [`--security-opt=seccomp=${config.seccompProfile}`] : []),
    `--pids-limit=${l.pids}`,
    `--memory=${l.memoryMiB}m`,
    `--memory-swap=${l.memoryMiB}m`,
    `--cpus=${fmt(l.cpus)}`,
    `--ulimit=nofile=${l.nofile ?? 1024}:${l.nofile ?? 1024}`,
    `--ulimit=fsize=${l.tmpfsMiB * 1048576}:${l.tmpfsMiB * 1048576}`,
    "--ulimit=core=0:0",
    `--tmpfs=/tmp:rw,noexec,nosuid,nodev,mode=1777,size=${l.tmpfsMiB}m`,
  ];
  for (const kind of /** @type {const} */ (["archive", "db", "rules"])) {
    const src = spec.mounts[kind];
    if (src) args.push(`--mount=type=bind,src=${src},dst=${MOUNT_TARGETS[kind]},readonly`);
  }
  args.push("--env=HOME=/tmp");
  for (const [k, v] of Object.entries(spec.env ?? {}))
    if (k !== "HOME") args.push(`--env=${k}=${v}`);
  args.push("--workdir=/tmp", spec.image, ...spec.argv);
  if (spec.paths && spec.paths.length > 0) args.push("--", ...spec.paths);
  assertRunArgsSafe(args, config);
  return Object.freeze(args);
}

const FLAG = /^(--[a-z][a-z-]*)(?:=(.*))?$/s;

/**
 * Audits a rendered argument list independently of the builder (defence in depth, and the check of ENG-S01 over mutated
 * copies). Allowlist based: every flag must be one the builder may emit, with an exact, safe value.
 * @param {readonly string[]} args arguments after the runtime binary
 * @param {Readonly<import("./config.js").SandboxConfig>} [config] adds the mount-root, network and user checks
 * @returns {string[]} the violated rule names (empty when the invocation is safe)
 */
export function findRunArgsProblems(args, config) {
  const problems = [];
  const bad = (rule) => problems.push(rule);
  if (!Array.isArray(args) || args.some((a) => typeof a !== "string"))
    return ["args must be a string array"];
  if (args[0] !== "run") bad("first argument must be run");
  const flags = [];
  let i = 1;
  for (; i < args.length && args[i].startsWith("-") && args[i] !== "--"; i += 1)
    flags.push(args[i]);
  const image = args[i];
  const count = new Map();
  const values = new Map();
  for (const f of flags) {
    const m = FLAG.exec(f);
    if (!m || !ALLOWED_FLAG_NAMES.includes(m[1])) {
      bad(`flag not allowed: ${f.startsWith("--") ? f.split("=")[0].slice(0, 30) : "short flag"}`);
      continue;
    }
    count.set(m[1], (count.get(m[1]) ?? 0) + 1);
    if (!values.has(m[1])) values.set(m[1], []);
    values.get(m[1]).push(m[2]);
  }
  const once = (name, value) => {
    if ((count.get(name) ?? 0) !== 1) return bad(`${name} must appear exactly once`);
    if (value !== undefined && values.get(name)[0] !== value) bad(`${name} has a forbidden value`);
  };
  once("--rm");
  once("--init");
  once("--read-only");
  once("--pull", "never");
  once("--cap-drop", "ALL");
  once("--workdir", "/tmp");
  once("--name");
  if (!CONTAINER_NAME_PATTERN.test(values.get("--name")?.[0] ?? "")) bad("--name is malformed");
  if ((count.get("--interactive") ?? 0) > 1) bad("--interactive repeated");
  // network: none, or the one dedicated egress network of the configuration
  once("--network");
  const net = values.get("--network")?.[0];
  if (net !== "none") {
    const allowed = config ? Object.values(config.egressNetworks) : [];
    if (!allowed.includes(net)) bad("--network must be none");
  }
  // user: numeric, non-root
  once("--user");
  const user = values.get("--user")?.[0] ?? "";
  if (!/^[1-9]\d{0,9}:[1-9]\d{0,9}$/.test(user)) bad("--user must be a numeric non-root uid:gid");
  if (config && user !== config.containerUser) bad("--user differs from the configured user");
  // user namespace (never host) and id maps
  if ((count.get("--userns") ?? 0) > 1) bad("--userns repeated");
  for (const v of values.get("--userns") ?? [])
    if (!USERNS_MODES.includes(v)) bad("--userns has a forbidden value");
  for (const name of ["--uidmap", "--gidmap"])
    for (const v of values.get(name) ?? [])
      if (!/^\d{1,10}:\d{1,10}:\d{1,10}$/.test(v ?? "")) bad(`${name} is malformed`);
  // security options: no-new-privileges exactly once, an optional seccomp profile that is a real path (never unconfined)
  const secOpts = values.get("--security-opt") ?? [];
  if (secOpts.filter((v) => v === "no-new-privileges").length !== 1)
    bad("--security-opt=no-new-privileges must appear exactly once");
  let seccomp = 0;
  for (const v of secOpts) {
    if (v === "no-new-privileges") continue;
    if (v?.startsWith("seccomp=") && isSafeAbsolutePath(v.slice(8)) && !/unconfined/i.test(v)) {
      seccomp += 1;
      if (config && config.seccompProfile && v.slice(8) !== config.seccompProfile)
        bad("seccomp profile differs from the configured one");
    } else bad("--security-opt has a forbidden value");
  }
  if (seccomp > 1) bad("--security-opt seccomp repeated");
  if (config && config.seccompProfile && seccomp !== 1)
    bad("the configured seccomp profile is missing");
  // limits: present and consistent
  once("--pids-limit");
  once("--memory");
  once("--memory-swap");
  once("--cpus");
  if (!/^[1-9]\d{0,6}$/.test(values.get("--pids-limit")?.[0] ?? ""))
    bad("--pids-limit must be a positive integer");
  const mem = values.get("--memory")?.[0];
  if (!/^[1-9]\d{0,7}m$/.test(mem ?? "")) bad("--memory must be a positive number of MiB");
  if (values.get("--memory-swap")?.[0] !== mem) bad("--memory-swap must equal --memory");
  if (!/^(?:[1-9]\d{0,2}|0\.\d{1,2}|[1-9]\d{0,2}\.\d{1,2})$/.test(values.get("--cpus")?.[0] ?? ""))
    bad("--cpus must be a positive number");
  const ulimits = values.get("--ulimit") ?? [];
  for (const kind of ["nofile", "fsize", "core"])
    if (ulimits.filter((u) => u?.startsWith(`${kind}=`)).length !== 1)
      bad(`--ulimit ${kind} must appear exactly once`);
  if (ulimits.some((u) => !/^(nofile|fsize|core)=\d+:\d+$/.test(u ?? "")))
    bad("--ulimit has a forbidden value");
  // tmpfs: /tmp only, noexec,nosuid,nodev and a size
  const tmpfs = values.get("--tmpfs") ?? [];
  if (
    tmpfs.length !== 1 ||
    !/^\/tmp:rw,noexec,nosuid,nodev,mode=1777,size=[1-9]\d{0,6}m$/.test(tmpfs[0] ?? "")
  )
    bad("--tmpfs must be exactly /tmp with noexec,nosuid,nodev and a size");
  // labels
  const labels = values.get("--label") ?? [];
  if (!labels.includes(`${LABEL_KEYS.scan}=1`)) bad("label qm.scan=1 is missing");
  for (const key of Object.values(LABEL_KEYS))
    if (labels.filter((x) => x?.startsWith(`${key}=`)).length !== 1)
      bad(`label ${key} must appear exactly once`);
  if (labels.some((x) => !/^qm\.[a-z]+=[A-Za-z0-9._-]{1,64}$/.test(x ?? "")))
    bad("a label is malformed");
  if (labels.some((x) => !Object.values(LABEL_KEYS).includes((x ?? "").split("=")[0])))
    bad("a label key is not one the runner writes");
  // mounts: bind, read-only, fixed targets, safe sources inside the configured roots; nothing else
  const mounts = values.get("--mount") ?? [];
  const seenTargets = new Set();
  for (const m of mounts) {
    const mm = /^type=bind,src=([^,=\s"']+),dst=(\/src|\/db|\/rules),readonly$/.exec(m ?? "");
    if (!mm) {
      bad("--mount must be a read-only bind mount of a known target");
      continue;
    }
    const [, src, dst] = mm;
    if (seenTargets.has(dst)) bad("--mount target repeated");
    seenTargets.add(dst);
    if (!isSafeAbsolutePath(src)) bad("--mount source is not a safe absolute path");
    if (src.split("/").some((seg) => /\.sock$/i.test(seg))) bad("--mount source is a socket");
    if (config) {
      if (isUnderForbiddenRoot(src, /** @type {string[]} */ (config.forbiddenMountRoots)))
        bad("--mount source is inside a forbidden host path");
      const kind = Object.keys(MOUNT_TARGETS).find((k) => MOUNT_TARGETS[k] === dst);
      if (!config.mountRoots[kind].some((r) => src === r || src.startsWith(`${r}/`)))
        bad("--mount source is outside the configured roots");
    }
  }
  if (net !== "none" && seenTargets.has("/src"))
    bad("a networked run must not mount repository content");
  // environment: allowlisted names, static values, no credentials
  const envs = values.get("--env") ?? [];
  const envNames = new Set();
  for (const e of envs) {
    const m = /^([A-Z][A-Z0-9_]*)=(.*)$/s.exec(e ?? "");
    if (!m || !ENV_ALLOWLIST.includes(m[1]) || !ENV_VALUE_PATTERN.test(m[2])) {
      bad("--env name or value is outside the allowlist");
      continue;
    }
    if (envNames.has(m[1])) bad("--env repeated");
    if (m[1] === "HOME" && m[2] !== "/tmp") bad("--env HOME must be /tmp");
    envNames.add(m[1]);
  }
  if (!envNames.has("HOME")) bad("--env HOME is missing");
  // image: a digest reference, directly after the flags
  if (typeof image !== "string" || !IMAGE_DIGEST_PATTERN.test(image))
    bad("the image must be a repository@sha256:<64 hex> digest reference");
  // after the image: the tool argv; repository paths only after the first `--`
  if (findCredentials({ args: args.slice(i + 1) }, "args").length > 0)
    bad("the arguments carry a credential");
  return problems;
}

/**
 * @param {readonly string[]} args
 * @param {Readonly<import("./config.js").SandboxConfig>} [config]
 * @throws {SandboxError} `policy_violation` listing the violated rules
 */
export function assertRunArgsSafe(args, config) {
  const problems = findRunArgsProblems(args, config);
  if (problems.length > 0)
    throw new SandboxError(
      SANDBOX_ERROR_CODES.policyViolation,
      `Run arguments rejected: ${problems.join("; ")}`,
      problems,
    );
}
