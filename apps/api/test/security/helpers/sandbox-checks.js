import { readdirSync, readFileSync } from "node:fs";
import {
  CLI_ENV_ALLOWLIST,
  ENV_ALLOWLIST,
  FakeSandboxRuntime,
  SandboxError,
  buildRunArgs,
  containerNameOf,
  createCapacityGate,
  createCliSandboxRuntime,
  createJanitor,
  createSandboxRunner,
  findRunArgsProblems,
  isValidRepoPath,
  parseInspectLines,
  sanitizeRepoPaths,
  validateRunSpec,
  validateSandboxConfig,
} from "@qmentisai/infra";
import { loadWorkerConfig, ConfigError } from "../../../../workers/src/config.js";

/**
 * Scan engine sandbox, part A (ADR-008 area 18, docs/modules/scan-engines/SPEC.md 14.1 and 16.1 part A): the generated container
 * invocation and the runner, WITHOUT any container, runtime binary or network. Everything runs against the pure functions, a
 * `FakeSandboxRuntime`, and a CLI runtime whose `execFile` is a recording stand-in. What is proved here is the ARGUMENT VECTOR and
 * the runner's behaviour; that a real runtime applies each flag, rootless operation and uid mapping are NOT proved (live checks
 * ENG-L01 to ENG-L05 and ENG-L18).
 * Covered: ENG-S01 (invocation invariants and configuration), ENG-S02 (RunSpec secure by construction and digest-only images; the
 * lock file part belongs to part B), ENG-S03 (execFile only, hostile names never alter argv; the per-tool "ignore repo config"
 * flags and the deny list belong to later parts), ENG-S04 (credentials, runner level), ENG-S10 (no orphans, janitor), ENG-S14
 * (capacity). Deferred to later parts: ENG-S05 to ENG-S09, S11 to S13.
 */

const SANDBOX_DIR = new URL("../../../../../packages/infra/src/sandbox/", import.meta.url);
const DIGEST = (c) => `sha256:${c.repeat(64)}`;
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const throwsCode = (fn, codes) => {
  try {
    fn();
  } catch (e) {
    return e instanceof SandboxError && codes.includes(e.code)
      ? null
      : `threw ${e?.name}/${e?.code}`;
  }
  return "did not throw";
};
const rejects = async (fn, codes) => {
  try {
    await fn();
  } catch (e) {
    return e instanceof SandboxError && codes.includes(e.code)
      ? null
      : `threw ${e?.name}/${e?.code}`;
  }
  return "did not reject";
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const CONFIG_INPUT = Object.freeze({
  runtimeBin: "podman",
  containerUser: "65534:65534",
  usernsMode: "keep-id",
  uidMap: [],
  gidMap: [],
  seccompProfile: "/etc/qm/seccomp.json",
  mountRoots: { archive: ["/tmp/qm-scan"], db: ["/var/lib/qm/db"], rules: ["/opt/qm/rules"] },
  egressNetworks: { db_refresh: "qm-egress" },
});
const config = () => validateSandboxConfig(CONFIG_INPUT);

/** One representative RunSpec per tool of the provisional catalog (SPEC 5.2; images are placeholders, only the shape matters). */
export function toolSpecs(over = {}) {
  const base = (toolId, repo, extra = {}) => ({
    toolId,
    image: `${repo}@${DIGEST("b")}`,
    argv: ["scan"],
    mounts: { archive: "/tmp/qm-scan/tree-1" },
    limits: {
      cpus: 2,
      memoryMiB: 2048,
      pids: 512,
      wallClockSeconds: 300,
      stdoutBytes: 1048576,
      tmpfsMiB: 1024,
    },
    labels: {
      tenantId: "tenant-1",
      executionId: "exec-1",
      taskId: "11111111-aaaa",
      attempt: 1,
      deadlineEpoch: 1790000000,
    },
    ...extra,
  });
  const db = (tool) => ({
    archive: "/tmp/qm-scan/tree-1",
    db: `/var/lib/qm/db/${tool}/${"c".repeat(64)}`,
  });
  const rules = (tool) => ({ archive: "/tmp/qm-scan/tree-1", rules: `/opt/qm/rules/${tool}` });
  return [
    base("syft", "anchore/syft", { env: { SYFT_CHECK_FOR_APP_UPDATE: "false" } }),
    base("trivy", "aquasec/trivy", {
      mounts: db("trivy"),
      env: { TRIVY_CACHE_DIR: "/db", TRIVY_SKIP_VERSION_CHECK: "true" },
    }),
    base("grype", "anchore/grype", {
      mounts: db("grype"),
      env: { GRYPE_DB_CACHE_DIR: "/db", GRYPE_DB_AUTO_UPDATE: "false" },
    }),
    base("osv-scanner", "ghcr.io/google/osv-scanner", {
      mounts: db("osv"),
      env: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: "/db" },
    }),
    base("opengrep", "registry.example.test:5000/qm/opengrep", {
      mounts: rules("opengrep"),
      argv: ["scan", "--disable-nosem"],
      paths: ["src/a.js"],
    }),
    base("bandit", "ghcr.io/pycqa/bandit/bandit", {
      mounts: rules("bandit"),
      argv: ["-r", "/src", "-f", "json"],
    }),
    base("gosec", "ghcr.io/securego/gosec", {
      env: { GOFLAGS: "-mod=readonly", GOPROXY: "off", CGO_ENABLED: "0" },
    }),
    base("gitleaks", "ghcr.io/gitleaks/gitleaks", { mounts: rules("gitleaks") }),
    base("detect-secrets", "registry.example.test:5000/qm/detect-secrets", {
      argv: ["scan", "--all-files"],
      paths: ["a/b.py"],
    }),
    base("block-extractor", "registry.example.test:5000/qm/block-extractor", {
      stdin: JSON.stringify([{ path: "a.js", startLine: 1, endLine: 2 }]),
    }),
    ...(over.extra ?? []),
  ];
}

/** Argv tokens that MUST be present in every scan invocation (exact). */
const REQUIRED_TOKENS = [
  "--rm",
  "--init",
  "--pull=never",
  "--network=none",
  "--read-only",
  "--user=65534:65534",
  "--cap-drop=ALL",
  "--security-opt=no-new-privileges",
  "--security-opt=seccomp=/etc/qm/seccomp.json",
  "--workdir=/tmp",
  "--env=HOME=/tmp",
  "--label=qm.scan=1",
  "--ulimit=core=0:0",
];

/** Flags and values that must never be accepted before the image. */
const FORBIDDEN_ADDITIONS = [
  "--privileged",
  "--privileged=true",
  "--network=host",
  "--network=bridge",
  "--network=container:other",
  "--net=host",
  "--pid=host",
  "--ipc=host",
  "--uts=host",
  "--cgroupns=host",
  "--userns=host",
  "--device=/dev/kvm",
  "--cap-add=SYS_ADMIN",
  "--cap-add=ALL",
  "--security-opt=seccomp=unconfined",
  "--security-opt=apparmor=unconfined",
  "--security-opt=label=disable",
  "--security-opt=systempaths=unconfined",
  "--volume=/:/host",
  "--volume=/var/run/docker.sock:/var/run/docker.sock",
  "-v=/:/host",
  "--mount=type=bind,src=/tmp/qm-scan/tree-1,dst=/src",
  "--mount=type=bind,src=/tmp/qm-scan/tree-1,dst=/src,readonly=false",
  "--mount=type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly",
  "--mount=type=bind,src=/proc,dst=/src,readonly",
  "--mount=type=bind,src=/sys,dst=/db,readonly",
  "--mount=type=bind,src=/home/user,dst=/rules,readonly",
  "--mount=type=bind,src=/tmp/qm-scan/x,dst=/etc,readonly",
  "--mount=type=tmpfs,dst=/work",
  "--env-file=/tmp/x",
  "--env=GITHUB_TOKEN=abc",
  "--env=DATABASE_URL=postgres://u:p@h/d",
  "--env=AWS_SECRET_ACCESS_KEY=abc",
  "--user=0",
  "--user=root",
  "--user=0:0",
  "--pull=always",
  "--entrypoint=/bin/sh",
  "--add-host=evil:1.2.3.4",
  "--group-add=0",
  "--shm-size=64g",
  "--publish=80:80",
  "-p=80:80",
  "--memory-reservation=1m",
  "--oom-kill-disable",
  "--tmpfs=/work:rw,exec",
  "--restart=always",
  "--log-driver=syslog",
];

const imageIndex = (args) => args.findIndex((a, i) => i > 0 && !a.startsWith("-"));

export const SANDBOX_CHECKS = [
  {
    id: "ENG-S01a",
    name: "container invocation invariants (SPEC 6.2, 14.1; no container is started): for every tool of the provisional catalog (plus the networked refresh job) the generated argument vector holds every required flag exactly once (--network=none, --read-only, --cap-drop=ALL, --security-opt=no-new-privileges, a seccomp profile that is not unconfined, a numeric non-root --user, --pids-limit, --memory with an equal --memory-swap, --cpus, --ulimit, a noexec,nosuid,nodev /tmp tmpfs, --pull=never, --init, the labels), only read-only bind mounts of the archive, db and rules at fixed targets, an environment inside the allowlist, a digest image and none of the forbidden flags; the audit refuses a copy of each vector with any required token removed or changed and with each of 46 forbidden additions inserted",
    async run() {
      const p = [];
      const cfg = config();
      for (const spec of toolSpecs()) {
        const args = buildRunArgs(spec, cfg);
        ok(
          p,
          findRunArgsProblems(args, cfg).length === 0,
          `${spec.toolId}: own audit ${findRunArgsProblems(args, cfg).join(",")}`,
        );
        for (const t of REQUIRED_TOKENS)
          ok(
            p,
            args.filter((a) => a === t).length === 1,
            `${spec.toolId}: ${t} count ${args.filter((a) => a === t).length}`,
          );
        const mem = args.find((a) => a.startsWith("--memory="));
        ok(
          p,
          mem && args.includes(mem.replace("--memory=", "--memory-swap=")),
          `${spec.toolId}: memory-swap differs`,
        );
        ok(
          p,
          args.some((a) => /^--pids-limit=[1-9]\d*$/.test(a)),
          `${spec.toolId}: pids`,
        );
        ok(
          p,
          args.some((a) => /^--cpus=\d/.test(a)),
          `${spec.toolId}: cpus`,
        );
        ok(
          p,
          args.filter((a) => a.startsWith("--ulimit=")).length === 3,
          `${spec.toolId}: ulimits`,
        );
        ok(
          p,
          args.filter((a) => a.startsWith("--tmpfs=")).length === 1 &&
            args.some((a) => /^--tmpfs=\/tmp:rw,noexec,nosuid,nodev,/.test(a)),
          `${spec.toolId}: tmpfs`,
        );
        for (const key of ["tenant", "execution", "task", "tool", "attempt", "deadline"])
          ok(
            p,
            args.some((a) => a.startsWith(`--label=qm.${key}=`)),
            `${spec.toolId}: label ${key}`,
          );
        const mounts = args.filter((a) => a.startsWith("--mount="));
        ok(
          p,
          mounts.length >= 1 &&
            mounts.every((m) =>
              /^--mount=type=bind,src=\/[^,]+,dst=\/(src|db|rules),readonly$/.test(m),
            ),
          `${spec.toolId}: mounts ${mounts.join(" ")}`,
        );
        ok(
          p,
          args
            .filter((a) => a.startsWith("--env="))
            .every((e) => ENV_ALLOWLIST.includes(e.slice(6).split("=")[0])),
          `${spec.toolId}: env outside the allowlist`,
        );
        const idx = imageIndex(args);
        ok(
          p,
          args[idx] === spec.image && /@sha256:[0-9a-f]{64}$/.test(args[idx]),
          `${spec.toolId}: image position or digest`,
        );
        ok(
          p,
          args.slice(1, idx).every((a) => a.startsWith("--")),
          `${spec.toolId}: a non-long flag before the image`,
        );
        ok(
          p,
          (spec.stdin !== undefined) === args.includes("--interactive"),
          `${spec.toolId}: --interactive only with stdin`,
        );
        // every required token removed in turn is refused
        for (const t of REQUIRED_TOKENS) {
          const mutated = args.filter((a) => a !== t);
          ok(
            p,
            findRunArgsProblems(mutated, cfg).length > 0,
            `${spec.toolId}: audit accepts a vector without ${t}`,
          );
        }
        for (const prefix of [
          "--pids-limit=",
          "--memory=",
          "--memory-swap=",
          "--cpus=",
          "--tmpfs=",
          "--name=",
          "--workdir=",
          "--ulimit=nofile=",
        ]) {
          const mutated = args.filter((a) => !a.startsWith(prefix));
          ok(
            p,
            findRunArgsProblems(mutated, cfg).length > 0,
            `${spec.toolId}: audit accepts a vector without ${prefix}`,
          );
        }
        for (const prefix of [
          "--label=qm.tenant=",
          "--label=qm.task=",
          "--label=qm.attempt=",
          "--label=qm.deadline=",
        ]) {
          ok(
            p,
            findRunArgsProblems(
              args.filter((a) => !a.startsWith(prefix)),
              cfg,
            ).length > 0,
            `${spec.toolId}: audit accepts a vector without ${prefix}`,
          );
        }
        // changed values
        const changes = [
          ["--network=none", "--network=host"],
          ["--pull=never", "--pull=always"],
          ["--user=65534:65534", "--user=0:0"],
          ["--cap-drop=ALL", "--cap-drop=NET_RAW"],
          ["--security-opt=seccomp=/etc/qm/seccomp.json", "--security-opt=seccomp=unconfined"],
          ["--env=HOME=/tmp", "--env=HOME=/root"],
        ];
        for (const [from, to] of changes)
          ok(
            p,
            findRunArgsProblems(
              args.map((a) => (a === from ? to : a)),
              cfg,
            ).length > 0,
            `${spec.toolId}: audit accepts ${to}`,
          );
        const swap = args.find((a) => a.startsWith("--memory-swap="));
        ok(
          p,
          findRunArgsProblems(
            args.map((a) => (a === swap ? "--memory-swap=999999m" : a)),
            cfg,
          ).length > 0,
          `${spec.toolId}: swap differing from memory accepted`,
        );
        ok(
          p,
          findRunArgsProblems(
            args.map((a) => (a.startsWith("--tmpfs=") ? a.replace("noexec", "exec") : a)),
            cfg,
          ).length > 0,
          `${spec.toolId}: exec tmpfs accepted`,
        );
        ok(
          p,
          findRunArgsProblems(
            args.map((a) => (a.startsWith("--mount=") ? a.replace(",readonly", "") : a)),
            cfg,
          ).length > 0,
          `${spec.toolId}: writable mount accepted`,
        );
        ok(
          p,
          findRunArgsProblems(
            args.map((a) => (a === spec.image ? "aquasec/trivy:latest" : a)),
            cfg,
          ).length > 0,
          `${spec.toolId}: tag image accepted`,
        );
        ok(
          p,
          findRunArgsProblems(
            args.map((a) =>
              a === spec.image ? `${spec.image.split("@")[0]}:1.2@${DIGEST("b")}` : a,
            ),
            cfg,
          ).length > 0,
          `${spec.toolId}: tag+digest image accepted`,
        );
        // forbidden additions, inserted before the image
        for (const extra of FORBIDDEN_ADDITIONS) {
          const mutated = [...args.slice(0, idx), extra, ...args.slice(idx)];
          ok(
            p,
            findRunArgsProblems(mutated, cfg).length > 0,
            `${spec.toolId}: audit accepts ${extra}`,
          );
        }
      }
      // the refresh job: the only networked run, a dedicated network, never repository content
      const refresh = toolSpecs()[0];
      const net = {
        ...refresh,
        toolId: "dbrefresh",
        mounts: { db: "/var/lib/qm/db/trivy/stage" },
        networkPurpose: "db_refresh",
      };
      const netArgs = buildRunArgs(net, config());
      ok(
        p,
        netArgs.includes("--network=qm-egress") && !netArgs.includes("--network=none"),
        "refresh job network",
      );
      ok(p, findRunArgsProblems(netArgs, config()).length === 0, "refresh job audit");
      ok(
        p,
        findRunArgsProblems(
          netArgs.map((a) => (a === "--network=qm-egress" ? "--network=other" : a)),
          config(),
        ).length > 0,
        "unconfigured network accepted",
      );
      ok(
        p,
        findRunArgsProblems(netArgs, validateSandboxConfig({ ...CONFIG_INPUT, egressNetworks: {} }))
          .length > 0,
        "network accepted without a configured egress network",
      );
      // determinism: the same input gives the same vector
      ok(
        p,
        JSON.stringify(buildRunArgs(toolSpecs()[1], cfg)) ===
          JSON.stringify(buildRunArgs(toolSpecs()[1], cfg)),
        "builder is not deterministic",
      );
      // without a seccomp profile configured the flag is absent, never "unconfined"
      const plain = validateSandboxConfig({ ...CONFIG_INPUT, seccompProfile: null });
      const plainArgs = buildRunArgs(toolSpecs()[0], plain);
      ok(
        p,
        !plainArgs.some((a) => /seccomp/.test(a)) &&
          findRunArgsProblems(plainArgs, plain).length === 0,
        "no-seccomp configuration",
      );
      // ---- mutation-sweep hardening: rules that must stand alone, one at a time -------------------------------------------
      {
        const spec = toolSpecs()[1];
        const vec = buildRunArgs(spec, cfg);
        const bare = (a) => findRunArgsProblems(a);
        const idx0 = imageIndex(vec);
        // every environment entry of the spec is rendered, HOME once
        for (const s of toolSpecs())
          for (const [k, v] of Object.entries(s.env ?? {}))
            ok(
              p,
              buildRunArgs(s, cfg).includes(`--env=${k}=${v}`),
              `${s.toolId}: env ${k} not rendered`,
            );
        const withHome = buildRunArgs({ ...spec, env: { ...spec.env, HOME: "/tmp" } }, cfg);
        ok(
          p,
          withHome.filter((a) => a.startsWith("--env=HOME=")).length === 1 &&
            withHome.includes("--env=TRIVY_CACHE_DIR=/db"),
          "HOME rendered once beside other env",
        );
        ok(
          p,
          !buildRunArgs({ ...spec, paths: [] }, cfg).includes("--"),
          "an empty path list still added the separator",
        );
        ok(
          p,
          buildRunArgs({ ...spec, paths: ["a.js"] }, cfg).includes("--"),
          "paths without the separator",
        );
        // shape of the audited input
        ok(
          p,
          bare("not an array").length > 0 && bare([1, 2]).length > 0 && bare(["run", 5]).length > 0,
          "audit accepted a non-array or non-string input",
        );
        ok(
          p,
          bare(["create", ...vec.slice(1)]).length > 0 && bare(vec.slice(1)).length > 0,
          "audit accepted a vector that does not start with run",
        );
        ok(
          p,
          bare(vec.slice(0, idx0)).length > 0 && bare(["run", ...vec.slice(1, idx0)]).length > 0,
          "audit accepted a vector without an image",
        );
        const without = (prefix) => vec.filter((a) => !a.startsWith(prefix));
        const set = (prefix, value) => vec.map((a) => (a.startsWith(prefix) ? value : a));
        // name
        ok(p, bare(without("--name=")).length > 0, "no --name accepted");
        for (const n of ["--name=x y", "--name=-bad", "--name=a;b", "--name="])
          ok(p, bare(set("--name=", n)).length > 0, `name ${n} accepted`);
        // user, with and without a configuration
        for (const u of [
          "--user=0:0",
          "--user=root",
          "--user=65534",
          "--user=0:65534",
          "--user=65534:0",
        ])
          ok(p, bare(set("--user=", u)).length > 0, `bare audit accepted ${u}`);
        ok(
          p,
          findRunArgsProblems(set("--user=", "--user=1000:1000"), cfg).length > 0,
          "a user other than the configured one accepted",
        );
        ok(
          p,
          bare(set("--user=", "--user=1000:1000")).length === 0,
          "control: another numeric non-root user is fine without a configuration",
        );
        // interactive only once
        const inter = buildRunArgs(
          toolSpecs().find((s) => s.stdin !== undefined),
          cfg,
        );
        ok(
          p,
          bare([...inter.slice(0, 1), "--interactive", ...inter.slice(1)]).length > 0,
          "--interactive twice accepted",
        );
        // user namespace: never host, never repeated
        const plain = validateSandboxConfig({ ...CONFIG_INPUT, usernsMode: null });
        const pv = buildRunArgs(spec, plain);
        const pi = imageIndex(pv);
        const addTo = (v, extra) => [
          ...v.slice(0, imageIndex(v)),
          ...extra,
          ...v.slice(imageIndex(v)),
        ];
        ok(p, findRunArgsProblems(pv, plain).length === 0, "control: no userns");
        for (const u of ["--userns=host", "--userns=container:x", "--userns=", "--userns=private"])
          ok(p, bare(addTo(pv, [u])).length > 0, `${u} accepted`);
        ok(p, bare(addTo(vec, ["--userns=keep-id"])).length > 0, "--userns repeated accepted");
        ok(p, bare(addTo(pv, ["--userns=keep-id"])).length === 0, "control: one valid userns");
        ok(
          p,
          bare(addTo(pv, ["--userns=keep-id", "--userns=auto"])).length > 0,
          "two userns accepted",
        );
        ok(p, pi > 0, "plain vector");
        // seccomp without a configuration: never unconfined, never relative or traversing, never repeated
        for (const s of [
          "--security-opt=seccomp=unconfined",
          "--security-opt=seccomp=profile.json",
          "--security-opt=seccomp=/etc/qm/../x.json",
          "--security-opt=seccomp=",
        ])
          ok(p, bare(set("--security-opt=seccomp=", s)).length > 0, `bare audit accepted ${s}`);
        ok(
          p,
          bare(addTo(vec, ["--security-opt=seccomp=/etc/qm/other.json"])).length > 0,
          "two seccomp options accepted",
        );
        ok(
          p,
          bare(set("--security-opt=seccomp=", "--security-opt=seccomp=/etc/qm/other.json"))
            .length === 0,
          "control: another safe profile without a configuration",
        );
        // each once-only flag duplicated (same and different value) and its value shape
        for (const prefix of [
          "--rm",
          "--init",
          "--read-only",
          "--pull=",
          "--cap-drop=",
          "--workdir=",
          "--name=",
          "--network=",
          "--user=",
          "--pids-limit=",
          "--memory=",
          "--memory-swap=",
          "--cpus=",
        ]) {
          const flag = vec.find((a) => a === prefix || a.startsWith(prefix));
          ok(p, bare(addTo(vec, [flag])).length > 0, `duplicate ${prefix} accepted`);
        }
        ok(
          p,
          bare(addTo(vec, ["--pids-limit=1"])).length > 0 &&
            bare(addTo(vec, ["--cpus=1"])).length > 0 &&
            bare(addTo(vec, ["--memory=1m"])).length > 0 &&
            bare(addTo(vec, ["--memory-swap=1m"])).length > 0,
          "a second limit with another value accepted",
        );
        for (const [name, bad] of [
          [
            "--pids-limit=",
            ["--pids-limit=0", "--pids-limit=-1", "--pids-limit=abc", "--pids-limit=1e9"],
          ],
          ["--cpus=", ["--cpus=0", "--cpus=-1", "--cpus=abc", "--cpus=1000"]],
        ])
          for (const b of bad) ok(p, bare(set(name, b)).length > 0, `${b} accepted`);
        for (const m of ["9x", "0m", "-1m", "1g", "abc", "999999999m"]) {
          const mutated = vec.map((a) =>
            a.startsWith("--memory=")
              ? `--memory=${m}`
              : a.startsWith("--memory-swap=")
                ? `--memory-swap=${m}`
                : a,
          );
          ok(p, bare(mutated).length > 0, `memory ${m} accepted`);
        }
        ok(
          p,
          bare(vec.filter((a) => !a.startsWith("--ulimit=fsize="))).length > 0 &&
            bare(vec.filter((a) => !a.startsWith("--ulimit=core="))).length > 0,
          "a missing ulimit accepted",
        );
        ok(
          p,
          bare(addTo(vec, ["--ulimit=nproc=1:1"])).length > 0 &&
            bare(addTo(vec, ["--ulimit=core=0:0"])).length > 0,
          "an extra ulimit accepted",
        );
        ok(
          p,
          bare(addTo(vec, ["--tmpfs=/tmp:rw,noexec,nosuid,nodev,mode=1777,size=1m"])).length > 0,
          "a second tmpfs accepted",
        );
        // labels: qm.scan must be 1, each key once, values shaped
        ok(p, bare(set("--label=qm.scan=", "--label=qm.scan=0")).length > 0, "qm.scan=0 accepted");
        ok(
          p,
          bare(addTo(vec, ["--label=qm.task=other"])).length > 0 &&
            bare(addTo(vec, ["--label=qm.extra=1"])).length > 0,
          "an extra or repeated label accepted",
        );
        ok(
          p,
          bare(set("--label=qm.task=", "--label=qm.task=a b")).length > 0,
          "a malformed label value accepted",
        );
        // mounts
        const m0 = vec.find((a) => a.startsWith("--mount=") && a.includes("dst=/src"));
        const swapMount = (src) =>
          vec.map((a) => (a === m0 ? `--mount=type=bind,src=${src},dst=/src,readonly` : a));
        ok(p, bare(addTo(vec, [m0])).length > 0, "a repeated mount target accepted");
        for (const src of [
          "/tmp/qm-scan/../../etc",
          "/tmp/qm-scan/./a",
          "/tmp/qm-scan//a",
          "/tmp/qm-scan/a/",
          "tmp/qm-scan/a",
          "/tmp/qm-scan/x.sock",
          "/tmp/qm-scan/x.sock/tree",
        ]) {
          ok(p, bare(swapMount(src)).length > 0, `bare audit accepted mount ${src}`);
          ok(p, findRunArgsProblems(swapMount(src), cfg).length > 0, `audit accepted mount ${src}`);
        }
        ok(
          p,
          findRunArgsProblems(swapMount("/tmp/qm-scan"), cfg).length === 0,
          "control: the mount root itself is a valid source",
        );
        ok(
          p,
          findRunArgsProblems(swapMount("/tmp/qm-scan-evil/t"), cfg).length > 0 &&
            findRunArgsProblems(swapMount("/tmp/qm-scan2"), cfg).length > 0,
          "a look-alike root accepted",
        );
        ok(
          p,
          buildRunArgs(
            { ...spec, mounts: { ...spec.mounts, archive: "/tmp/qm-scan" } },
            cfg,
          ).includes("--mount=type=bind,src=/tmp/qm-scan,dst=/src,readonly"),
          "a source equal to the root was refused by the builder",
        );
        // environment
        ok(
          p,
          bare(addTo(vec, ["--env=GOFLAGS=-mod=readonly"])).length === 0,
          "control: another allowlisted env",
        );
        ok(
          p,
          bare(addTo(vec, ["--env=TRIVY_CACHE_DIR=/db"])).length > 0 &&
            bare(addTo(vec, ["--env=HOME=/tmp"])).length > 0,
          "a repeated env accepted",
        );
        ok(p, bare(vec.filter((a) => !a.startsWith("--env=HOME="))).length > 0, "no HOME accepted");
        for (const e of [
          "--env=lower=1",
          "--env=LD_PRELOAD=/x",
          "--env=GOFLAGS=a b",
          '--env=GOFLAGS="x"',
          "--env=GOFLAGS",
          "--env=GOFLAGS=;",
        ])
          ok(p, bare(addTo(vec, [e])).length > 0, `${e} accepted`);
        // credentials in the arguments after the image (first and later elements)
        for (const secret of ["ghp_abcdefghijklmnopqrstuvwxyz0123456789", "AKIAABCDEFGHIJKLMNOP"]) {
          ok(
            p,
            bare([...vec.slice(0, idx0 + 1), secret, ...vec.slice(idx0 + 1)]).length > 0 &&
              bare([...vec, secret]).length > 0,
            `a credential after the image accepted (${secret.slice(0, 4)})`,
          );
          ok(
            p,
            throwsCode(
              () => buildRunArgs({ ...spec, argv: [secret] }, cfg),
              ["policy_violation"],
            ) === null,
            "a credential as the first argument accepted",
          );
        }
      }
      return p;
    },
  },
  {
    id: "ENG-S01b",
    name: "sandbox configuration fails fast and names no value (SPEC 16.1 part A, D-20): the runtime binary is docker or podman only (never a path or a shell), the container user is numeric and non-root, the user namespace mode is never host, id maps are n:n:n, the seccomp profile is a safe absolute path and never unconfined, mount roots are not forbidden host roots, egress networks are dedicated names; the worker configuration defaults the rollout flag SCAN_ENGINES_ENSEMBLE_ENABLED to false, accepts true, refuses other values, and refuses each invalid sandbox setting with a ConfigError that names the variable and never the offending value; nothing in the sandbox assumes a rootful runtime (docker and podman, with and without a user namespace mode, both build audited vectors)",
    async run() {
      const p = [];
      const badInputs = [
        { runtimeBin: "/bin/sh" },
        { runtimeBin: "docker; rm -rf /" },
        { containerUser: "0:0" },
        { containerUser: "root" },
        { containerUser: "65534" },
        { usernsMode: "host" },
        { uidMap: ["x"] },
        { gidMap: ["0:0"] },
        { seccompProfile: "relative.json" },
        { seccompProfile: "/etc/qm/unconfined.json" },
        { mountRoots: { archive: ["/"], db: [], rules: [] } },
        { mountRoots: { archive: ["/proc"], db: [], rules: [] } },
        { mountRoots: { archive: ["/var/run/docker"], db: [], rules: [] } },
        { mountRoots: { archive: ["/tmp/a b"], db: [], rules: [] } },
        { egressNetworks: { db_refresh: "host" } },
        { egressNetworks: { db_refresh: "none" } },
        { egressNetworks: { other: "net1" } },
        { ceilings: { cpus: 0 } },
        { cliTimeoutMs: 5 },
      ];
      for (const bad of badInputs) {
        const e = throwsCode(
          () => validateSandboxConfig({ ...CONFIG_INPUT, ...bad }),
          ["invalid_config"],
        );
        ok(p, e === null, `config ${JSON.stringify(bad).slice(0, 60)}: ${e}`);
      }
      try {
        validateSandboxConfig({ ...CONFIG_INPUT, containerUser: "secret-value-0:0" });
      } catch (e) {
        ok(p, !String(e.message).includes("secret-value"), "config error echoes a value");
      }
      for (const bin of ["docker", "podman"])
        for (const usernsMode of [null, "keep-id", "auto", "nomap"]) {
          const c = validateSandboxConfig({ ...CONFIG_INPUT, runtimeBin: bin, usernsMode });
          const a = buildRunArgs(toolSpecs()[0], c);
          ok(p, findRunArgsProblems(a, c).length === 0, `${bin}/${usernsMode}: audit`);
          ok(
            p,
            usernsMode
              ? a.includes(`--userns=${usernsMode}`)
              : !a.some((x) => x.startsWith("--userns")),
            `${bin}/${usernsMode}: userns flag`,
          );
        }
      const withMaps = validateSandboxConfig({
        ...CONFIG_INPUT,
        uidMap: ["0:1:1", "1:100000:65536"],
        gidMap: ["0:1:1"],
      });
      const mapped = buildRunArgs(toolSpecs()[0], withMaps);
      ok(
        p,
        mapped.includes("--uidmap=0:1:1") && mapped.includes("--gidmap=0:1:1"),
        "uid/gid maps are rendered from configuration",
      );
      // worker configuration
      const base = {
        RABBITMQ_URL: "amqp://localhost",
        DATABASE_URL: "postgres://localhost/qm_test",
      };
      const def = loadWorkerConfig(base);
      ok(p, def.scanEngines.ensembleEnabled === false, "rollout flag is not off by default");
      ok(
        p,
        loadWorkerConfig({
          ...base,
          SCAN_ENGINES_ENSEMBLE_ENABLED: "true",
          SANDBOX_ARCHIVE_ROOT: "/var/lib/qm/scan",
          SANDBOX_RULES_DIR: "/var/lib/qm/rules",
        }).scanEngines.ensembleEnabled === true,
        "flag true not honoured",
      );
      ok(
        p,
        def.scanEngines.sandbox.runtimeBin === "podman" &&
          def.scanEngines.sandbox.containerUser === "65534:65534",
        "sandbox defaults",
      );
      for (const [variable, value] of [
        ["SCAN_ENGINES_ENSEMBLE_ENABLED", "yes"],
        ["SANDBOX_RUNTIME_BIN", "/bin/sh"],
        ["SANDBOX_USER", "0:0"],
        ["SANDBOX_USERNS_MODE", "host"],
        ["SANDBOX_UIDMAP", "not-a-map"],
        ["SANDBOX_SECCOMP_PROFILE", "../relative"],
        ["SANDBOX_STDOUT_MAX_BYTES", "12"],
      ]) {
        try {
          loadWorkerConfig({ ...base, [variable]: value });
          p.push(`${variable}=${value} was accepted`);
        } catch (e) {
          ok(p, e instanceof ConfigError, `${variable}: not a ConfigError`);
          ok(
            p,
            !String(e.message).includes(value) || value.length < 3,
            `${variable}: the message echoes the value`,
          );
          ok(
            p,
            e.problems.some(
              (x) => x.variable.includes(variable) || x.variable.includes("SANDBOX_*"),
            ),
            `${variable}: not named`,
          );
        }
      }
      // ---- mutation-sweep hardening: configuration boundaries ---------------------------------------------------------------
      for (const bad of [null, [], "x", 5, undefined])
        ok(
          p,
          throwsCode(() => validateSandboxConfig(bad), ["invalid_config"]) === null,
          `config ${JSON.stringify(bad)} accepted`,
        );
      const good = (over) =>
        throwsCode(() => validateSandboxConfig({ ...CONFIG_INPUT, ...over }), []) ===
        "did not throw";
      ok(p, good({ uidMap: Array.from({ length: 8 }, () => "0:1:1") }), "eight id maps refused");
      ok(
        p,
        !good({ uidMap: Array.from({ length: 9 }, () => "0:1:1") }) &&
          !good({ uidMap: "0:1:1" }) &&
          !good({ uidMap: [5] }),
        "nine, non-array or non-string id maps accepted",
      );
      ok(
        p,
        !good({ forbiddenMountRoots: "x" }) &&
          !good({ forbiddenMountRoots: ["rel"] }) &&
          !good({ forbiddenMountRoots: [5] }) &&
          good({ forbiddenMountRoots: ["/etc"] }),
        "forbiddenMountRoots validation",
      );
      ok(
        p,
        good({ ceilings: { cpus: 64 } }) &&
          !good({ ceilings: { cpus: 65 } }) &&
          !good({ ceilings: { cpus: -1 } }) &&
          !good({ ceilings: { cpus: "4" } }) &&
          !good({ ceilings: { cpus: Number.NaN } }),
        "ceiling bounds",
      );
      for (const [key, lo, hi] of [
        ["stderrBytes", 1024, 4194304],
        ["cliTimeoutMs", 1000, 600000],
        ["killGraceMs", 100, 120000],
      ]) {
        ok(p, good({ [key]: lo }) && good({ [key]: hi }), `${key} bounds refused`);
        ok(
          p,
          !good({ [key]: lo - 1 }) &&
            !good({ [key]: hi + 1 }) &&
            !good({ [key]: lo + 0.5 }) &&
            !good({ [key]: "5000" }),
          `${key} out-of-range accepted`,
        );
      }
      ok(
        p,
        good({ mountRoots: { archive: ["/tmp/qm-scan"] } }) &&
          !good({ mountRoots: "x" }) &&
          !good({ mountRoots: { archive: "x" } }),
        "mountRoots shape",
      );
      return p;
    },
  },
  {
    id: "ENG-S02a",
    name: "RunSpec is secure by construction and the image is a digest only (SPEC 6.2, 14.1; the lock file consistency belongs to part B): unknown keys are refused (network, privileged, user, devices, capAdd, volumes, entrypoint, securityOpt, pid, envFile, extra mounts), a tag, a tag with a digest, a missing, short, upper-case or non-sha256 digest, a bare name and a hostile string are refused, mounts must be safe absolute paths inside the configured root of their kind and never a forbidden host path, a runtime socket, a path with option-injecting characters or relative, env names outside the allowlist and non-static values are refused, limits above the ceilings or non-positive are refused, a network purpose needs a configured network and never mounts repository content; a valid spec passes and the validated copy is frozen and detached from the input",
    async run() {
      const p = [];
      const cfg = config();
      const good = toolSpecs()[1];
      ok(
        p,
        throwsCode(() => validateRunSpec(good, cfg), []) === "did not throw",
        "control: a valid spec is refused",
      );
      const frozen = validateRunSpec(good, cfg);
      ok(
        p,
        Object.isFrozen(frozen) && Object.isFrozen(frozen.limits) && frozen !== good,
        "validated spec is not a frozen copy",
      );
      const refuse = (label, spec) => {
        const e = throwsCode(() => buildRunArgs(spec, cfg), ["invalid_spec", "policy_violation"]);
        ok(p, e === null, `${label}: ${e}`);
      };
      for (const key of [
        "network",
        "privileged",
        "user",
        "devices",
        "capAdd",
        "volumes",
        "entrypoint",
        "securityOpt",
        "pid",
        "ipc",
        "envFile",
        "readOnly",
        "seccomp",
        "memorySwap",
        "extraMounts",
        "command",
      ])
        refuse(`extra key ${key}`, { ...good, [key]: key === "privileged" ? true : "x" });
      refuse("extra mount kind", {
        ...good,
        mounts: { ...good.mounts, home: "/tmp/qm-scan/home" },
      });
      refuse("extra limit key", { ...good, limits: { ...good.limits, swap: 1 } });
      refuse("extra label key", { ...good, labels: { ...good.labels, extra: "x" } });
      const img = (image) => refuse(`image ${image.slice(0, 40)}`, { ...good, image });
      img("aquasec/trivy:latest");
      img("aquasec/trivy");
      img("aquasec/trivy:0.76.2@" + DIGEST("a"));
      img("aquasec/trivy@sha256:abc");
      img("aquasec/trivy@sha256:" + "A".repeat(64));
      img("aquasec/trivy@sha512:" + "a".repeat(128));
      img("aquasec/trivy@sha256:" + "a".repeat(65));
      img("Aquasec/Trivy@" + DIGEST("a"));
      img("aquasec/trivy@" + DIGEST("a") + " --privileged");
      img("--privileged@" + DIGEST("a"));
      img("");
      refuse("image not a string", { ...good, image: 5 });
      const mount = (label, mounts) => refuse(`mount ${label}`, { ...good, mounts });
      mount("root", { archive: "/" });
      mount("proc", { archive: "/proc" });
      mount("sys", { archive: "/sys/kernel" });
      mount("etc", { archive: "/etc" });
      mount("home", { archive: "/home/user" });
      mount("socket", { archive: "/tmp/qm-scan/docker.sock" });
      mount("socket dir", { archive: "/tmp/qm-scan/x.sock/tree" });
      mount("outside the root", { archive: "/tmp/other" });
      mount("prefix lookalike", { archive: "/tmp/qm-scan-evil/tree" });
      mount("comma injection", { archive: "/tmp/qm-scan/a,dst=/etc" });
      mount("equals", { archive: "/tmp/qm-scan/a=b" });
      mount("space", { archive: "/tmp/qm-scan/a b" });
      mount("newline", { archive: "/tmp/qm-scan/a\nb" });
      mount("relative", { archive: "tmp/qm-scan/a" });
      mount("traversal", { archive: "/tmp/qm-scan/../../etc" });
      mount("db under the archive root", { archive: "/tmp/qm-scan/t", db: "/tmp/qm-scan/db" });
      mount("rules under the db root", {
        archive: "/tmp/qm-scan/t",
        rules: "/var/lib/qm/db/rules",
      });
      mount("none", {});
      mount("not an object", "/tmp/qm-scan/a");
      mount("non-string source", { archive: ["/tmp/qm-scan/a"] });
      refuse("env name", { ...good, env: { GITHUB_TOKEN: "x" } });
      refuse("env LD_PRELOAD", { ...good, env: { LD_PRELOAD: "/x" } });
      refuse("env value space", { ...good, env: { GOFLAGS: "-a -b" } });
      refuse("env value quote", { ...good, env: { GOFLAGS: '"x"' } });
      refuse("env value newline", { ...good, env: { GOFLAGS: "a\nb" } });
      refuse("env value long", { ...good, env: { GOFLAGS: "a".repeat(300) } });
      for (const [k, v] of [
        ["cpus", 0],
        ["cpus", 99],
        ["cpus", Number.NaN],
        ["memoryMiB", 0],
        ["memoryMiB", 999999],
        ["memoryMiB", 1.5],
        ["pids", 0],
        ["pids", 99999],
        ["wallClockSeconds", 0],
        ["wallClockSeconds", 99999],
        ["stdoutBytes", 0],
        ["stdoutBytes", 9e9],
        ["tmpfsMiB", 0],
        ["tmpfsMiB", 99999],
        ["nofile", 0],
        ["cpus", "2"],
        ["pids", -1],
      ])
        refuse(`limit ${k}=${v}`, { ...good, limits: { ...good.limits, [k]: v } });
      for (const k of [
        "cpus",
        "memoryMiB",
        "pids",
        "wallClockSeconds",
        "stdoutBytes",
        "tmpfsMiB",
      ]) {
        const limits = { ...good.limits };
        delete limits[k];
        refuse(`missing limit ${k}`, { ...good, limits });
      }
      refuse("label tenant", { ...good, labels: { ...good.labels, tenantId: "a b" } });
      refuse("label task newline", { ...good, labels: { ...good.labels, taskId: "x\ny" } });
      refuse("attempt 0", { ...good, labels: { ...good.labels, attempt: 0 } });
      refuse("attempt string", { ...good, labels: { ...good.labels, attempt: "1" } });
      refuse("deadline", { ...good, labels: { ...good.labels, deadlineEpoch: -1 } });
      refuse("toolId", { ...good, toolId: "Bad Tool" });
      refuse("tool id long", { ...good, toolId: "a".repeat(40) });
      refuse("network purpose unknown", { ...good, networkPurpose: "scan" });
      refuse("network purpose with the archive", { ...good, networkPurpose: "db_refresh" });
      ok(
        p,
        throwsCode(
          () =>
            buildRunArgs(
              { ...good, mounts: { db: "/var/lib/qm/db/trivy/x" }, networkPurpose: "db_refresh" },
              validateSandboxConfig({ ...CONFIG_INPUT, egressNetworks: {} }),
            ),
          ["policy_violation"],
        ) === null,
        "network purpose without a configured network",
      );
      refuse("argv separator", { ...good, argv: ["scan", "--"] });
      refuse("argv control", { ...good, argv: ["a\u0007"] });
      refuse("argv object", { ...good, argv: [{ toString: () => "x" }] });
      refuse("argv too long", { ...good, argv: Array.from({ length: 300 }, () => "a") });
      refuse("stdin too big", { ...good, stdin: "x".repeat(1048577) });
      refuse("stdin not a string", { ...good, stdin: { a: 1 } });
      refuse("spec null", null);
      refuse("spec array", []);
      // prototype pollution style keys
      refuse("__proto__ key", JSON.parse(`{"__proto__":{"user":"0"},"toolId":"x"}`));
      // the input is never mutated
      const before = JSON.stringify(good);
      validateRunSpec(good, cfg);
      ok(p, JSON.stringify(good) === before, "validation mutated its input");
      // ---- mutation-sweep hardening: each rule of validateRunSpec on its own, and the boundaries ------------------------------
      {
        const direct = (label, spec, c = cfg) => {
          const e = throwsCode(
            () => validateRunSpec(spec, c),
            ["invalid_spec", "policy_violation"],
          );
          ok(p, e === null, `direct ${label}: ${e}`);
        };
        const accepts = (label, spec) => {
          const e = throwsCode(() => validateRunSpec(spec, cfg), []);
          ok(p, e === "did not throw", `direct control ${label}: refused`);
        };
        const L = good.limits;
        direct("image number", { ...good, image: 5 });
        direct("image tag", { ...good, image: "aquasec/trivy:latest" });
        direct("mounts null", { ...good, mounts: null });
        direct("mounts string", { ...good, mounts: "/tmp/qm-scan/a" });
        direct("mounts array", { ...good, mounts: [] });
        direct("socket mount", { ...good, mounts: { archive: "/tmp/qm-scan/docker.sock" } });
        direct("socket dir mount", { ...good, mounts: { archive: "/tmp/qm-scan/x.sock/tree" } });
        direct("mount outside root", { ...good, mounts: { archive: "/tmp/elsewhere" } });
        direct("mount source number", { ...good, mounts: { archive: 5 } });
        direct("env array", { ...good, env: ["HOME=/tmp"] });
        direct("env string", { ...good, env: "x" });
        direct("env name", { ...good, env: { PATH: "/usr/bin" } });
        direct("env value", { ...good, env: { GOFLAGS: "a b" } });
        direct("env value number", { ...good, env: { GOFLAGS: 5 } });
        direct("env HOME", { ...good, env: { HOME: "/root" } });
        accepts("env HOME /tmp", { ...good, env: { HOME: "/tmp" } });
        direct("limits null", { ...good, limits: null });
        direct("limits array", { ...good, limits: [] });
        direct("labels null", { ...good, labels: null });
        direct("labels string", { ...good, labels: "x" });
        direct("label number", { ...good, labels: { ...good.labels, tenantId: 5 } });
        direct("label empty", { ...good, labels: { ...good.labels, executionId: "" } });
        direct("attempt 0", { ...good, labels: { ...good.labels, attempt: 0 } });
        direct("attempt 1001", { ...good, labels: { ...good.labels, attempt: 1001 } });
        accepts("attempt 1", { ...good, labels: { ...good.labels, attempt: 1 } });
        accepts("attempt 1000", { ...good, labels: { ...good.labels, attempt: 1000 } });
        direct("deadline 0", { ...good, labels: { ...good.labels, deadlineEpoch: 0 } });
        direct("deadline fraction", { ...good, labels: { ...good.labels, deadlineEpoch: 1.5 } });
        accepts("deadline 1", { ...good, labels: { ...good.labels, deadlineEpoch: 1 } });
        direct("purpose unknown", { ...good, networkPurpose: "scan" });
        direct(
          "purpose without network",
          { ...good, mounts: { db: "/var/lib/qm/db/trivy/x" }, networkPurpose: "db_refresh" },
          validateSandboxConfig({ ...CONFIG_INPUT, egressNetworks: {} }),
        );
        direct("purpose with archive", { ...good, networkPurpose: "db_refresh" });
        accepts("purpose valid", {
          ...good,
          mounts: { db: "/var/lib/qm/db/trivy/x" },
          networkPurpose: "db_refresh",
        });
        accepts("mount equal to the root", { ...good, mounts: { archive: "/tmp/qm-scan" } });
        // boundaries
        accepts("argv 256", { ...good, argv: Array.from({ length: 256 }, () => "a") });
        direct("argv 257", { ...good, argv: Array.from({ length: 257 }, () => "a") });
        accepts("arg 1024", { ...good, argv: ["a".repeat(1024)] });
        direct("arg 1025", { ...good, argv: ["a".repeat(1025)] });
        accepts("paths 2000", { ...good, paths: Array.from({ length: 2000 }, (_, i) => `f${i}`) });
        direct("paths 2001", { ...good, paths: Array.from({ length: 2001 }, (_, i) => `f${i}`) });
        accepts("path 1024", { ...good, paths: ["a".repeat(1024)] });
        direct("path 1025", { ...good, paths: ["a".repeat(1025)] });
        direct("path empty", { ...good, paths: [""] });
        direct("path long", { ...good, paths: ["a".repeat(3000)] });
        direct("paths not an array", { ...good, paths: "a.js" });
        accepts("stdin 1 MiB", { ...good, stdin: "x".repeat(1048576) });
        direct("stdin 1 MiB + 1", { ...good, stdin: "x".repeat(1048577) });
        const max = {
          cpus: 4,
          memoryMiB: 8192,
          pids: 2048,
          wallClockSeconds: 7200,
          stdoutBytes: 134217728,
          tmpfsMiB: 4096,
        };
        accepts("limits at the ceilings", { ...good, limits: { ...L, ...max } });
        for (const [k, v] of Object.entries(max))
          direct(`limit ${k} above the ceiling`, {
            ...good,
            limits: { ...L, [k]: v + (k === "cpus" ? 0.01 : 1) },
          });
        accepts("nofile at 65536", { ...good, limits: { ...L, nofile: 65536 } });
        direct("nofile above", { ...good, limits: { ...L, nofile: 65537 } });
        // the helper predicates
        ok(
          p,
          isValidRepoPath("a/b.js") &&
            !isValidRepoPath("") &&
            !isValidRepoPath("--") &&
            !isValidRepoPath(5) &&
            !isValidRepoPath("a".repeat(1025)) &&
            isValidRepoPath("a".repeat(1024)),
          "isValidRepoPath",
        );
        ok(
          p,
          containerNameOf(validateRunSpec(good, cfg)) === "qm-11111111-trivy-1",
          "container name",
        );
      }
      return p;
    },
  },
  {
    id: "ENG-S03a",
    name: "repository content is never executed or used as a command (SPEC 14.1 ENG-S03, runner part; the per-tool ignore-repo-config flags and the tool-control deny list belong to the adapter and tree parts): no source file of the sandbox module starts a shell, imports child_process outside the CLI driver, evaluates text, reads the environment outside the driver default, or names the runtime socket in code; the CLI driver calls execFile with an argument array, shell false and an environment limited to the client allowlist even when the process holds credentials; hostile file names (--config=evil, ; rm -rf /, newline, a leading -, spaces, $(), backslash, traversal, absolute, bidi, empty) are dropped and counted or, when valid, appear ONLY after the -- separator and never as a flag; the container name and every label come from validated ids",
    async run() {
      const p = [];
      const files = readdirSync(SANDBOX_DIR).filter((f) => f.endsWith(".js"));
      ok(p, files.length >= 10, `sandbox sources found: ${files.length}`);
      for (const f of files) {
        const code = readFileSync(new URL(f, SANDBOX_DIR), "utf8")
          .replace(/\/\*[\s\S]*?\*\//g, "")
          .replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
        ok(
          p,
          !/(?<![.\w])(exec|execSync|execFileSync|spawn|spawnSync|fork)\s*\(/.test(code),
          `${f}: starts a process outside execFile`,
        );
        ok(p, !/\bshell\s*:\s*(true|["'`])/.test(code), `${f}: enables a shell`);
        ok(
          p,
          !/\b(sh|bash|zsh|cmd)(\.exe)?["'`]?\s*,\s*\[?\s*["'`]-c/.test(code) &&
            !/["'`](sh|bash) -c/.test(code),
          `${f}: shell -c`,
        );
        ok(p, !/\beval\s*\(|new\s+Function\s*\(|\bvm\./.test(code), `${f}: evaluates text`);
        ok(p, f === "cli-runtime.js" || !/child_process/.test(code), `${f}: imports child_process`);
        ok(p, f === "cli-runtime.js" || !/process\.env/.test(code), `${f}: reads the environment`);
        ok(
          p,
          (code.match(/process\.env/g) ?? []).length <= (f === "cli-runtime.js" ? 1 : 0),
          `${f}: reads the environment more than once`,
        );
        ok(
          p,
          !/docker\.sock|podman\.sock|\/var\/run\/docker/.test(code.replace(/"\/var\/run"/g, "")),
          `${f}: names a runtime socket in code`,
        );
        ok(
          p,
          !/--privileged|--cap-add|--network=host|unconfined/.test(
            code.replace(/"[^"\n]*unconfined[^"\n]*"/g, "").replace(/\/unconfined\/i/g, ""),
          ),
          `${f}: emits a forbidden flag`,
        );
      }
      ok(
        p,
        /import \{ execFile as nodeExecFile \} from "node:child_process"/.test(
          readFileSync(new URL("cli-runtime.js", SANDBOX_DIR), "utf8"),
        ),
        "the CLI driver does not import execFile only",
      );
      // the driver as executed
      const calls = [];
      const sentinel = {
        GITHUB_TOKEN: "ghp_SENTINELSENTINELSENTINEL",
        DATABASE_URL: "postgres://u:pw@h/d",
        AWS_SECRET_ACCESS_KEY: "AKIASENTINEL",
        LLM_API_KEY: "sk-ant-SENTINELSENTINELSENTINEL",
        PATH: "/usr/bin",
        HOME: "/home/x",
        XDG_RUNTIME_DIR: "/run/user/1",
      };
      const exec = (file, args, options, cb) => {
        calls.push({ file, args: [...args], options });
        setImmediate(() => cb(null, Buffer.from(args[0] === "run" ? "{}" : ""), Buffer.alloc(0)));
        return { stdin: { end() {}, on() {} }, kill() {} };
      };
      const runtime = createCliSandboxRuntime({
        config: CONFIG_INPUT,
        execFile: exec,
        env: sentinel,
      });
      const res = await runtime.run(toolSpecs()[0]);
      await runtime.kill("qm-11111111-syft-1");
      await runtime.remove("qm-11111111-syft-1");
      await runtime.health();
      await runtime.listByLabel({ "qm.scan": "1" });
      ok(p, res.status === "exited" && res.exitCode === 0, `driver run result ${res.status}`);
      ok(
        p,
        calls.length >= 4 &&
          calls.every(
            (c) => c.file === "podman" && Array.isArray(c.args) && c.options.shell === false,
          ),
        "driver call shape",
      );
      for (const c of calls) {
        ok(
          p,
          Object.keys(c.options.env).every((k) => CLI_ENV_ALLOWLIST.includes(k)),
          `${c.args[0]}: client env outside the allowlist`,
        );
        ok(
          p,
          !JSON.stringify([c.args, c.options.env]).match(/SENTINEL|ghp_|postgres:\/\/|AKIA/),
          `${c.args[0]}: a worker credential reached the runtime call`,
        );
      }
      ok(p, calls[0].args[0] === "run" && !calls[0].args.includes("sh"), "first call is run");
      const dockerRuntime = createCliSandboxRuntime({
        config: { ...CONFIG_INPUT, runtimeBin: "docker" },
        execFile: exec,
        env: {},
      });
      await dockerRuntime.kill("qm-x");
      ok(p, calls[calls.length - 1].file === "docker", "the binary is selected by configuration");
      ok(
        p,
        (await rejects(() => runtime.kill("x; rm -rf /"), ["invalid_spec"])) === null,
        "a malformed container name reached the runtime",
      );
      ok(
        p,
        (await rejects(() => runtime.kill("--all"), ["invalid_spec"])) === null,
        "an option-like container name reached the runtime",
      );
      ok(
        p,
        (await rejects(() => runtime.listByLabel({ "qm.scan": "1 --all" }), ["invalid_spec"])) ===
          null,
        "a hostile label filter reached the runtime",
      );
      ok(
        p,
        (await rejects(() => runtime.listByLabel({}), ["invalid_spec"])) === null,
        "an empty label filter listed everything",
      );
      const before = calls.length;
      ok(
        p,
        (await rejects(
          () => runtime.run({ ...toolSpecs()[0], network: "host" }),
          ["policy_violation", "invalid_spec"],
        )) === null,
        "a forbidden spec was run",
      );
      ok(p, calls.length === before, "a refused spec still called the runtime");
      // hostile repository paths
      const hostile = [
        "--config=evil",
        "; rm -rf /",
        "a\nb",
        "-rf",
        "a b",
        "$(touch x)",
        "../x",
        "a/../b",
        "/etc/passwd",
        "a\\b",
        "a‮b",
        "",
        "a//b",
        "./a",
        "ok/file.js",
        "dir/\u0007x",
        "--",
        "a\u0000b",
      ];
      const { paths, dropped } = sanitizeRepoPaths(hostile);
      ok(
        p,
        JSON.stringify(paths) ===
          JSON.stringify(["--config=evil", "-rf", "a b", "$(touch x)", "ok/file.js"]),
        `kept paths ${JSON.stringify(paths)}`,
      );
      ok(p, dropped === hostile.length - 5, `dropped ${dropped}`);
      const cfg = config();
      const args = buildRunArgs({ ...toolSpecs()[4], paths }, cfg);
      const sep = args.indexOf("--");
      const idx = imageIndex(args);
      ok(
        p,
        sep > idx &&
          args.slice(sep + 1).join("\u0000") === paths.map((x) => `/src/${x}`).join("\u0000"),
        "paths are not exactly the tail after --, under the archive mount",
      );
      ok(
        p,
        args
          .slice(0, idx)
          .every(
            (a) =>
              (a.startsWith("--") && !paths.includes(a.split("=")[0])) ||
              ["--config=evil"].includes(a) === false,
          ),
        "a repository path became a flag",
      );
      ok(
        p,
        !args.slice(0, sep).includes("--config=evil") &&
          args.filter((a) => a === "--").length === 1,
        "a hostile name altered the argument vector before the separator",
      );
      ok(
        p,
        throwsCode(
          () => buildRunArgs({ ...toolSpecs()[4], paths: ["a\nb"] }, cfg),
          ["invalid_spec"],
        ) === null,
        "an invalid path reached the builder",
      );
      ok(
        p,
        throwsCode(
          () => buildRunArgs({ ...toolSpecs()[4], paths: ["../x"] }, cfg),
          ["invalid_spec"],
        ) === null,
        "a traversal path reached the builder",
      );
      ok(
        p,
        sanitizeRepoPaths(Array.from({ length: 2500 }, (_, i) => `f${i}`)).paths.length === 2000,
        "the path count is not bounded",
      );
      ok(p, sanitizeRepoPaths("not an array").paths.length === 0, "non-array input");
      // ---- mutation-sweep hardening: the client environment and the driver's result -------------------------------------------
      {
        const seen = [];
        const stub = (file, args, options, cb) => {
          seen.push({ file, args: [...args], options });
          setImmediate(() => cb(null, Buffer.from(""), Buffer.alloc(0)));
          return { stdin: { end() {}, on() {} }, kill() {} };
        };
        const env = {
          PATH: "/usr/bin",
          HOME: "/home/x",
          XDG_RUNTIME_DIR: "/run/user/1",
          DOCKER_HOST: "unix:///run/user/1/docker.sock",
          GITHUB_TOKEN: "ghp_SENTINELSENTINELSENTINEL",
          FOO: "bar",
        };
        const rt = createCliSandboxRuntime({ config: CONFIG_INPUT, execFile: stub, env });
        await rt.run(toolSpecs()[0]);
        const e = seen[0].options.env;
        ok(
          p,
          e.PATH === "/usr/bin" &&
            e.HOME === "/home/x" &&
            e.XDG_RUNTIME_DIR === "/run/user/1" &&
            e.DOCKER_HOST === env.DOCKER_HOST,
          "the allowlisted client variables were not passed",
        );
        ok(
          p,
          !("GITHUB_TOKEN" in e) &&
            !("FOO" in e) &&
            seen[0].options.windowsHide === true &&
            seen[0].options.shell === false,
          "client environment or options",
        );
        ok(
          p,
          seen[0].options.maxBuffer === Math.max(1048576, 65536) &&
            seen[0].options.encoding === "buffer",
          `maxBuffer ${seen[0].options.maxBuffer}`,
        );
        ok(
          p,
          Object.isFrozen(CLI_ENV_ALLOWLIST) &&
            !CLI_ENV_ALLOWLIST.some((n) => /TOKEN|SECRET|KEY|URL|PASSWORD/i.test(n)),
          "client allowlist contains a credential-like name",
        );
      }
      ok(
        p,
        sanitizeRepoPaths(["a".repeat(1024), "a".repeat(1025), "a".repeat(5000)]).paths.length ===
          1,
        "path length bound",
      );
      return p;
    },
  },
  {
    id: "ENG-S04a",
    name: "no credential reaches a tool through the runner (SPEC 14.1 ENG-S04, runner part; the engine and configuration parts belong to later parts): a spec carrying a GitHub token, bearer header, private key, cloud key, credentialed URL or a credential-named env key in its arguments, paths, stdin or environment is refused before any runtime call; the container environment of every tool is exactly HOME=/tmp plus allowlisted static names; a planted worker environment never appears in any recorded vector, label or name",
    async run() {
      const p = [];
      const cfg = config();
      const fake = new FakeSandboxRuntime({ config: CONFIG_INPUT });
      const planted = {
        GITHUB_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        DATABASE_URL: "postgres://user:password@db.internal/qm",
        AWS_ACCESS_KEY_ID: "AKIAABCDEFGHIJKLMNOP",
        LLM_API_KEY: "sk-ant-abcdefghijklmnopqrstuvwxyz",
      };
      const saved = {};
      for (const [k, v] of Object.entries(planted)) {
        saved[k] = process.env[k];
        process.env[k] = v;
      }
      try {
        for (const spec of toolSpecs()) {
          const r = await fake.run(spec);
          ok(p, r.status === "exited", `${spec.toolId}: ${r.status}`);
        }
      } finally {
        for (const [k, v] of Object.entries(saved)) {
          if (v === undefined) delete process.env[k];
          else process.env[k] = v;
        }
      }
      const runs = fake.calls.filter((c) => c.type === "run");
      ok(p, runs.length === toolSpecs().length, "recorded runs");
      for (const c of runs) {
        const text = JSON.stringify(c.args);
        for (const v of Object.values(planted))
          ok(p, !text.includes(v), `${c.spec.toolId}: planted value in the vector`);
        const envs = c.args
          .filter((a) => a.startsWith("--env="))
          .map((a) => a.slice(6).split("=")[0]);
        ok(
          p,
          envs.includes("HOME") && envs.every((n) => ENV_ALLOWLIST.includes(n)),
          `${c.spec.toolId}: env names ${envs.join(",")}`,
        );
        ok(p, !c.args.some((a) => a.startsWith("--env-file")), `${c.spec.toolId}: env file`);
      }
      const base = toolSpecs()[0];
      const secrets = [
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "Bearer abcdefghijklmnop1234",
        "-----BEGIN RSA PRIVATE KEY-----",
        "AKIAABCDEFGHIJKLMNOP",
        "https://user:pw@example.test/x",
        "sk-ant-abcdefghijklmnopqrstuvwxyz",
        "https://example.test/x?access_token=abcdefghij",
      ];
      for (const s of secrets) {
        for (const where of ["argv", "stdin", "path"]) {
          if (where === "path" && /\s/.test(s)) continue;
          const spec =
            where === "argv"
              ? { ...base, argv: ["scan", s] }
              : where === "stdin"
                ? { ...base, stdin: `{"x":"${s}"}` }
                : { ...base, paths: [`a/${s}`.replace(/\s/g, "_")] };
          const e = throwsCode(() => buildRunArgs(spec, cfg), ["policy_violation", "invalid_spec"]);
          ok(p, e === null, `credential in ${where} (${s.slice(0, 8)}): ${e}`);
        }
        ok(
          p,
          throwsCode(
            () => buildRunArgs({ ...base, env: { GOFLAGS: s } }, cfg),
            ["policy_violation"],
          ) === null,
          `credential in env value (${s.slice(0, 8)})`,
        );
      }
      ok(
        p,
        throwsCode(
          () => buildRunArgs({ ...base, env: { GITHUB_TOKEN: "x" } }, cfg),
          ["policy_violation"],
        ) === null,
        "credential-named env key accepted",
      );
      const refused = new FakeSandboxRuntime({ config: CONFIG_INPUT });
      ok(
        p,
        (await rejects(
          () => refused.run({ ...base, argv: ["scan", secrets[0]] }),
          ["policy_violation"],
        )) === null,
        "fake runtime ran a credentialed spec",
      );
      ok(
        p,
        refused.calls.filter((c) => c.type === "run").length === 0 || refused.containers.size === 0,
        "a refused spec left a container",
      );
      return p;
    },
  },
  {
    id: "ENG-S10a",
    name: "cancellation leaves no orphan (SPEC 6.4, 14.1 ENG-S10; the fake runtime stands for any driver): an abort signal, the wall-clock deadline, a runner abort of the whole attempt and an output over the cap each end with kill then remove of every started container exactly once and none left; the output of a killed run is discarded and never returned for parsing; abortAttempt kills only the containers of its own task and attempt (another attempt, another task and an unlabelled container are untouched), a second abortAttempt kills nothing; a runtime fault is reported as runtime_error; the CLI driver kills the container then removes it by name on abort and on timeout, discards output, and treats a missing container as success",
    async run() {
      const p = [];
      const fake = new FakeSandboxRuntime({ config: CONFIG_INPUT });
      const runner = createSandboxRunner({ runtime: fake });
      const spec = (toolId, taskId, attempt, over = {}) => ({
        ...toolSpecs()[0],
        toolId,
        labels: {
          tenantId: "tenant-1",
          executionId: "exec-1",
          taskId,
          attempt,
          deadlineEpoch: 1790000000,
        },
        ...over,
      });
      // 1. abort signal during a hanging run
      fake.script("hang1", { hang: true });
      const ac = new AbortController();
      const r1p = runner.runTool(spec("hang1", "task-aaaa1", 1), { signal: ac.signal });
      await sleep(10);
      ok(p, fake.containers.size === 1, "control: the container is running");
      ac.abort();
      const r1 = await r1p;
      ok(
        p,
        r1.status === "aborted" && r1.aborted && r1.exitCode === null && r1.stdout === "",
        `abort result ${r1.status}`,
      );
      ok(
        p,
        fake.killCount("qm-taskaaaa-hang1-1") === 1 &&
          fake.removeCount("qm-taskaaaa-hang1-1") === 1,
        "abort: kill/remove counts",
      );
      const order = fake.calls
        .filter((c) => c.name === "qm-taskaaaa-hang1-1" && c.type !== "run")
        .map((c) => c.type);
      ok(p, order.join(",") === "kill,remove", `abort order ${order.join(",")}`);
      ok(p, fake.containers.size === 0, "abort: a container remains");
      // an already aborted signal starts nothing
      const pre = new AbortController();
      pre.abort();
      const before = fake.containers.size;
      const rp = await runner.runTool(spec("hang1", "task-aaaa2", 1), { signal: pre.signal });
      ok(
        p,
        rp.status === "aborted" && fake.containers.size === before,
        "pre-aborted run started a container",
      );
      // 2. wall-clock deadline
      fake.script("slow", { hang: true });
      const t0 = Date.now();
      const r2 = await runner.runTool(
        spec("slow", "task-bbbb1", 1, {
          limits: { ...toolSpecs()[0].limits, wallClockSeconds: 1 },
        }),
      );
      ok(
        p,
        r2.status === "timed_out" && r2.timedOut && r2.stdout === "" && Date.now() - t0 < 3000,
        `timeout result ${r2.status}`,
      );
      ok(
        p,
        fake.killCount("qm-taskbbbb-slow-1") === 1 &&
          fake.removeCount("qm-taskbbbb-slow-1") === 1 &&
          fake.containers.size === 0,
        "timeout: kill/remove/none left",
      );
      // 3. output over the cap
      fake.script("flood", { stdout: "x".repeat(2000), exitCode: 0 });
      const r3 = await runner.runTool(
        spec("flood", "task-cccc1", 1, { limits: { ...toolSpecs()[0].limits, stdoutBytes: 1024 } }),
      );
      ok(
        p,
        r3.status === "output_limit" &&
          r3.stdout === "" &&
          fake.killCount("qm-taskcccc-flood-1") === 1 &&
          fake.removeCount("qm-taskcccc-flood-1") === 1,
        `flood ${r3.status}`,
      );
      // a normal run keeps its output and needs no kill (--rm)
      fake.script("fine", { stdout: "{}", exitCode: 1 });
      const r4 = await runner.runTool(spec("fine", "task-dddd1", 1));
      ok(
        p,
        r4.status === "exited" &&
          r4.exitCode === 1 &&
          r4.stdout === "{}" &&
          fake.killCount("qm-taskdddd-fine-1") === 0,
        "normal run",
      );
      fake.script("fault", { runtimeFault: true });
      const r5 = await runner.runTool(spec("fault", "task-eeee1", 1));
      ok(p, r5.status === "runtime_error", `fault ${r5.status}`);
      // 4. abortAttempt reaps exactly the attempt
      for (const t of ["h1", "h2", "h3"]) fake.script(t, { hang: true });
      fake.script("other-attempt", { hang: true });
      fake.script("other-task", { hang: true });
      const pending = [
        runner.runTool(spec("h1", "task-ffff1", 2)),
        runner.runTool(spec("h2", "task-ffff1", 2)),
        runner.runTool(spec("h3", "task-ffff1", 2)),
        runner.runTool(spec("other-attempt", "task-ffff1", 3)),
        runner.runTool(spec("other-task", "task-gggg1", 2)),
      ];
      fake.seed("unlabelled-1", {});
      fake.seed("someone-else", { "com.other": "1" });
      await sleep(20);
      ok(
        p,
        runner.activeCount({ taskId: "task-ffff1", attempt: 2 }) === 3,
        "control: three active tools",
      );
      const reaped = await runner.abortAttempt({ taskId: "task-ffff1", attempt: 2 });
      ok(
        p,
        reaped.reaped.length === 3 && reaped.failed.length === 0,
        `reaped ${JSON.stringify(reaped)}`,
      );
      const results = await Promise.all(pending.slice(0, 3));
      ok(
        p,
        results.every((r) => r.status === "aborted" && r.stdout === ""),
        "reaped runs are not aborted results",
      );
      for (const t of ["h1", "h2", "h3"])
        ok(
          p,
          fake.killCount(`qm-taskffff-${t}-2`) === 1 &&
            fake.removeCount(`qm-taskffff-${t}-2`) === 1,
          `${t}: kill/remove counts`,
        );
      ok(
        p,
        fake.killCount("qm-taskffff-other-attempt-3") === 0 &&
          fake.killCount("qm-taskgggg-other-task-2") === 0,
        "another attempt or task was killed",
      );
      ok(
        p,
        fake.killCount("unlabelled-1") === 0 &&
          fake.killCount("someone-else") === 0 &&
          fake.containers.has("unlabelled-1"),
        "an unlabelled container was touched",
      );
      const again = await runner.abortAttempt({ taskId: "task-ffff1", attempt: 2 });
      ok(
        p,
        again.reaped.length === 0 && fake.killCount("qm-taskffff-h1-2") === 1,
        "a second abort killed again",
      );
      await runner.abortAttempt({ taskId: "task-ffff1", attempt: 3 });
      await runner.abortAttempt({ taskId: "task-gggg1", attempt: 2 });
      await Promise.all(pending);
      ok(
        p,
        [...fake.containers.keys()].sort().join(",") === "someone-else,unlabelled-1",
        `left: ${[...fake.containers.keys()].join(",")}`,
      );
      // 5. the CLI driver (recording stand-in for execFile; no process)
      const calls = [];
      let runChildDone;
      const exec = (file, args, options, cb) => {
        calls.push({ file, args: [...args] });
        const child = { stdin: { end() {}, on() {} }, kill() {} };
        if (args[0] === "run")
          runChildDone = () =>
            cb(
              Object.assign(new Error("killed"), { code: null, signal: "SIGKILL" }),
              Buffer.from("PARTIAL"),
              Buffer.alloc(0),
            );
        else if (args[0] === "kill")
          setImmediate(() => {
            cb(null, Buffer.alloc(0), Buffer.alloc(0));
            runChildDone?.();
          });
        else if (args[0] === "rm")
          setImmediate(() =>
            cb(
              Object.assign(new Error("x"), { code: 1 }),
              Buffer.alloc(0),
              Buffer.from("Error: No such container: x"),
            ),
          );
        else setImmediate(() => cb(null, Buffer.alloc(0), Buffer.alloc(0)));
        return child;
      };
      const cli = createCliSandboxRuntime({ config: CONFIG_INPUT, execFile: exec, env: {} });
      const acc = new AbortController();
      const cp = cli.run(toolSpecs()[0], { signal: acc.signal });
      await sleep(5);
      acc.abort();
      const cr = await cp;
      ok(
        p,
        cr.status === "aborted" && cr.stdout === "" && cr.exitCode === null,
        `cli abort ${cr.status} stdout ${cr.stdout}`,
      );
      const kinds = calls.map((c) => c.args[0]);
      const ki = kinds.indexOf("kill");
      ok(
        p,
        kinds[0] === "run" && ki > 0 && kinds.indexOf("rm") > ki,
        `cli order ${kinds.join(",")}`,
      );
      ok(p, kinds.filter((k) => k === "kill").length === 1, "cli: kill count");
      ok(
        p,
        calls
          .filter((c) => c.args[0] === "kill" || c.args[0] === "rm")
          .every((c) => c.args.includes("qm-11111111-syft-1")),
        "cli: kill/rm name",
      );
      ok(p, !cr.cleanupFailed, "cli: a missing container counted as a cleanup failure");
      // ---- mutation-sweep hardening: the CLI driver's results and the fake's bookkeeping ----------------------------------------
      {
        const mk = (handler) => {
          const log = [];
          const exec = (file, args, options, cb) => {
            log.push({ args: [...args], options });
            handler(args, cb, log);
            return { stdin: { end() {}, on() {} }, kill() {} };
          };
          return {
            log,
            rt: createCliSandboxRuntime({ config: CONFIG_INPUT, execFile: exec, env: {} }),
          };
        };
        const done = (cb, code, out = "", err = "") =>
          setImmediate(() =>
            cb(
              code === 0 ? null : Object.assign(new Error("x"), { code }),
              Buffer.from(out),
              Buffer.from(err),
            ),
          );
        // an exit code of the tool is reported as is
        const a = mk((args, cb) => done(cb, 2, "partial", "warn"));
        const ra = await a.rt.run(toolSpecs()[0]);
        ok(
          p,
          ra.status === "exited" &&
            ra.exitCode === 2 &&
            ra.stdout === "partial" &&
            ra.stderr === "warn" &&
            !ra.timedOut &&
            !ra.aborted &&
            !ra.stdoutTruncated &&
            !ra.stderrTruncated &&
            !ra.cleanupFailed,
          `exit 2: ${JSON.stringify(ra)}`,
        );
        // a runtime fault
        const b = mk((args, cb) => done(cb, 125, "", "daemon error"));
        ok(
          p,
          (await b.rt.run(toolSpecs()[0])).status === "runtime_error",
          "exit 125 is not a runtime error",
        );
        const c = mk(() => {
          throw new Error("spawn failed");
        });
        const rc = await c.rt.run(toolSpecs()[0]);
        ok(
          p,
          rc.status === "runtime_error" &&
            rc.exitCode === null &&
            !rc.stdoutTruncated &&
            !rc.timedOut &&
            !rc.aborted,
          `sync throw: ${JSON.stringify(rc)}`,
        );
        // oversized output: reported truncated, capped
        const cap = 1024;
        const spec = { ...toolSpecs()[0], limits: { ...toolSpecs()[0].limits, stdoutBytes: cap } };
        const d = mk((args, cb) => done(cb, 0, "x".repeat(cap + 10), "e".repeat(70000)));
        const rd = await d.rt.run(spec);
        ok(
          p,
          rd.stdout.length === cap &&
            rd.stdoutTruncated &&
            rd.stderrTruncated &&
            rd.stderr.length === 65536,
          `caps ${rd.stdout.length}/${rd.stderr.length}`,
        );
        const dExact = mk((args, cb) => done(cb, 0, "x".repeat(cap), "e".repeat(65536)));
        const re = await dExact.rt.run(spec);
        ok(
          p,
          !re.stdoutTruncated && !re.stderrTruncated,
          "output exactly at the cap reported truncated",
        );
        // the client stopped by the output cap: the container is killed and removed
        const f = mk((args, cb) => {
          if (args[0] === "run")
            setImmediate(() =>
              cb(
                Object.assign(new Error("maxBuffer"), {
                  code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
                }),
                Buffer.from("x".repeat(cap)),
                Buffer.alloc(0),
              ),
            );
          else done(cb, 0);
        });
        const rf = await f.rt.run(spec);
        const fk = f.log.map((x) => x.args[0]);
        ok(
          p,
          rf.status === "output_limit" &&
            rf.stdout === "" &&
            rf.stdoutTruncated &&
            fk.includes("kill") &&
            fk.includes("rm") &&
            !rf.cleanupFailed,
          `output limit ${rf.status} ${fk.join(",")}`,
        );
        const g = mk((args, cb) => {
          if (args[0] === "run")
            setImmediate(() =>
              cb(
                Object.assign(new Error("maxBuffer"), {
                  code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
                }),
                Buffer.from("x"),
                Buffer.alloc(0),
              ),
            );
          else done(cb, 1, "", "Error: permission denied");
        });
        ok(
          p,
          (await g.rt.run(spec)).cleanupFailed === true,
          "a failed cleanup after the output cap was not reported",
        );
        const g2 = mk((args, cb) => {
          if (args[0] === "run")
            setImmediate(() =>
              cb(
                Object.assign(new Error("maxBuffer"), {
                  code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
                }),
                Buffer.from("x"),
                Buffer.alloc(0),
              ),
            );
          else if (args[0] === "kill") done(cb, 1, "", "Error: permission denied");
          else done(cb, 0);
        });
        ok(
          p,
          (await g2.rt.run(spec)).cleanupFailed === true,
          "a failed kill after the output cap was not reported",
        );
        const g3 = mk((args, cb) => {
          if (args[0] === "run")
            setImmediate(() =>
              cb(
                Object.assign(new Error("maxBuffer"), {
                  code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
                }),
                Buffer.from("x"),
                Buffer.alloc(0),
              ),
            );
          else if (args[0] === "rm") done(cb, 1, "", "Error: permission denied");
          else done(cb, 0);
        });
        ok(
          p,
          (await g3.rt.run(spec)).cleanupFailed === true,
          "a failed removal after the output cap was not reported",
        );
        // a pre-aborted signal starts nothing
        const h = mk((args, cb) => done(cb, 0));
        const pre = new AbortController();
        pre.abort();
        const rh = await h.rt.run(toolSpecs()[0], { signal: pre.signal });
        ok(
          p,
          h.log.length === 0 &&
            rh.status === "aborted" &&
            rh.aborted &&
            !rh.timedOut &&
            !rh.stdoutTruncated &&
            !rh.stderrTruncated &&
            !rh.cleanupFailed &&
            rh.exitCode === null &&
            rh.durationMs === 0,
          `pre-aborted: ${JSON.stringify(rh)}`,
        );
        // the wall clock: kill then remove, timed_out and not aborted; remove repeated once after the client is gone
        let release;
        const t = mk((args, cb) => {
          if (args[0] === "run")
            release = () =>
              cb(
                Object.assign(new Error("killed"), { code: null, signal: "SIGKILL" }),
                Buffer.from("PARTIAL"),
                Buffer.alloc(0),
              );
          else if (args[0] === "kill")
            setImmediate(() => {
              cb(null, Buffer.alloc(0), Buffer.alloc(0));
              release?.();
            });
          else done(cb, 0);
        });
        const rt1 = await t.rt.run({
          ...toolSpecs()[0],
          limits: { ...toolSpecs()[0].limits, wallClockSeconds: 1 },
        });
        const tk = t.log.map((x) => x.args[0]);
        ok(
          p,
          rt1.status === "timed_out" &&
            rt1.timedOut &&
            !rt1.aborted &&
            rt1.stdout === "" &&
            rt1.exitCode === null,
          `cli timeout ${JSON.stringify(rt1)}`,
        );
        ok(
          p,
          tk.filter((x) => x === "kill").length === 1 &&
            tk.filter((x) => x === "rm").length === 2 &&
            tk.indexOf("kill") < tk.indexOf("rm"),
          `cli timeout calls ${tk.join(",")}`,
        );
        let releaseCf;
        const cf = mk((args, cb) => {
          if (args[0] === "run")
            releaseCf = () =>
              cb(
                Object.assign(new Error("killed"), { code: null }),
                Buffer.alloc(0),
                Buffer.alloc(0),
              );
          else if (args[0] === "kill")
            setImmediate(() => {
              cb(null, Buffer.alloc(0), Buffer.alloc(0));
              releaseCf?.();
            });
          else done(cb, 1, "", "Error: permission denied");
        });
        const ac3 = new AbortController();
        const rp3 = cf.rt.run(toolSpecs()[0], { signal: ac3.signal });
        await sleep(2);
        ac3.abort();
        ok(
          p,
          (await rp3).cleanupFailed === true,
          "a failed removal after an abort was not reported",
        );
        // the fake's own bookkeeping
        const quick = new FakeSandboxRuntime({ config: CONFIG_INPUT });
        quick.script("flag", { stdout: "x".repeat(1024), exitCode: 0 });
        const rq = await quick.run({
          ...toolSpecs()[0],
          toolId: "flag",
          limits: { ...toolSpecs()[0].limits, stdoutBytes: 1024 },
        });
        ok(
          p,
          rq.status === "exited" &&
            !rq.stdoutTruncated &&
            !rq.stderrTruncated &&
            !rq.timedOut &&
            !rq.aborted &&
            !rq.cleanupFailed &&
            rq.stdout.length === 1024,
          `fake exact cap ${JSON.stringify({ ...rq, stdout: rq.stdout.length })}`,
        );
        const pa = new AbortController();
        pa.abort();
        const rpa = await quick.run(toolSpecs()[0], { signal: pa.signal });
        ok(
          p,
          rpa.aborted === true && rpa.status === "aborted" && !rpa.timedOut,
          "fake pre-aborted result",
        );
        ok(
          p,
          (await quick.health()).ok === true && quick.calls.some((x) => x.type === "health"),
          "fake health",
        );
        quick.forgetRunnerState();
        ok(
          p,
          quick.calls.some((x) => x.type === "crash"),
          "fake crash marker",
        );
      }
      return p;
    },
  },
  {
    id: "ENG-S10b",
    name: "the janitor reaps orphans and nothing else (SPEC 6.4, 14.1 ENG-S10): a labelled container past its deadline, one whose attempt is no longer running and one with malformed labels are killed then removed once; one whose attempt is running is kept; an unlabelled container and one labelled for another system are never listed or touched; an error reading the attempt state keeps an unexpired container and removes an expired one; a runner crash (state dropped while containers run) is recovered by one sweep; the CLI driver lists by label filters, parses inspect output tolerantly and returns only qm.scan=1 containers",
    async run() {
      const p = [];
      const fake = new FakeSandboxRuntime({ config: CONFIG_INPUT });
      const NOW = 1_700_000_000_000;
      const labels = (task, attempt, deadline, extra = {}) => ({
        "qm.scan": "1",
        "qm.tenant": "tenant-1",
        "qm.execution": "exec-1",
        "qm.task": task,
        "qm.tool": "syft",
        "qm.attempt": String(attempt),
        "qm.deadline": String(deadline),
        ...extra,
      });
      const future = Math.floor(NOW / 1000) + 600;
      const past = Math.floor(NOW / 1000) - 5;
      fake.seed("expired", labels("t-exp", 1, past));
      fake.seed("not-running", labels("t-done", 1, future));
      fake.seed("running", labels("t-live", 1, future));
      fake.seed("bad-deadline", labels("t-bad", 1, "soon"));
      fake.seed("no-task", { "qm.scan": "1", "qm.deadline": String(future) });
      fake.seed("probe-error", labels("t-err", 1, future));
      fake.seed("expired-probe-error", labels("t-err2", 1, past));
      fake.seed("unlabelled", {});
      fake.seed("other-system", { app: "web", "qm.scan": "0" });
      const states = { "t-live": true, "t-done": false, "t-bad": true };
      const janitor = createJanitor({
        runtime: fake,
        now: () => NOW,
        isAttemptRunning: async ({ taskId }) => {
          if (taskId === "t-err" || taskId === "t-err2") throw new Error("db down");
          return states[taskId] ?? false;
        },
      });
      const res = await janitor.sweep();
      const gone = new Set(res.removed);
      for (const n of [
        "expired",
        "not-running",
        "bad-deadline",
        "no-task",
        "expired-probe-error",
      ]) {
        ok(
          p,
          gone.has(n) &&
            fake.killCount(n) === 1 &&
            fake.removeCount(n) === 1 &&
            !fake.containers.has(n),
          `${n}: not reaped exactly once`,
        );
      }
      for (const n of ["running", "probe-error"])
        ok(
          p,
          !gone.has(n) && fake.containers.has(n) && fake.killCount(n) === 0,
          `${n}: was removed`,
        );
      for (const n of ["unlabelled", "other-system"])
        ok(
          p,
          fake.containers.has(n) && fake.killCount(n) === 0 && fake.removeCount(n) === 0,
          `${n}: was touched`,
        );
      ok(
        p,
        fake.calls.filter((c) => c.type === "list").every((c) => c.labels["qm.scan"] === "1"),
        "the janitor listed without the label filter",
      );
      ok(
        p,
        res.kept === 2 && res.removed.length === 5,
        `sweep summary ${JSON.stringify({ kept: res.kept, removed: res.removed.length })}`,
      );
      const second = await janitor.sweep();
      ok(p, second.removed.length === 0, "a second sweep removed more");
      // crash recovery: two runs in flight, the runner loses its state, one sweep clears them
      const crash = new FakeSandboxRuntime({ config: CONFIG_INPUT });
      crash.script("hang", { hang: true });
      const spec = (task) => ({
        ...toolSpecs()[0],
        toolId: "hang",
        labels: {
          tenantId: "tenant-1",
          executionId: "exec-1",
          taskId: task,
          attempt: 1,
          deadlineEpoch: future,
        },
      });
      void crash.run(spec("crash-aaa1"));
      void crash.run(spec("crash-bbb1"));
      await sleep(10);
      ok(p, crash.containers.size === 2, "control: two containers in flight");
      crash.forgetRunnerState();
      const swept = await createJanitor({
        runtime: crash,
        now: () => NOW,
        isAttemptRunning: async () => false,
      }).sweep();
      ok(
        p,
        swept.removed.length === 2 && crash.containers.size === 0,
        `crash recovery removed ${swept.removed.length}`,
      );
      // the CLI driver's listing
      const calls = [];
      const lines = [
        JSON.stringify({
          id: "a".repeat(64),
          name: "/qm-1",
          labels: { "qm.scan": "1", "qm.task": "t1" },
          state: "running",
        }),
        JSON.stringify({
          id: "b".repeat(64),
          name: "other",
          labels: { app: "x" },
          state: "running",
        }),
        JSON.stringify({ id: "c".repeat(64), name: "qm-2", labels: null, state: "running" }),
        "not json",
        JSON.stringify({
          id: "d".repeat(64),
          name: "bad name; rm",
          labels: { "qm.scan": "1" },
          state: "running",
        }),
        JSON.stringify({
          id: "e".repeat(64),
          name: "qm-3",
          labels: { "qm.scan": "1", n: 5 },
          state: 3,
        }),
      ].join("\n");
      const exec = (file, args, options, cb) => {
        calls.push([...args]);
        setImmediate(() =>
          cb(
            null,
            Buffer.from(
              args[0] === "ps"
                ? `${"a".repeat(64)}\n${"b".repeat(64)}\ngarbage\n`
                : args[0] === "inspect"
                  ? lines
                  : "",
            ),
            Buffer.alloc(0),
          ),
        );
        return { stdin: { end() {}, on() {} }, kill() {} };
      };
      const cli = createCliSandboxRuntime({ config: CONFIG_INPUT, execFile: exec, env: {} });
      const listed = await cli.listByLabel({ "qm.scan": "1", "qm.task": "t1" });
      ok(
        p,
        calls[0].join(" ").includes("--filter=label=qm.scan=1") &&
          calls[0].includes("--filter=label=qm.task=t1"),
        "ps filters",
      );
      ok(
        p,
        calls[1][0] === "inspect" && calls[1].filter((a) => /^[0-9a-f]{64}$/.test(a)).length === 2,
        "only well-formed ids are inspected",
      );
      ok(
        p,
        listed.map((c) => c.name).join(",") === "qm-1,qm-3",
        `listed ${listed.map((c) => c.name).join(",")}`,
      );
      ok(
        p,
        parseInspectLines(`{"name":"x","labels":{"__proto__":"1","qm.scan":"1"},"state":"running"}`)
          .length === 1,
        "tolerant parse",
      );
      const health = await cli.health();
      ok(p, health.ok === true && health.runtime === "podman", "health");
      const down = createCliSandboxRuntime({
        config: CONFIG_INPUT,
        execFile: (f, a, o, cb) => {
          setImmediate(() =>
            cb(Object.assign(new Error("x"), { code: "ENOENT" }), Buffer.alloc(0), Buffer.alloc(0)),
          );
          return { stdin: { end() {}, on() {} }, kill() {} };
        },
        env: {},
      });
      const dh = await down.health();
      ok(p, dh.ok === false && dh.reason === "binary_not_found", "health without a binary");
      ok(
        p,
        (await rejects(() => down.run(toolSpecs()[0]), ["runtime_unavailable"])) === null,
        "run without a binary did not report runtime_unavailable",
      );
      // ---- mutation-sweep hardening ----------------------------------------------------------------------------------------
      ok(p, fake.calls.filter((c) => c.type === "list").length >= 1, "the janitor never listed");
      {
        const nowS = Math.floor(NOW / 1000);
        const edge = new FakeSandboxRuntime({ config: CONFIG_INPUT });
        edge.seed("on-deadline-running", labels("t-live", 1, nowS));
        edge.seed("past-deadline-running", labels("t-live", 1, nowS - 1));
        edge.seed("bad-attempt-running", { ...labels("t-live", 1, future), "qm.attempt": "x" });
        edge.seed("bad-deadline-running", labels("t-live", 1, "soon"));
        const sw = await createJanitor({
          runtime: edge,
          now: () => NOW,
          isAttemptRunning: async () => true,
        }).sweep();
        ok(
          p,
          !sw.removed.includes("on-deadline-running") &&
            sw.removed.includes("past-deadline-running"),
          `deadline edge ${JSON.stringify(sw.removed)}`,
        );
        ok(
          p,
          sw.removed.includes("bad-attempt-running") && sw.removed.includes("bad-deadline-running"),
          "malformed labels of a running attempt were kept",
        );
        const grace = await createJanitor({
          runtime: edge,
          now: () => NOW,
          graceSeconds: 5,
          isAttemptRunning: async () => true,
        }).sweep();
        ok(p, grace.listed <= 1, "grace sweep");
      }
      {
        // the CLI driver: health parsing and the inspect parser
        const reply =
          (text, code = 0) =>
          (file, args, options, cb) => {
            setImmediate(() =>
              cb(
                code === 0 ? null : Object.assign(new Error("x"), { code }),
                Buffer.from(text),
                Buffer.alloc(0),
              ),
            );
            return { stdin: { end() {}, on() {} }, kill() {} };
          };
        const h = async (text, code = 0) =>
          createCliSandboxRuntime({
            config: CONFIG_INPUT,
            execFile: reply(text, code),
            env: {},
          }).health();
        ok(
          p,
          (await h("host:\n  rootless: true\n")).rootless === true &&
            (await h("host:\n  rootless: false\n")).rootless === false,
          "podman rootless parse",
        );
        ok(
          p,
          (await h("Security Options:\n  seccomp\n  rootless\n")).rootless === true,
          "docker rootless parse",
        );
        ok(p, (await h("Security Options:\n  seccomp\n")).rootless === null, "unknown rootless");
        const failed = await h("", 1);
        ok(
          p,
          failed.ok === false && failed.reason === "info_failed" && failed.rootless === null,
          `info failed ${JSON.stringify(failed)}`,
        );
        const parsed = parseInspectLines(
          JSON.stringify({ name: "/qm-9", labels: { "qm.scan": "1", n: 5, s: "v" } }),
        );
        ok(
          p,
          parsed.length === 1 &&
            parsed[0].id === null &&
            parsed[0].state === "unknown" &&
            parsed[0].labels.s === "v" &&
            !("n" in parsed[0].labels),
          `parse ${JSON.stringify(parsed)}`,
        );
        ok(
          p,
          parseInspectLines(
            JSON.stringify({ id: 5, name: "qm-8", labels: { "qm.scan": "1" }, state: 5 }),
          )[0].id === null,
          "a numeric id was kept",
        );
        ok(
          p,
          parseInspectLines("null\n5\n[]\n{}\n").length === 0 &&
            parseInspectLines(JSON.stringify({ name: 5, labels: { "qm.scan": "1" } })).length === 0,
          "malformed inspect lines",
        );
        ok(
          p,
          parseInspectLines(JSON.stringify({ name: "qm-7", labels: ["qm.scan"] })).length === 0,
          "array labels",
        );
      }
      return p;
    },
  },
  {
    id: "ENG-S14a",
    name: "capacity and fairness limits hold (SPEC 5.8, SE-19, 14.1 ENG-S14; the scheduler wiring is part K): under 60 concurrent scripted tool runs from three tenants, several tasks and trusted and fork work, the number of runs inside the gate never exceeds the per-worker, per-tenant, per-task or fork-share limit at any moment and every run completes; a waiter that cannot get capacity before its timeout is refused with the capacity code and holds nothing; an aborted waiter is released from the queue; releasing twice frees once; a tenant at its own limit does not block another tenant; the fork share never blocks trusted runs; invalid limits are refused",
    async run() {
      const p = [];
      const limits = { perWorker: 6, perTenant: 2, perTask: 2, forkShare: 2 };
      const gate = createCapacityGate(limits);
      const live = { worker: 0, forks: 0, tenants: new Map(), tasks: new Map() };
      const peak = { worker: 0, forks: 0, tenant: 0, task: 0 };
      const jobs = [];
      for (let i = 0; i < 60; i += 1) {
        const ref = { tenantId: `tn-${i % 3}`, taskId: `tk-${i % 5}`, fork: i % 5 === 0 };
        jobs.push(
          (async () => {
            const release = await gate.acquire(ref, { timeoutMs: 20000 });
            live.worker += 1;
            if (ref.fork) live.forks += 1;
            live.tenants.set(ref.tenantId, (live.tenants.get(ref.tenantId) ?? 0) + 1);
            live.tasks.set(ref.taskId, (live.tasks.get(ref.taskId) ?? 0) + 1);
            peak.worker = Math.max(peak.worker, live.worker);
            peak.forks = Math.max(peak.forks, live.forks);
            peak.tenant = Math.max(peak.tenant, live.tenants.get(ref.tenantId));
            peak.task = Math.max(peak.task, live.tasks.get(ref.taskId));
            await sleep(2 + (i % 4));
            live.worker -= 1;
            if (ref.fork) live.forks -= 1;
            live.tenants.set(ref.tenantId, live.tenants.get(ref.tenantId) - 1);
            live.tasks.set(ref.taskId, live.tasks.get(ref.taskId) - 1);
            release();
            return true;
          })(),
        );
      }
      const done = await Promise.all(jobs);
      ok(p, done.length === 60 && done.every(Boolean), "not every run completed");
      ok(
        p,
        peak.worker <= limits.perWorker &&
          peak.tenant <= limits.perTenant &&
          peak.task <= limits.perTask &&
          peak.forks <= limits.forkShare,
        `peaks ${JSON.stringify(peak)}`,
      );
      ok(
        p,
        peak.worker >= 3 && peak.task === limits.perTask,
        `control: the limits were exercised ${JSON.stringify(peak)}`,
      );
      const snap = gate.snapshot();
      ok(
        p,
        snap.worker === 0 &&
          snap.forks === 0 &&
          snap.tenants === 0 &&
          snap.tasks === 0 &&
          snap.waiting === 0,
        `gate not empty ${JSON.stringify(snap)}`,
      );
      // timeouts, aborts, double release
      const small = createCapacityGate({ perWorker: 1, perTenant: 1, perTask: 1, forkShare: 1 });
      const hold = await small.acquire({ tenantId: "a", taskId: "x" }, { timeoutMs: 1000 });
      const t0 = Date.now();
      ok(
        p,
        (await rejects(
          () => small.acquire({ tenantId: "b", taskId: "y" }, { timeoutMs: 30 }),
          ["capacity"],
        )) === null,
        "timeout was not a capacity error",
      );
      ok(
        p,
        Date.now() - t0 >= 25 && small.snapshot().waiting === 0 && small.snapshot().worker === 1,
        "timeout: waiter left the queue or held capacity",
      );
      const ac = new AbortController();
      const waiting = small.acquire(
        { tenantId: "b", taskId: "y" },
        { timeoutMs: 5000, signal: ac.signal },
      );
      await sleep(5);
      ac.abort();
      ok(
        p,
        (await rejects(() => waiting, ["capacity"])) === null && small.snapshot().waiting === 0,
        "abort did not leave the queue",
      );
      const pre = new AbortController();
      pre.abort();
      ok(
        p,
        (await rejects(
          () =>
            small.acquire({ tenantId: "b", taskId: "y" }, { timeoutMs: 5000, signal: pre.signal }),
          ["capacity"],
        )) === null && small.snapshot().worker === 1,
        "pre-aborted acquire took capacity",
      );
      hold();
      hold();
      ok(p, small.snapshot().worker === 0, "double release freed twice");
      const a = await small.acquire({ tenantId: "a", taskId: "x" }, { timeoutMs: 1000 });
      const second = small.acquire({ tenantId: "a", taskId: "x2" }, { timeoutMs: 1000 });
      await sleep(5);
      ok(p, small.snapshot().waiting === 1, "the second waiter is not queued");
      a();
      const r2 = await second;
      r2();
      // fairness: a tenant at its limit does not block another tenant; forks never block trusted work
      const fair = createCapacityGate({ perWorker: 4, perTenant: 1, perTask: 4, forkShare: 1 });
      const r1 = await fair.acquire({ tenantId: "a", taskId: "t1" }, { timeoutMs: 1000 });
      const blocked = fair.acquire({ tenantId: "a", taskId: "t2" }, { timeoutMs: 5000 });
      const other = await fair.acquire({ tenantId: "b", taskId: "t3" }, { timeoutMs: 100 });
      ok(p, fair.snapshot().waiting === 1, "tenant A's second run is not waiting");
      r1();
      (await blocked)();
      other();
      const forks = createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 4, forkShare: 1 });
      const f1 = await forks.acquire(
        { tenantId: "a", taskId: "t1", fork: true },
        { timeoutMs: 1000 },
      );
      ok(
        p,
        (await rejects(
          () => forks.acquire({ tenantId: "a", taskId: "t2", fork: true }, { timeoutMs: 30 }),
          ["capacity"],
        )) === null,
        "a second fork run was admitted",
      );
      const trusted = await forks.acquire({ tenantId: "a", taskId: "t3" }, { timeoutMs: 100 });
      trusted();
      f1();
      for (const bad of [
        { ...limits, perWorker: 0 },
        { ...limits, perTenant: 1.5 },
        { ...limits, forkShare: -1 },
        { perWorker: 1 },
      ])
        ok(
          p,
          throwsCode(() => createCapacityGate(bad), ["invalid_config"]) === null,
          `invalid limits ${JSON.stringify(bad)}`,
        );
      return p;
    },
  },
];
