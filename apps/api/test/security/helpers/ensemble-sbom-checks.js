import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertRunArgsSafe,
  buildRunArgs,
  resolveRunSpecImage,
  validateRunSpec,
  validateSandboxConfig,
} from "@qmentisai/infra";
import { loadImageLock } from "../../../../workers/src/execution/engines/ensemble/catalog/index.js";
import {
  canonicalPurl,
  runToolParse,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import {
  SBOM_MAX_PATHS,
  SBOM_MAX_RECORDS,
  SBOM_MAX_SCANNED_COMPONENTS,
  SYFT_ARGV,
  TRIVY_SBOM_ARGV,
  collectSbomLiteStreams,
  createSbomAdapterRegistry,
  createSbomLiteAdapter,
  createSyftAdapter,
  createTrivySbomAdapter,
  isPackageComponent,
  mapSbomRecord,
  relativeLocation,
  runSbomEnsemble,
  sbomRecordSchema,
  trivyRefPaths,
} from "../../../../workers/src/execution/engines/ensemble/sbom/index.js";
import { inventoryArchive } from "../../../../workers/src/execution/engines/sbom/index.js";
import { CONFIG_INPUT } from "./sandbox-checks.js";
import { TASK_A } from "./ensemble-fakes.js";

/**
 * Scan engines, part E (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S03, S06, S09 and 16.1 part E): the SBOM ensemble (Syft and
 * Trivy in SBOM mode over CycloneDX JSON, the `sbom-lite` adapter, the component merge) over HAND-WRITTEN fixtures. No container,
 * process, database or network is used. NOT proved: that the fixtures resemble real Syft or Trivy output (they were written from
 * the tools' documented formats and from memory; fidelity is the live test ENG-L11), that the real tools run with these command
 * lines (ENG-L01, ENG-L06), or the purl normalization rules against the purl specification (OQ-5, still to verify).
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const SBOM_DIR = path.join(ROOT, "apps/workers/src/execution/engines/ensemble/sbom");
const FIX = path.join(ROOT, "apps/api/test/security/fixtures/scan-engines/sbom");
const fixture = (name) => readFileSync(path.join(FIX, name));
const DIGEST_SYFT = `sha256:${"a1".repeat(32)}`;
const DIGEST_TRIVY = `sha256:${"b2".repeat(32)}`;
const RUN = {
  syft: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  trivy: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  lite: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
};
const SYFT = createSyftAdapter();
const TRIVY = createTrivySbomAdapter();
const LITE = createSbomLiteAdapter();
const ADAPTER_OF = { syft: SYFT, trivy: TRIVY, "sbom-lite": LITE };
const ctx = (toolRunId, imageDigest, over = {}) => ({
  toolRunId,
  toolVersion: "fixture-1",
  imageDigest,
  ...over,
});
const run = (adapter, stdout, over = {}, limits) =>
  runToolParse(
    adapter,
    { stdout, exitCode: 0, ...over.streams },
    { taskRef: TASK_A, ...ctx(RUN.syft, DIGEST_SYFT), ...over.ctx },
    limits,
  );
const fixtureRuns = () => [
  {
    adapter: SYFT,
    streams: { stdout: fixture("syft-cyclonedx.json"), exitCode: 0 },
    ctx: ctx(RUN.syft, DIGEST_SYFT),
  },
  {
    adapter: TRIVY,
    streams: { stdout: fixture("trivy-cyclonedx.json"), exitCode: 0 },
    ctx: ctx(RUN.trivy, DIGEST_TRIVY),
  },
  {
    adapter: LITE,
    streams: { stdout: fixture("sbom-lite-items.json"), exitCode: 0 },
    ctx: ctx(RUN.lite, null),
  },
];
const ok = (problems, condition, message) => {
  if (!condition) problems.push(message);
};
const eq = (problems, label, got, want) =>
  ok(
    problems,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );
const throwsCode = (fn) => {
  try {
    fn();
  } catch (e) {
    return e?.code ?? e?.reason ?? `non-coded ${e?.name}`;
  }
  return null;
};
const cdx = (components, over = {}) =>
  Buffer.from(
    JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components, ...over }),
  );
const lib = (purl, over = {}) => ({ type: "library", name: "n", purl, ...over });
const listJs = (dir) =>
  readdirSync(dir).flatMap((f) => {
    const p = path.join(dir, f);
    return statSync(p).isDirectory() ? listJs(p) : p.endsWith(".js") ? [p] : [];
  });

export const ENSEMBLE_SBOM_CHECKS = [
  {
    id: "ENG-S03c",
    name: "the SBOM tool invocations are sealed and contain nothing from the repository (SPEC scan-engines 6.2, 11.3, 14.1 ENG-S01 and ENG-S03, part E): the Syft and Trivy (SBOM mode) plans resolve to the locked digests, pass RunSpec validation and the argument audit, carry the platform configuration flag (`-c /rules/syft.yaml`, `--config /rules/trivy.yaml`), the update check and telemetry switches, read-only mounts of the tree and the rules only (no database, no paths), the fixed working directory /tmp, and equal the sealed command lines documented in IMAGES.md; the argument vector is the same constant whatever the tree or the task, the wall clock is capped by the task deadline; the SBOM module imports no process, file-system or network module (the legacy bridge excepted), reads no environment, is imported by nothing in the worker, registers Syft and Trivy only when the ensemble is enabled (strictly true) and keeps the legacy engine as the registered default; the platform configuration files exist and carry no ignore or exclude setting",
    async run() {
      const p = [];
      const config = validateSandboxConfig(CONFIG_INPUT);
      const { resolver } = loadImageLock();
      const planCtx = (over = {}) => ({
        tenantId: "tenant-1",
        executionId: "exec-1",
        taskId: "11111111-aaaa-4aaa-8aaa-111111111111",
        attempt: 1,
        deadlineEpoch: 1790000000,
        archiveDir: "/tmp/qm-scan/tree-1",
        rulesDir: "/opt/qm/rules/syft",
        ...over,
      });
      const images = readFileSync(path.join(ROOT, "docs/modules/scan-engines/IMAGES.md"), "utf8");
      for (const [adapter, argv, rulesTool, flags] of [
        [SYFT, SYFT_ARGV, "syft", ["-c", "/rules/syft.yaml", "dir:/src", "-o", "cyclonedx-json"]],
        [
          TRIVY,
          TRIVY_SBOM_ARGV,
          "trivy",
          [
            "fs",
            "--config",
            "/rules/trivy.yaml",
            "--scanners",
            "license",
            "--format",
            "cyclonedx",
            "/src",
          ],
        ],
      ]) {
        const plan = adapter.plan(planCtx({ rulesDir: `/opt/qm/rules/${rulesTool}` }));
        eq(p, `${adapter.toolId} argv`, plan.argv, flags);
        ok(p, argv.join(" ") === flags.join(" "), `${adapter.toolId}: constant differs`);
        ok(
          p,
          images.includes(flags.join(" ")),
          `${adapter.toolId}: IMAGES.md has a different sealed command`,
        );
        ok(p, Object.isFrozen(argv), `${adapter.toolId}: the argv constant is mutable`);
        const spec = resolveRunSpecImage(plan, resolver, { scanType: "sbom" });
        ok(p, /@sha256:[0-9a-f]{64}$/.test(spec.image), `${adapter.toolId}: image is not a digest`);
        const validated = validateRunSpec(spec, config);
        const args = buildRunArgs(validated, config);
        assertRunArgsSafe(args, config);
        const joined = args.join("\n");
        for (const needle of [
          "--network=none",
          "--read-only",
          "--cap-drop=ALL",
          "--pull=never",
          "--workdir=/tmp",
          `--mount=type=bind,src=/tmp/qm-scan/tree-1,dst=/src,readonly`,
          `--mount=type=bind,src=/opt/qm/rules/${rulesTool},dst=/rules,readonly`,
        ])
          ok(p, joined.includes(needle), `${adapter.toolId}: missing ${needle}`);
        ok(p, !joined.includes("dst=/db"), `${adapter.toolId}: mounts a database`);
        ok(
          p,
          !("paths" in plan) && !args.includes("--"),
          `${adapter.toolId}: passes repository paths`,
        );
        ok(
          p,
          args.filter((a) => a.startsWith("--mount=")).length === 2,
          `${adapter.toolId}: mount count`,
        );
        // the vector never depends on the tree or the task
        const other = adapter.plan(
          planCtx({
            rulesDir: `/opt/qm/rules/${rulesTool}`,
            taskId: "99999999-aaaa-4aaa-8aaa-999999999999",
            archiveDir: "/tmp/qm-scan/--config=evil; rm -rf",
          }),
        );
        eq(p, `${adapter.toolId} constant argv`, other.argv, plan.argv);
        // the wall clock is the smaller of the tool limit and the task seconds left
        ok(
          p,
          adapter.plan(planCtx({ secondsToDeadline: 7 })).limits.wallClockSeconds === 7,
          `${adapter.toolId}: deadline`,
        );
        ok(
          p,
          adapter.plan(planCtx({ secondsToDeadline: 100000 })).limits.wallClockSeconds ===
            plan.limits.wallClockSeconds,
          `${adapter.toolId}: limit raised by a long deadline`,
        );
        ok(
          p,
          adapter.plan(planCtx({ secondsToDeadline: 0 })).limits.wallClockSeconds ===
            plan.limits.wallClockSeconds,
          `${adapter.toolId}: zero seconds`,
        );
        ok(
          p,
          throwsCode(() => adapter.plan({ ...planCtx(), archiveDir: undefined })) !== null,
          `${adapter.toolId}: plan accepted a missing mount`,
        );
        ok(
          p,
          throwsCode(() => adapter.plan({ ...planCtx(), attempt: "1" })) !== null,
          `${adapter.toolId}: plan accepted a text attempt`,
        );
      }
      // the limits are the Recommended numbers of SPEC 5.8 (the temporary file system is not in the table) and are frozen constants
      const MiB = 1048576;
      eq(p, "syft limits", SYFT.plan(planCtx()).limits, {
        cpus: 1,
        memoryMiB: 1024,
        pids: 128,
        wallClockSeconds: 180,
        stdoutBytes: 64 * MiB,
        tmpfsMiB: 512,
      });
      eq(p, "trivy limits", TRIVY.plan(planCtx()).limits, {
        cpus: 2,
        memoryMiB: 2048,
        pids: 256,
        wallClockSeconds: 300,
        stdoutBytes: 64 * MiB,
        tmpfsMiB: 512,
      });
      eq(
        p,
        "one second left",
        SYFT.plan(planCtx({ secondsToDeadline: 1 })).limits.wallClockSeconds,
        1,
      );
      eq(
        p,
        "a fractional or negative deadline is ignored",
        [
          SYFT.plan(planCtx({ secondsToDeadline: 1.5 })).limits.wallClockSeconds,
          SYFT.plan(planCtx({ secondsToDeadline: -4 })).limits.wallClockSeconds,
        ],
        [180, 180],
      );
      for (const key of ["tenantId", "executionId", "taskId", "archiveDir", "rulesDir"]) {
        ok(
          p,
          throwsCode(() => SYFT.plan(planCtx({ [key]: "" }))) !== null,
          `plan accepted an empty ${key}`,
        );
        ok(
          p,
          throwsCode(() => SYFT.plan(planCtx({ [key]: 7 }))) !== null,
          `plan accepted a numeric ${key}`,
        );
        ok(
          p,
          throwsCode(() => SYFT.plan(planCtx({ [key]: "x" }))) === null,
          `plan refused a one-character ${key}`,
        );
      }
      ok(
        p,
        throwsCode(() => SYFT.plan(planCtx({ deadlineEpoch: 1.5 }))) !== null,
        "plan accepted a fractional deadline",
      );
      ok(p, throwsCode(() => SYFT.plan(undefined)) !== null, "plan accepted no context");
      eq(p, "sbom-lite plan", LITE.plan({}), { toolId: "sbom-lite", inProcess: true });
      // the limits are the Recommended numbers of SPEC 5.8 (the temporary file system is not in the table) and are frozen constants
      eq(p, "syft limits", SYFT.plan(planCtx()).limits, {
        cpus: 1,
        memoryMiB: 1024,
        pids: 128,
        wallClockSeconds: 180,
        stdoutBytes: 64 * MiB,
        tmpfsMiB: 512,
      });
      eq(p, "trivy limits", TRIVY.plan(planCtx()).limits, {
        cpus: 2,
        memoryMiB: 2048,
        pids: 256,
        wallClockSeconds: 300,
        stdoutBytes: 64 * MiB,
        tmpfsMiB: 512,
      });
      eq(
        p,
        "one second left",
        SYFT.plan(planCtx({ secondsToDeadline: 1 })).limits.wallClockSeconds,
        1,
      );
      eq(
        p,
        "a fractional or negative deadline is ignored",
        [
          SYFT.plan(planCtx({ secondsToDeadline: 1.5 })).limits.wallClockSeconds,
          SYFT.plan(planCtx({ secondsToDeadline: -4 })).limits.wallClockSeconds,
        ],
        [180, 180],
      );
      for (const key of ["tenantId", "executionId", "taskId", "archiveDir", "rulesDir"]) {
        ok(
          p,
          throwsCode(() => SYFT.plan(planCtx({ [key]: "" }))) !== null,
          `plan accepted an empty ${key}`,
        );
        ok(
          p,
          throwsCode(() => SYFT.plan(planCtx({ [key]: 7 }))) !== null,
          `plan accepted a numeric ${key}`,
        );
        ok(
          p,
          throwsCode(() => SYFT.plan(planCtx({ [key]: "x" }))) === null,
          `plan refused a one-character ${key}`,
        );
      }
      ok(
        p,
        throwsCode(() => SYFT.plan(planCtx({ deadlineEpoch: 1.5 }))) !== null,
        "plan accepted a fractional deadline",
      );
      ok(p, throwsCode(() => SYFT.plan(undefined)) !== null, "plan accepted no context");
      eq(p, "sbom-lite plan", LITE.plan({}), { toolId: "sbom-lite", inProcess: true });
      const syftEnv = SYFT.plan(planCtx()).env;
      eq(p, "syft env", syftEnv, { SYFT_CHECK_FOR_APP_UPDATE: "false" });
      eq(p, "trivy env", TRIVY.plan(planCtx()).env, {
        TRIVY_SKIP_VERSION_CHECK: "true",
        TRIVY_DISABLE_TELEMETRY: "true",
        TRIVY_CACHE_DIR: "/tmp/c",
      });
      // control: the audit is not vacuous (a tampered vector is refused)
      const good = validateRunSpec(
        resolveRunSpecImage(SYFT.plan(planCtx()), resolver, { scanType: "sbom" }),
        config,
      );
      const args = buildRunArgs(good, config);
      ok(
        p,
        throwsCode(() =>
          assertRunArgsSafe(
            [...args.filter((a) => a !== "--network=none"), "--network=host"],
            config,
          ),
        ) !== null,
        "control: a host network vector was accepted",
      );
      // registry: the legacy path is always there, the ensemble tools only when enabled
      const ids = (r) => r.select("sbom").map((a) => a.toolId);
      eq(p, "default registry", ids(createSbomAdapterRegistry()), ["sbom-lite"]);
      eq(p, "enabled registry", ids(createSbomAdapterRegistry({ ensembleEnabled: true })), [
        "sbom-lite",
        "syft",
        "trivy",
      ]);
      for (const flag of ["true", 1, "yes", {}, [], undefined, null, false])
        eq(
          p,
          `flag ${JSON.stringify(flag)}`,
          ids(createSbomAdapterRegistry({ ensembleEnabled: flag })),
          ["sbom-lite"],
        );
      // source guards
      const FORBIDDEN_IMPORT =
        /from\s+["'](node:(child_process|net|http|https|http2|dgram|dns|tls|fs|fs\/promises|worker_threads|vm|cluster|os|path)|child_process|fs|net|http|https|@qmentisai\/db|@prisma\/client|ioredis|amqplib|socket\.io)/;
      const FORBIDDEN_CALL =
        /\b(eval\s*\(|new Function\s*\(|import\s*\(|fetch\s*\(|Date\.now\s*\(|new Date\s*\(|Math\.random\s*\(|process\.|execFile|spawn\s*\()/;
      for (const file of listJs(SBOM_DIR)) {
        const src = readFileSync(file, "utf8")
          .replace(/\/\*[\s\S]*?\*\//g, "")
          .replace(/^\s*\/\/.*$/gm, "");
        const name = path.relative(ROOT, file);
        ok(p, !FORBIDDEN_IMPORT.test(src), `${name}: a forbidden import`);
        ok(
          p,
          !FORBIDDEN_CALL.test(src),
          `${name}: a forbidden call (${FORBIDDEN_CALL.exec(src)?.[0]})`,
        );
        for (const m of src.matchAll(/from\s+["']([^"']+)["']/g))
          if (!m[1].startsWith("."))
            ok(
              p,
              ["zod", "@qmentisai/shared"].includes(m[1]),
              `${name}: unexpected dependency ${m[1]}`,
            );
          else {
            const target = path.resolve(path.dirname(file), m[1]);
            const inside =
              target.startsWith(SBOM_DIR) ||
              target.startsWith(path.join(SBOM_DIR, "../core")) ||
              (file.endsWith("sbom-lite.js") && target.endsWith("engines/sbom/index.js"));
            ok(p, inside, `${name}: imports outside the SBOM ensemble (${m[1]})`);
          }
      }
      // nothing in the worker imports the SBOM ensemble before part K; the legacy engine is untouched
      for (const file of listJs(path.join(ROOT, "apps/workers/src"))) {
        if (file.startsWith(SBOM_DIR)) continue;
        ok(
          p,
          !/ensemble\/sbom/.test(readFileSync(file, "utf8")),
          `${path.relative(ROOT, file)}: imports the SBOM ensemble before part K`,
        );
      }
      const registry = readFileSync(
        path.join(ROOT, "apps/workers/src/execution/engines.js"),
        "utf8",
      );
      ok(p, !/ensemble/.test(registry), "the engine registry mentions the ensemble");
      const legacy = readFileSync(
        path.join(ROOT, "apps/workers/src/execution/engines/sbom/index.js"),
        "utf8",
      );
      ok(
        p,
        /scanType: "sbom",\s+engineId: "default"/.test(legacy),
        "the legacy SBOM engine is no longer sbom/default",
      );
      // platform configuration files
      for (const name of ["syft.yaml", "trivy.yaml"]) {
        const cfg = readFileSync(path.join(SBOM_DIR, "rules", name), "utf8")
          .split("\n")
          .filter((l) => !l.trim().startsWith("#"))
          .join("\n");
        ok(p, cfg.trim().length > 0, `${name} has no setting`);
        ok(p, !/exclude|ignore|skip|path|file|scan/i.test(cfg), `${name} changes what is scanned`);
      }
      return p;
    },
  },
  {
    id: "ENG-S06e",
    name: "SBOM ensemble mapping and merge on hand-written Syft, Trivy and sbom-lite fixtures (SPEC scan-engines 5.6.1, 7.2, SE-12 to SE-14, OQ-14, ENG-S06, part E; the fixtures are NOT real tool output and their fidelity is unverified): packages are read from CycloneDX JSON only (files, operating systems, lockfile applications and the scanned root are bookkeeping, never components), the purl is canonicalized (Django, scoped npm, Go case) so the tools agree, a component listed twice by one tool becomes one record with all its locations (never two findings of one tool), Trivy locations come from the lockfile application and the dependency graph, Syft locations from its properties, two tools agreeing give one finding with two provenance entries and confidence high (a single tool stays medium), the strongest scope wins, a declared-only range is dropped next to a locked version in the same directory, the output is identical for any component order and for a second run, one failing tool degrades the task (row 6) and all failing tools fail it (row 7), the roll-up of a clean run is complete and eligible, locations are capped at 20 with the exact count, and the sbom-lite adapter yields the same components as the legacy inventory it wraps",
    async run() {
      const p = [];
      const result = runSbomEnsemble({ taskRef: TASK_A, runs: fixtureRuns() });
      const byPurl = new Map(result.findings.map((f) => [f.component.purl, f]));
      eq(
        p,
        "tool outcomes",
        result.outcomes.map((o) => [o.toolId, o.status, o.reason, o.recordsSeen, o.recordsDropped]),
        [
          ["syft", "succeeded", null, 7, 0],
          ["trivy", "succeeded", null, 7, 0],
          ["sbom-lite", "succeeded", null, 5, 0],
        ],
      );
      eq(
        p,
        "roll-up",
        [
          result.rollup.taskStatus,
          result.rollup.completeness,
          result.rollup.matchedRow,
          result.rollup.resolutionEligible,
        ],
        ["succeeded", "complete", 5, true],
      );
      eq(p, "stats", result.stats, {
        candidates: 19,
        findings: 9,
        merged: 9,
        redundantComponents: 1,
      });
      eq(p, "purls", [...byPurl.keys()].sort(), [
        "pkg:cargo/only-lite@0.1.0",
        "pkg:golang/github.com/foo/bar@v1.2.3",
        "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        "pkg:npm/%40babel/core@7.20.0",
        "pkg:npm/express@4.18.2",
        "pkg:npm/lodash@4.17.20",
        "pkg:npm/only-syft@1.0.0",
        "pkg:npm/only-trivy@2.0.0",
        "pkg:pypi/django@3.2",
      ]);
      const tools = (purl) =>
        byPurl
          .get(purl)
          ?.provenance.map((x) => x.toolId)
          .join("+");
      eq(p, "lodash tools", tools("pkg:npm/lodash@4.17.20"), "sbom-lite+syft+trivy");
      eq(p, "django tools (case folded)", tools("pkg:pypi/django@3.2"), "sbom-lite+syft+trivy");
      eq(p, "go tools (case folded)", tools("pkg:golang/github.com/foo/bar@v1.2.3"), "syft+trivy");
      eq(p, "scoped npm tools", tools("pkg:npm/%40babel/core@7.20.0"), "syft+trivy");
      eq(p, "only syft", tools("pkg:npm/only-syft@1.0.0"), "syft");
      eq(p, "only trivy", tools("pkg:npm/only-trivy@2.0.0"), "trivy");
      eq(p, "only lite", tools("pkg:cargo/only-lite@0.1.0"), "sbom-lite");
      for (const [purl, f] of byPurl) {
        const multi = f.provenance.length > 1;
        eq(
          p,
          `${purl} confidence`,
          [f.confidence, f.confidenceBasis],
          multi ? ["high", "multi_tool"] : ["medium", "tool"],
        );
        eq(
          p,
          `${purl} severity`,
          [f.severity, f.severityAssumed, f.kind],
          ["info", false, "component"],
        );
        ok(
          p,
          new Set(f.provenance.map((x) => x.toolId)).size === f.provenance.length,
          `${purl}: a tool twice in provenance`,
        );
      }
      // locations: Syft properties, Trivy graph, folded duplicates
      eq(
        p,
        "lodash locations",
        [
          byPurl.get("pkg:npm/lodash@4.17.20").locations,
          byPurl.get("pkg:npm/lodash@4.17.20").locationCount,
        ],
        [[{ path: "package-lock.json" }, { path: "web/package-lock.json" }], 2],
      );
      eq(p, "django locations", byPurl.get("pkg:pypi/django@3.2").locations, [
        { path: "py/requirements.txt" },
      ]);
      eq(p, "go locations", byPurl.get("pkg:golang/github.com/foo/bar@v1.2.3").locations, [
        { path: "go/go.mod" },
      ]);
      eq(
        p,
        "maven locations",
        byPurl.get("pkg:maven/org.apache.commons/commons-lang3@3.12.0").locations,
        [{ path: "java/pom.xml" }],
      );
      eq(
        p,
        "syft rule id is the cataloger",
        byPurl.get("pkg:npm/only-syft@1.0.0").provenance[0].ruleId,
        "javascript-lock-cataloger",
      );
      // scope: the strongest wins (required -> prod, the legacy dev beats unknown)
      eq(
        p,
        "scopes",
        [
          "pkg:npm/only-syft@1.0.0",
          "pkg:npm/lodash@4.17.20",
          "pkg:npm/express@4.18.2",
          "pkg:npm/only-trivy@2.0.0",
        ].map((k) => byPurl.get(k).component.scope),
        ["prod", "prod", "dev", undefined],
      );
      // declared-only range next to the locked version
      ok(p, !byPurl.has("pkg:npm/express"), "the declared-only range was kept");
      // no confusing duplicates: one finding per canonical component, one record per component and tool
      ok(p, byPurl.size === result.findings.length, "two findings share a canonical purl");
      for (const runItem of fixtureRuns()) {
        const out = run(runItem.adapter, runItem.streams.stdout, { ctx: runItem.ctx });
        const purls = out.candidates.map((c) => c.component.purl);
        ok(
          p,
          new Set(purls).size === purls.length,
          `${runItem.adapter.toolId}: duplicate components from one tool`,
        );
      }
      // determinism: any component order and a second run give the same bytes
      const shuffled = (name) => {
        const doc = JSON.parse(fixture(name));
        doc.components.reverse();
        doc.dependencies?.reverse();
        return Buffer.from(JSON.stringify(doc));
      };
      const again = runSbomEnsemble({
        taskRef: TASK_A,
        runs: fixtureRuns().map((r, i) =>
          i === 0
            ? { ...r, streams: { ...r.streams, stdout: shuffled("syft-cyclonedx.json") } }
            : i === 1
              ? { ...r, streams: { ...r.streams, stdout: shuffled("trivy-cyclonedx.json") } }
              : r,
        ),
      });
      eq(p, "second run", again.findings, result.findings);
      // the merge cannot use a record of another task (the framework stamps the task from trusted context)
      ok(
        p,
        result.findings.every((f) => !("taskRef" in f)),
        "a finding carries the task reference",
      );
      // one failing tool degrades, all failing tools fail
      const degraded = runSbomEnsemble({
        taskRef: TASK_A,
        runs: fixtureRuns().map((r, i) =>
          i === 1 ? { ...r, streams: { stdout: Buffer.from("not json"), exitCode: 0 } } : r,
        ),
      });
      eq(
        p,
        "degraded",
        [
          degraded.outcomes[1].status,
          degraded.outcomes[1].reason,
          degraded.rollup.taskStatus,
          degraded.rollup.matchedRow,
          degraded.rollup.completeness,
          degraded.rollup.resolutionEligible,
        ],
        ["failed", "output_invalid", "succeeded", 6, "incomplete", false],
      );
      ok(
        p,
        degraded.findings.some((f) => f.component.purl === "pkg:npm/lodash@4.17.20"),
        "a degraded run lost its findings",
      );
      ok(
        p,
        !degraded.findings.some((f) => f.component.purl === "pkg:npm/only-trivy@2.0.0"),
        "a failed tool's component was kept",
      );
      const dead = runSbomEnsemble({
        taskRef: TASK_A,
        runs: fixtureRuns().map((r) => ({
          ...r,
          streams: { stdout: Buffer.from("x"), exitCode: 3 },
        })),
      });
      eq(
        p,
        "all failed",
        [dead.rollup.taskStatus, dead.rollup.reason, dead.rollup.matchedRow, dead.findings.length],
        ["failed", "tools_failed", 7, 0],
      );
      const skipped = runSbomEnsemble({
        taskRef: TASK_A,
        runs: [
          { toolId: "syft", status: "skipped", reason: "no_applicable_files" },
          { toolId: "trivy", status: "skipped", reason: "no_applicable_files" },
        ],
        relevantFilesExist: false,
      });
      eq(
        p,
        "nothing to scan",
        [skipped.rollup.coverageState, skipped.rollup.completeness, skipped.findings.length],
        ["nothing_to_scan", "complete", 0],
      );
      const gap = runSbomEnsemble({
        taskRef: TASK_A,
        runs: [{ toolId: "syft", status: "skipped", reason: "no_applicable_files" }],
      });
      eq(
        p,
        "relevant files are assumed by default",
        [gap.rollup.coverageState, gap.rollup.completeness, gap.rollup.matchedRow],
        ["language_gap", "incomplete", 4],
      );
      // an empty but valid document is a clean, empty run
      const empty = run(SYFT, cdx([]));
      eq(
        p,
        "empty document",
        [empty.status, empty.candidates.length, empty.recordsSeen],
        ["succeeded", 0, 0],
      );
      // location cap with the exact count, folded duplicates
      const many = cdx(
        Array.from({ length: 100 }, (_, i) =>
          lib("pkg:npm/many@1.0.0", {
            properties: [
              {
                name: "syft:location:0:path",
                value: `/d${String(i).padStart(3, "0")}/package-lock.json`,
              },
            ],
          }),
        ),
      );
      const capped = run(SYFT, many);
      eq(
        p,
        "folded and capped",
        [
          capped.candidates.length,
          capped.candidates[0].locations.length,
          capped.candidates[0].locationCount,
          capped.recordsSeen,
        ],
        [1, SBOM_MAX_PATHS, 100, 1],
      );
      // scope of a component listed twice: required beats excluded
      const twice = run(
        SYFT,
        cdx([
          lib("pkg:npm/s@1", { scope: "excluded" }),
          lib("pkg:npm/s@1", { scope: "required" }),
          lib("pkg:npm/s@1", { scope: "optional" }),
        ]),
      );
      eq(p, "strongest scope", twice.candidates[0].component.scope, "prod");
      eq(
        p,
        "scope order dev over optional",
        run(
          SYFT,
          cdx([
            lib("pkg:npm/t@1", { scope: "optional" }),
            lib("pkg:npm/t@1", { scope: "excluded" }),
          ]),
        ).candidates[0].component.scope,
        "dev",
      );
      eq(
        p,
        "no scope stays absent",
        "scope" in run(SYFT, cdx([lib("pkg:npm/u@1")])).candidates[0].component,
        false,
      );
      eq(
        p,
        "unknown scope word is no scope",
        "scope" in run(SYFT, cdx([lib("pkg:npm/v@1", { scope: "weird" })])).candidates[0].component,
        false,
      );
      // package types
      const types = run(
        SYFT,
        cdx([
          { type: "file", name: "f", purl: "pkg:generic/f@1" },
          { type: "operating-system", name: "debian" },
          { type: "application", name: "package-lock.json" },
          { type: "application", name: "app", purl: "pkg:generic/app@1" },
          { type: "framework", name: "fw", purl: "pkg:npm/fw@1" },
          lib("pkg:npm/lib@1"),
        ]),
      );
      eq(p, "package types", types.candidates.map((c) => c.component.purl).sort(), [
        "pkg:generic/app@1",
        "pkg:npm/fw@1",
        "pkg:npm/lib@1",
      ]);
      // purl-derived names, versions, ecosystems
      const scoped = run(
        SYFT,
        cdx([
          lib("pkg:npm/%40Babel/Core@7.0.0"),
          lib("pkg:maven/org.x/y@1?type=jar&repository_url=evil"),
        ]),
      ).candidates;
      eq(
        p,
        "derived fields",
        scoped.map((c) => [c.component.name, c.component.version, c.component.ecosystem, c.title]),
        [
          ["org.x/y", "1", "maven", "org.x/y@1"],
          ["@babel/core", "7.0.0", "npm", "@babel/core@7.0.0"],
        ],
      );
      ok(p, !scoped[0].component.purl.includes("repository_url"), "a dropped qualifier survived");
      // an unversioned purl gives an unversioned component
      eq(
        p,
        "unversioned",
        "version" in run(SYFT, cdx([lib("pkg:npm/nov")])).candidates[0].component,
        false,
      );
      // the mapper is total on every record of every fixture
      for (const runItem of fixtureRuns()) {
        const doc = JSON.parse(runItem.streams.stdout);
        ok(
          p,
          Array.isArray(doc) ||
            doc.metadata.properties.some(
              (x) => x.name === "qm:fixture" && /NOT real tool output/.test(x.value),
            ),
          `${runItem.adapter.toolId}: the fixture does not say it is hand-written`,
        );
      }
      // each tool's OWN locations (the merge would otherwise hide a broken extractor)
      const own = (adapter, name) =>
        run(adapter, fixture(name))
          .candidates.map((c) => [
            c.component.purl,
            c.locations.map((l) => l.path),
            c.locationCount,
          ])
          .sort((a, b) => (a[0] < b[0] ? -1 : 1));
      const wantOwn = (extra) =>
        [
          ["pkg:golang/github.com/foo/bar@v1.2.3", ["go/go.mod"], 1],
          ["pkg:maven/org.apache.commons/commons-lang3@3.12.0", ["java/pom.xml"], 1],
          ["pkg:npm/%40babel/core@7.20.0", ["package-lock.json"], 1],
          ["pkg:npm/express@4.18.2", ["package-lock.json"], 1],
          ["pkg:npm/lodash@4.17.20", ["package-lock.json", "web/package-lock.json"], 2],
          extra,
          ["pkg:pypi/django@3.2", ["py/requirements.txt"], 1],
        ].sort((a, b) => (a[0] < b[0] ? -1 : 1));
      eq(
        p,
        "syft own locations",
        own(SYFT, "syft-cyclonedx.json"),
        wantOwn(["pkg:npm/only-syft@1.0.0", ["package-lock.json"], 1]),
      );
      eq(
        p,
        "trivy own locations",
        own(TRIVY, "trivy-cyclonedx.json"),
        wantOwn(["pkg:npm/only-trivy@2.0.0", ["package-lock.json"], 1]),
      );
      for (const [adapter, name] of [
        [SYFT, "syft-cyclonedx.json"],
        [TRIVY, "trivy-cyclonedx.json"],
      ])
        ok(
          p,
          run(adapter, fixture(name)).candidates.every(
            (c) => c.location.path === c.locations[0].path,
          ),
          `${adapter.toolId}: the location is not the first occurrence`,
        );
      for (const [adapter, name] of [
        [SYFT, "syft-cyclonedx.json"],
        [TRIVY, "trivy-cyclonedx.json"],
      ])
        ok(
          p,
          run(adapter, fixture(name)).candidates.every(
            (c) => c.location.path === c.locations[0].path,
          ),
          `${adapter.toolId}: the location is not the first occurrence`,
        );
      // Trivy's lockfile applications: direct dependsOn only, safe names only, no purl, de-duplicated
      const app = (ref, name, extra = {}) => ({
        type: "application",
        "bom-ref": ref,
        name,
        ...extra,
      });
      const graph = trivyRefPaths({
        components: [
          app("a1", "package-lock.json"),
          app("a2", "x/y.lock"),
          app("a3", "with-purl", { purl: "pkg:npm/z@1" }),
          app("a4", "../evil"),
          { type: "library", "bom-ref": "a5", name: "l" },
          { type: "application", name: "noref" },
          { type: "application", "bom-ref": "a6" },
          null,
          5,
        ],
        dependencies: [
          { ref: "a1", dependsOn: ["l1", 5, null, "l2", "l1"] },
          { ref: "a2", dependsOn: ["l1"] },
          { ref: "a3", dependsOn: ["l9"] },
          { ref: "a4", dependsOn: ["l8"] },
          { ref: "a5", dependsOn: ["l7"] },
          { ref: "zz", dependsOn: ["l6"] },
          { ref: "a1", dependsOn: "not an array" },
          null,
          7,
        ],
      });
      eq(
        p,
        "trivy graph",
        [...graph.entries()],
        [
          ["l1", ["package-lock.json", "x/y.lock"]],
          ["l2", ["package-lock.json"]],
        ],
      );
      eq(
        p,
        "trivy graph of nothing",
        [trivyRefPaths({}).size, trivyRefPaths({ components: "x", dependencies: "y" }).size],
        [0, 0],
      );
      eq(
        p,
        "relative locations",
        ["/a/b", "./a", "././a", "//a", "a", "/", "", "../a", "a/../b", 5, null, undefined].map(
          relativeLocation,
        ),
        ["a/b", "a", "a", null, "a", null, null, null, null, null, null, null],
      );
      eq(
        p,
        "package components",
        [
          { type: "library" },
          { type: "framework" },
          { type: "application" },
          { type: "application", purl: "pkg:npm/a@1" },
          { type: "application", purl: "" },
          { type: "application", purl: "x" },
          { type: "file", purl: "pkg:npm/a@1" },
          { type: "operating-system" },
        ].map(isPackageComponent),
        [true, true, false, true, false, true, false, false],
      );
      eq(
        p,
        "a pathless record has no location keys",
        Object.keys(mapSbomRecord({ purl: "pkg:npm/m@1", paths: [], pathCount: 0 })).filter((k) =>
          k.startsWith("location"),
        ),
        [],
      );
      eq(
        p,
        "mapper on a minimal record",
        mapSbomRecord({ purl: "pkg:npm/m@1", paths: [], pathCount: 0 }).component,
        { purl: "pkg:npm/m@1", name: "m", version: "1", ecosystem: "npm" },
      );
      ok(
        p,
        !sbomRecordSchema.safeParse({ purl: "pkg:npm/m@1", paths: [], pathCount: 0, extra: 1 })
          .success,
        "the record schema accepted an unknown key",
      );
      return p;
    },
  },
  {
    id: "ENG-S06f",
    name: "the sbom-lite adapter wraps the legacy inventory without changing it (SPEC scan-engines 5.10, OQ-18, executions 17.ab, part E): over a temporary tree with lockfiles in two directories the adapter reports exactly the components of the legacy inventory (canonical purls, manifests as locations, one record per component even when it is listed by several manifests), the legacy engine still emits one item per component and manifest, a truncated or incomplete inventory is reported beside the streams and not as cut output, an aborted signal aborts, and no component, path or purl is invented",
    async run() {
      const p = [];
      const dir = mkdtempSync(path.join(os.tmpdir(), "qm-sbom-lite-"));
      try {
        const write = (rel, text) => {
          mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
          writeFileSync(path.join(dir, rel), text);
        };
        const lock = (deps) =>
          JSON.stringify({
            lockfileVersion: 3,
            packages: {
              "": { name: "root" },
              ...Object.fromEntries(
                Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v }]),
              ),
            },
          });
        write("package-lock.json", lock({ lodash: "4.17.20", express: "4.18.2" }));
        write("web/package-lock.json", lock({ lodash: "4.17.20" }));
        write("py/requirements.txt", "Django==3.2\nrequests==2.31.0\n");
        write("go/go.mod", "module x\n\ngo 1.21\n\nrequire github.com/Foo/Bar v1.2.3\n");
        write("package.json", JSON.stringify({ dependencies: { express: "^4.18.0" } }));
        const signal = new AbortController().signal;
        const legacyItems = [];
        const legacy = await inventoryArchive(
          { sourceDir: dir },
          { signal, emit: (i) => legacyItems.push(i) },
        );
        ok(
          p,
          legacyItems.length >= 6,
          `control: the legacy inventory emitted ${legacyItems.length} items`,
        );
        const collected = await collectSbomLiteStreams(dir, { signal });
        eq(
          p,
          "flags",
          [
            collected.truncated,
            collected.incomplete,
            collected.streams.truncated,
            collected.streams.exitCode,
          ],
          [legacy.truncated, legacy.incomplete, false, 0],
        );
        const outcome = run(LITE, collected.streams.stdout, { ctx: ctx(RUN.lite, null) });
        eq(
          p,
          "status",
          [outcome.status, outcome.reason, outcome.recordsDropped],
          ["succeeded", null, 0],
        );
        const legacyPurls = [
          ...new Set(legacyItems.map((i) => canonicalPurl(i.componentPurl).canonical)),
        ].sort();
        eq(
          p,
          "same components",
          outcome.candidates.map((c) => c.component.purl).sort(),
          legacyPurls,
        );
        const lodash = outcome.candidates.find(
          (c) => c.component.purl === "pkg:npm/lodash@4.17.20",
        );
        eq(
          p,
          "lodash folded",
          [lodash.locations, lodash.locationCount],
          [[{ path: "package-lock.json" }, { path: "web/package-lock.json" }], 2],
        );
        eq(
          p,
          "legacy still one item per manifest",
          legacyItems.filter((i) => i.componentPurl === "pkg:npm/lodash@4.17.20").length,
          2,
        );
        ok(
          p,
          outcome.candidates.every(
            (c) =>
              c.provenance[0].imageDigestShort === "none" && c.provenance[0].toolId === "sbom-lite",
          ),
          "sbom-lite provenance",
        );
        const merged = runSbomEnsemble({
          taskRef: TASK_A,
          runs: [{ adapter: LITE, streams: collected.streams, ctx: ctx(RUN.lite, null) }],
        });
        ok(
          p,
          !merged.findings.some((f) => f.component.purl === "pkg:npm/express"),
          "the declared range was kept next to the locked version",
        );
        ok(
          p,
          merged.findings.some((f) => f.component.purl === "pkg:pypi/django@3.2"),
          "a PyPI component is missing",
        );
        // scope order over the manifests of one component: prod over dev over optional and peer over unknown, the first wins a tie
        const scopeOf = (first, second) =>
          run(
            LITE,
            Buffer.from(
              JSON.stringify([
                {
                  path: "a/package-lock.json",
                  componentPurl: "pkg:npm/s@1",
                  data: { scope: first },
                },
                {
                  path: "b/package-lock.json",
                  componentPurl: "pkg:npm/s@1",
                  data: { scope: second },
                },
              ]),
            ),
            { ctx: ctx(RUN.lite, null) },
          ).candidates[0].component.scope;
        eq(
          p,
          "sbom-lite scope order",
          [
            ["prod", "dev"],
            ["dev", "prod"],
            ["dev", "optional"],
            ["optional", "dev"],
            ["optional", "unknown"],
            ["unknown", "optional"],
            ["peer", "unknown"],
            ["unknown", "peer"],
            ["optional", "peer"],
            ["peer", "optional"],
            ["unknown", "unknown"],
            ["prod", "prod"],
            ["dev", "unknown"],
            ["unknown", "dev"],
            ["unknown", "prod"],
          ].map(([a, b]) => scopeOf(a, b)),
          [
            "prod",
            "prod",
            "dev",
            "dev",
            "optional",
            "optional",
            "peer",
            "peer",
            "optional",
            "peer",
            undefined,
            "prod",
            "dev",
            "dev",
            "prod",
          ],
        );
        // truncated inventory: reported beside the streams, the records are still parsed
        const limited = await collectSbomLiteStreams(dir, {
          signal,
          inventory: (input, hooks) =>
            inventoryArchive(input, { ...hooks, limits: { ...hooksLimits(), maxComponents: 2 } }),
        });
        eq(
          p,
          "truncated inventory",
          [
            limited.truncated,
            limited.incomplete,
            limited.streams.truncated,
            run(LITE, limited.streams.stdout, { ctx: ctx(RUN.lite, null) }).status,
          ],
          [true, true, false, "succeeded"],
        );
        // abort
        const controller = new AbortController();
        controller.abort();
        let aborted = false;
        try {
          await collectSbomLiteStreams(dir, { signal: controller.signal });
        } catch {
          aborted = true;
        }
        ok(p, aborted, "an aborted signal did not abort the inventory");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S09d",
    name: "hostile SBOM tool output is tolerated (SPEC scan-engines 7.2 mapper boundaries, 14.1 ENG-S09, part E): empty, truncated, non-JSON, wrong-format, wrong-version and wrong-shape documents fail with the fixed word output_invalid; an oversize document, a cut stream and more than the scanned-component cap fail with output_too_large; 50000 records are kept and the rest cut (partial); a document nested beyond the depth cap, or carrying __proto__, constructor or prototype keys anywhere, is refused without touching Object.prototype; purls that are not purls (empty, no type, control characters, over 500 characters, undecodable) are dropped and counted, over 20 percent dropped fails the tool and a smaller share makes it partial; unsafe locations (traversal, absolute, backslash, bidirectional, control) never reach a finding and a tool path that does not exist in the tree drops the record; a credential-shaped cataloger name is redacted; a million-times repeated component folds into one; time stays bounded for a 500000-component document; the same holds for sbom-lite items",
    async run() {
      const p = [];
      const failed = (label, outcome, reason) =>
        ok(
          p,
          outcome.status === "failed" &&
            outcome.reason === reason &&
            outcome.candidates.length === 0,
          `${label}: ${outcome.status}/${outcome.reason}`,
        );
      const tiny = '{"type":"library","name":"a","purl":"pkg:npm/a@1"}';
      const huge =
        '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[' +
        Array.from({ length: SBOM_MAX_SCANNED_COMPONENTS + 1 }, () => tiny).join(",") +
        "]}";
      for (const adapter of [SYFT, TRIVY]) {
        const t = adapter.toolId;
        failed(`${t} empty`, run(adapter, Buffer.alloc(0)), "output_invalid");
        failed(`${t} not json`, run(adapter, Buffer.from("<xml/>")), "output_invalid");
        failed(
          `${t} truncated json`,
          run(
            adapter,
            Buffer.from('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"lib'),
          ),
          "output_invalid",
        );
        failed(`${t} array root`, run(adapter, Buffer.from("[]")), "output_invalid");
        failed(`${t} null root`, run(adapter, Buffer.from("null")), "output_invalid");
        failed(
          `${t} spdx`,
          run(adapter, Buffer.from(JSON.stringify({ spdxVersion: "SPDX-2.3", packages: [] }))),
          "output_invalid",
        );
        failed(`${t} wrong format`, run(adapter, cdx([], { bomFormat: "SPDX" })), "output_invalid");
        failed(`${t} version 2`, run(adapter, cdx([], { specVersion: "2.0" })), "output_invalid");
        eq(
          p,
          `${t} spec versions`,
          ["1.0", "1.6", "1.12"].map(
            (v) => run(adapter, cdx([lib("pkg:npm/v@1")], { specVersion: v })).status,
          ),
          ["succeeded", "succeeded", "succeeded"],
        );
        failed(
          `${t} version with three digits`,
          run(adapter, cdx([], { specVersion: "1.123" })),
          "output_invalid",
        );
        failed(
          `${t} version text`,
          run(adapter, cdx([], { specVersion: "1.6; drop" })),
          "output_invalid",
        );
        failed(`${t} components object`, run(adapter, cdx({}, {})), "output_invalid");
        failed(`${t} components text`, run(adapter, cdx("x")), "output_invalid");
        failed(`${t} bom`, run(adapter, Buffer.from("��")), "output_invalid");
        failed(
          `${t} unaccepted exit code`,
          run(adapter, cdx([]), { streams: { exitCode: 1 } }),
          "exit_code",
        );
        failed(
          `${t} killed (null exit)`,
          run(adapter, cdx([]), { streams: { exitCode: null } }),
          "exit_code",
        );
        failed(
          `${t} cut stream`,
          run(adapter, cdx([]), { streams: { truncated: true } }),
          "output_too_large",
        );
        failed(
          `${t} oversize`,
          run(adapter, cdx([lib("pkg:npm/a@1")]), {}, { maxBytes: 20 }),
          "output_too_large",
        );
        // depth
        const deep =
          '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a","purl":"pkg:npm/a@1","properties":[{"name":"x","value":"y","z":' +
          "[".repeat(100000) +
          "]".repeat(100000) +
          "}]}]}";
        const started = Date.now();
        failed(`${t} deep nesting`, run(adapter, Buffer.from(deep)), "output_invalid");
        ok(p, Date.now() - started < 3000, `${t}: deep nesting was slow`);
        failed(
          `${t} deep nesting under a lower cap`,
          run(
            adapter,
            cdx([
              lib("pkg:npm/a@1", {
                properties: [{ name: "n", value: "v", a: { b: { c: { d: 1 } } } }],
              }),
            ]),
            {},
            { maxDepth: 4 },
          ),
          "output_invalid",
        );
        // prototype pollution
        for (const [label, body] of [
          [
            "root",
            '{"__proto__":{"polluted":true},"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}',
          ],
          [
            "component",
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a","purl":"pkg:npm/a@1","__proto__":{"polluted":true}}]}',
          ],
          [
            "property",
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a","purl":"pkg:npm/a@1","properties":[{"name":"x","constructor":{"prototype":{"polluted":true}}}]}]}',
          ],
          [
            "prototype key",
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"a","purl":"pkg:npm/a@1","prototype":{}}]}',
          ],
          [
            "dependencies",
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"dependencies":[{"ref":"a","__proto__":{"polluted":true}}]}',
          ],
        ]) {
          failed(`${t} ${label} key`, run(adapter, Buffer.from(body)), "output_invalid");
          ok(
            p,
            {}.polluted === undefined && Object.prototype.polluted === undefined,
            `${t}: ${label} polluted Object.prototype`,
          );
        }
        // bad purls
        const badPurls = [
          "",
          "pkg:",
          "pkg:npm",
          "pkg:/name",
          "npm/a@1",
          "pkg:npm/a\u0000b@1",
          `pkg:npm/${"a".repeat(600)}@1`,
          "pkg:npm/%E0%A4%A@1",
          "pkg:9npm/a@1",
          "http://x/y",
          "pkg:npm//@1",
        ];
        const some = run(
          adapter,
          cdx([
            ...Array.from({ length: 100 }, (_, i) => lib(`pkg:npm/ok${i}@1`)),
            ...badPurls.slice(0, 9).map((purl) => lib(purl)),
          ]),
        );
        eq(
          p,
          `${t} a few bad purls`,
          [some.status, some.reason, some.candidates.length, some.recordsDropped],
          ["partial", "output_invalid", 100, 9],
        );
        failed(
          `${t} many bad purls`,
          run(
            adapter,
            cdx([
              ...Array.from({ length: 10 }, (_, i) => lib(`pkg:npm/ok${i}@1`)),
              ...badPurls.map((purl) => lib(purl)),
            ]),
          ),
          "output_invalid",
        );
        failed(
          `${t} no purl on libraries`,
          run(adapter, cdx(Array.from({ length: 10 }, () => ({ type: "library", name: "n" })))),
          "output_invalid",
        );
        failed(
          `${t} malformed components`,
          run(adapter, cdx([null, 1, "x", [], {}, { type: 5 }, { type: "library" }])),
          "output_invalid",
        );
        // bookkeeping that is malformed is not a package (never a record, never a drop); a malformed library is
        const tenLibs = Array.from({ length: 10 }, (_, i) => lib(`pkg:npm/b${i}@1`));
        const bookkeeping = run(
          adapter,
          cdx([
            ...tenLibs,
            { type: "file", name: 5 },
            { type: "operating-system" },
            { type: "application", name: {} },
            { type: "data", name: [] },
          ]),
        );
        eq(
          p,
          `${t} malformed bookkeeping`,
          [bookkeeping.status, bookkeeping.recordsSeen, bookkeeping.recordsDropped],
          ["succeeded", 10, 0],
        );
        const badLib = run(adapter, cdx([...tenLibs, { type: "library", name: 5 }]));
        eq(
          p,
          `${t} a malformed library`,
          [badLib.status, badLib.recordsSeen, badLib.recordsDropped],
          ["partial", 11, 1],
        );
        const badFw = run(adapter, cdx([...tenLibs, { type: "framework", name: 5 }]));
        eq(p, `${t} a malformed framework`, [badFw.status, badFw.recordsDropped], ["partial", 1]);
        const noType = run(adapter, cdx([...tenLibs, { name: "x" }]));
        eq(
          p,
          `${t} a component without a type`,
          [noType.status, noType.recordsDropped],
          ["partial", 1],
        );
        failed(`${t} a null root document`, run(adapter, Buffer.from("null")), "output_invalid");
        // every schema bound of a component: accepted at the limit, dropped (and counted) one over
        const edge = (label, make, max) => {
          const atMax = run(adapter, cdx([...tenLibs, make(max)]));
          eq(p, `${t} ${label} at ${max}`, [atMax.status, atMax.recordsDropped], ["succeeded", 0]);
          const over = run(adapter, cdx([...tenLibs, make(max + 1)]));
          eq(p, `${t} ${label} at ${max + 1}`, [over.status, over.recordsDropped], ["partial", 1]);
        };
        edge(
          "property name",
          (n) => lib("pkg:npm/edge@1", { properties: [{ name: "x".repeat(n) }] }),
          200,
        );
        edge(
          "property value",
          (n) => lib("pkg:npm/edge@1", { properties: [{ name: "n", value: "v".repeat(n) }] }),
          2000,
        );
        edge("bom-ref", (n) => lib("pkg:npm/edge@1", { "bom-ref": "r".repeat(n) }), 1200);
        edge("component name", (n) => lib("pkg:npm/edge@1", { name: "x".repeat(n) }), 1000);
        edge(
          "property count",
          (n) =>
            lib("pkg:npm/edge@1", {
              properties: Array.from({ length: n }, (_, i) => ({ name: `p${i}` })),
            }),
          200,
        );
        edge(
          "occurrence count",
          (n) =>
            lib("pkg:npm/edge@1", {
              evidence: { occurrences: Array.from({ length: n }, () => ({})) },
            }),
          200,
        );
        edge(
          "occurrence location",
          (n) =>
            lib("pkg:npm/edge@1", { evidence: { occurrences: [{ location: "x".repeat(n) }] } }),
          1100,
        );
        // text from the tool is cut where the record allows: a long cataloger name, a long version
        const cut = run(
          adapter,
          cdx([
            lib("pkg:npm/cut@1", {
              properties: [{ name: "syft:package:foundBy", value: "f".repeat(121) }],
            }),
            lib(`pkg:npm/long@${"1".repeat(150)}`),
          ]),
        );
        eq(
          p,
          `${t} text is cut, not dropped`,
          [
            cut.status,
            cut.recordsDropped,
            cut.candidates.map((c) => c.provenance[0].ruleId?.length),
            cut.candidates.map((c) => c.component.version.length),
            cut.candidates.map((c) => c.component.purl.length),
          ],
          ["succeeded", 0, [120, null], [1, 100], [13, 163]],
        );
        // bad entries beside many good ones: dropped and counted, never a crash
        const noise = run(
          adapter,
          cdx([...Array.from({ length: 30 }, (_, i) => lib(`pkg:npm/n${i}@1`)), null, 7]),
        );
        eq(
          p,
          `${t} null and numeric entries`,
          [noise.status, noise.recordsSeen, noise.recordsDropped],
          ["partial", 32, 2],
        );
        // names and versions
        const longName = run(
          adapter,
          cdx([lib(`pkg:npm/${"n".repeat(400)}@1`), lib("pkg:npm/ok@1")]),
        );
        eq(
          p,
          `${t} over-long name is shortened, the purl is kept`,
          [
            longName.candidates.length,
            longName.candidates[0].component.name.length,
            longName.candidates[0].component.purl.length,
          ],
          [2, 200, 410],
        );
        // locations
        const hostile = [
          "/../../etc/passwd",
          "../x",
          "/",
          "",
          "//abs",
          "a\\b",
          "a/./b",
          "a//b",
          "a\u0007b",
          "x".repeat(1100),
        ];
        const loc = run(
          adapter,
          cdx([
            lib("pkg:npm/loc@1", {
              properties: hostile
                .map((v, i) => ({ name: `syft:location:${i}:path`, value: v }))
                .concat([{ name: "syft:location:99:path", value: "/good/package-lock.json" }]),
            }),
          ]),
        );
        eq(
          p,
          `${t} unsafe locations dropped`,
          [loc.status, loc.candidates[0].locations, loc.candidates[0].locationCount],
          ["succeeded", [{ path: "good/package-lock.json" }], 1],
        );
        const missing = run(
          adapter,
          cdx([
            ...Array.from({ length: 8 }, (_, i) =>
              lib(`pkg:npm/e${i}@1`, {
                properties: [{ name: "syft:location:0:path", value: "/there/package-lock.json" }],
              }),
            ),
            lib("pkg:npm/m@1", {
              properties: [{ name: "syft:location:0:path", value: "/nope/package-lock.json" }],
            }),
            lib("pkg:npm/b@1", {
              properties: [{ name: "syft:location:0:path", value: "/a\u202eb/lock" }],
            }),
            lib("pkg:npm/n@1", {
              properties: [{ name: "syft:location:0:path", value: "/there/package-lock.json" }],
            }),
          ]),
          { ctx: { pathExists: (rel) => rel === "there/package-lock.json" } },
        );
        eq(
          p,
          `${t} path not in the tree`,
          [missing.candidates.map((c) => c.component.purl), missing.recordsDropped],
          [
            [
              "pkg:npm/e0@1",
              "pkg:npm/e1@1",
              "pkg:npm/e2@1",
              "pkg:npm/e3@1",
              "pkg:npm/e4@1",
              "pkg:npm/e5@1",
              "pkg:npm/e6@1",
              "pkg:npm/e7@1",
              "pkg:npm/n@1",
            ],
            2,
          ],
        );
        // credential-shaped cataloger, control characters, bidirectional text
        const noisy = run(
          adapter,
          cdx([
            lib("pkg:npm/c@1", {
              properties: [
                { name: "syft:package:foundBy", value: "ghp_abcdefghijklmnopqrstuv1234" },
              ],
            }),
            lib("pkg:npm/d@1", {
              properties: [{ name: "syft:package:foundBy", value: "a\u001b[31mred\u202etext" }],
            }),
          ]),
        );
        ok(
          p,
          !JSON.stringify(noisy.candidates).includes("ghp_abcdefghij"),
          `${t}: a credential-shaped name survived`,
        );
        const flat = JSON.stringify(noisy.candidates);
        ok(
          p,
          !flat.includes("\\u001b") &&
            !flat.includes("\\u202e") &&
            !flat.includes(String.fromCharCode(0x1b)) &&
            !flat.includes(String.fromCharCode(0x202e)),
          `${t}: control or bidirectional text survived`,
        );
        // repetition folds
        const repeated = run(
          adapter,
          cdx(Array.from({ length: 20000 }, () => lib("pkg:npm/rep@1.0.0"))),
        );
        eq(
          p,
          `${t} repeated component`,
          [repeated.candidates.length, repeated.recordsSeen, repeated.status],
          [1, 1, "succeeded"],
        );
        // huge counts
        const unique = (n) =>
          '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[' +
          Array.from(
            { length: n },
            (_, i) => `{"type":"library","name":"a","purl":"pkg:npm/a${i}@1"}`,
          ).join(",") +
          "]}";
        // the two adapters share the cap constant and the parse path: the slow cases run once
        if (adapter !== SYFT) continue;
        const t0 = Date.now();
        const big = run(adapter, Buffer.from(unique(SBOM_MAX_RECORDS + 1000)));
        eq(
          p,
          `${t} over the record cap`,
          [big.status, big.reason, big.truncated, big.recordsSeen, big.candidates.length],
          ["partial", "output_too_large", true, SBOM_MAX_RECORDS, SBOM_MAX_RECORDS],
        );
        ok(
          p,
          Date.now() - t0 < 20000,
          `${t}: ${SBOM_MAX_RECORDS} records took ${Date.now() - t0} ms`,
        );
        const t1 = Date.now();
        const atCap = run(adapter, Buffer.from(huge.replace(tiny + ",", "")));
        eq(
          p,
          `${t} exactly the scanned cap`,
          [atCap.status, atCap.candidates.length],
          ["succeeded", 1],
        );
        failed(`${t} over the scanned cap`, run(adapter, Buffer.from(huge)), "output_too_large");
        ok(
          p,
          Date.now() - t1 < 20000,
          `${t}: ${SBOM_MAX_SCANNED_COMPONENTS} components took ${Date.now() - t1} ms`,
        );
      }
      // sbom-lite items
      const liteItem = (over = {}) => ({
        path: "package-lock.json",
        componentPurl: "pkg:npm/a@1",
        data: { scope: "prod" },
        ...over,
      });
      failed("lite object", run(LITE, Buffer.from("{}")), "output_invalid");
      failed("lite empty", run(LITE, Buffer.alloc(0)), "output_invalid");
      failed("lite proto", run(LITE, Buffer.from('[{"__proto__":{"x":1}}]')), "output_invalid");
      failed(
        "lite junk items",
        run(LITE, Buffer.from(JSON.stringify([1, null, "x", [], {}]))),
        "output_invalid",
      );
      const liteMixed = run(
        LITE,
        Buffer.from(
          JSON.stringify([
            ...Array.from({ length: 20 }, (_, i) => liteItem({ componentPurl: `pkg:npm/p${i}@1` })),
            liteItem({ path: "../x" }),
            liteItem({ componentPurl: "nope" }),
            liteItem({ path: "/abs" }),
          ]),
        ),
      );
      eq(
        p,
        "lite mixed",
        [liteMixed.status, liteMixed.candidates.length, liteMixed.recordsDropped],
        ["partial", 21, 2],
      );
      eq(
        p,
        "lite scope words",
        run(LITE, Buffer.from(JSON.stringify([liteItem({ data: { scope: "weird" } })])))
          .candidates[0].component.scope,
        undefined,
      );
      // the global prototype is intact after everything
      ok(p, Object.keys(Object.prototype).length === 0, "Object.prototype gained a key");
      // the constants the framework relies on
      eq(
        p,
        "caps",
        [SBOM_MAX_RECORDS, SBOM_MAX_SCANNED_COMPONENTS, SBOM_MAX_PATHS],
        [50000, 500000, 20],
      );
      void ADAPTER_OF;
      return p;
    },
  },
];

function hooksLimits() {
  return {
    maxFileBytes: 5 * 1024 * 1024,
    maxTotalBytes: 40 * 1024 * 1024,
    maxFiles: 500,
    maxDirectories: 20000,
    maxDepth: 32,
    maxComponents: 50000,
    maxJsonDepth: 128,
    maxLineLength: 4096,
    maxNameLength: 200,
    maxVersionLength: 100,
  };
}
