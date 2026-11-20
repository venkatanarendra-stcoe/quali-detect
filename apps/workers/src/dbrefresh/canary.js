/**
 * The canary scan of the promotion gate (docs/modules/scan-engines/SPEC.md SE-35 b). A tiny PLATFORM-OWNED fixture (an SBOM with one
 * long-lived vulnerable package) is scanned in the same sandbox, sealed and offline, against the candidate snapshot mounted read-only
 * at `/db`; the expected advisory must appear. No repository content, no tenant data and no network are involved.
 *
 * UNVERIFIED (ENG-L09, SPEC 17.p): the command lines and the output parsers below are the Part F reading of the tools' documented
 * offline switches and have NOT been run against the real tools. The final argv of the SCA adapters (Part G) must replace them.
 */

/** The fixture: CycloneDX with lodash 4.17.20 (CVE-2021-23337 / GHSA-35jh-r3h4-6jhm). Platform constant, never user data. */
export const CANARY_FIXTURE = Object.freeze({
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  version: 1,
  components: [
    {
      type: "library",
      name: "lodash",
      version: "4.17.20",
      purl: "pkg:npm/lodash@4.17.20",
      "bom-ref": "pkg:npm/lodash@4.17.20",
    },
  ],
});

/** Any of these advisory ids proves the data contains the known vulnerability. */
export const CANARY_EXPECTED_IDS = Object.freeze(["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"]);

const LIMITS = Object.freeze({
  cpus: 1,
  memoryMiB: 1024,
  pids: 128,
  wallClockSeconds: 120,
  stdoutBytes: 8 * 1024 * 1024,
  tmpfsMiB: 256,
});

/** Collects advisory ids from a JSON document of either tool (bounded, tolerant: anything unreadable yields no ids). */
function idsFromJson(stdout) {
  const ids = new Set();
  let doc;
  try {
    doc = JSON.parse(String(stdout).slice(0, 8 * 1024 * 1024));
  } catch {
    return ids;
  }
  const visit = (node, depth) => {
    if (depth > 12 || node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 5000)) visit(item, depth + 1);
      return;
    }
    for (const key of ["VulnerabilityID", "id"])
      if (typeof node[key] === "string" && node[key].length <= 120) ids.add(node[key]);
    for (const value of Object.values(node)) visit(value, depth + 1);
  };
  visit(doc, 0);
  return ids;
}

/** Per tool: the catalog key, the sealed offline command (UNVERIFIED), the fixed environment and the output reader. */
export const CANARY_PLANS = Object.freeze({
  trivy: Object.freeze({
    imageKey: "trivy",
    argv: Object.freeze([
      "sbom",
      "--cache-dir",
      "/db",
      "--skip-db-update",
      "--skip-java-db-update",
      "--offline-scan",
      "--scanners",
      "vuln",
      "--pkg-types",
      "library",
      "--format",
      "json",
      "-",
    ]),
    env: Object.freeze({ TRIVY_SKIP_VERSION_CHECK: "true", TRIVY_DISABLE_TELEMETRY: "true" }),
    parse: idsFromJson,
  }),
  "osv-scanner": Object.freeze({
    imageKey: "osv-scanner",
    argv: Object.freeze([
      "--offline",
      "--download-offline-databases",
      "--format",
      "json",
      "--sbom",
      "/dev/stdin",
    ]),
    env: Object.freeze({}),
    parse: idsFromJson,
  }),
});

/**
 * @param {{ runner: { runTool: Function }, resolver: { resolve: Function }, plans?: typeof CANARY_PLANS, now?: () => number }} deps
 * @returns {(input: { toolId: string, sha256: string, dir: string, signal?: AbortSignal }) => Promise<{ ok: boolean, reason?: "missing_advisory" | "unavailable" }>}
 *   `unavailable` means the canary could not run (runtime, image or timeout): the candidate is kept, not rejected; `missing_advisory` is a failed canary
 */
export function createSandboxCanary({ runner, resolver, plans = CANARY_PLANS, now = Date.now }) {
  return async ({ toolId, sha256, dir, signal }) => {
    const plan = plans[toolId];
    if (!plan) return { ok: false, reason: "unavailable" };
    let image;
    try {
      image = resolver.resolve(plan.imageKey, { scanType: "sca" }).image;
    } catch {
      return { ok: false, reason: "unavailable" };
    }
    const spec = {
      toolId,
      image,
      argv: [...plan.argv],
      mounts: { db: dir },
      env: { ...plan.env },
      stdin: JSON.stringify(CANARY_FIXTURE),
      limits: { ...LIMITS },
      labels: {
        tenantId: "platform",
        executionId: "dbrefresh",
        taskId: `canary-${sha256.slice(0, 12)}`,
        attempt: 1,
        deadlineEpoch: Math.floor(now() / 1000) + LIMITS.wallClockSeconds + 60,
      },
    };
    let result;
    try {
      result = await runner.runTool(spec, { signal });
    } catch {
      return { ok: false, reason: "unavailable" };
    }
    if (result.status !== "exited") return { ok: false, reason: "unavailable" };
    const ids = plan.parse(result.stdout);
    return CANARY_EXPECTED_IDS.some((id) => ids.has(id))
      ? { ok: true }
      : { ok: false, reason: "missing_advisory" };
  };
}
