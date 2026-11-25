// DEVELOPMENT TOOL (ENG-L09, docs/modules/scan-engines/ENG_L21_RUNBOOK.md section 2): loads vulnerability databases that YOU downloaded with
// the locked Trivy and OSV-Scanner images into the platform mirror through the REAL refresh job (`refreshTool`: hash, inspection,
// candidate row, mirror store, canary scan in the real sandbox, atomic promotion). The real downloader of the platform does not exist
// yet (OQ-29), so this script plays that one component: it packs the two directories into the bundle layout of the runbook and serves
// them to the job through the `{ latest, download }` interface. Nothing else is bypassed.
//
//   node --env-file=apps/workers/.env apps/workers/scripts/eng-l09/load-local-bundles.js \
//        --work /tmp/qm-e2e --trivy-db /tmp/qm-e2e/trivy-db --osv-db /tmp/qm-e2e/osv-db
//
// Needs (in the environment): DATABASE_URL, RABBITMQ_URL, REDIS_URL (optional), SCAN_DB_REFRESH_ENABLED=true, SCAN_DB_MIRROR_ROOT,
// SCAN_DB_CACHE_ROOT, SANDBOX_RULES_DIR, SANDBOX_RUNTIME_BIN and, in development, SCAN_ENGINES_LOCAL_IMAGES. It refuses NODE_ENV=production.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { createDbClient } from "@qmentisai/db";
import { loadWorkerConfig } from "../../src/config.js";
import { buildDbRefreshDeps } from "../../src/dbrefresh/index.js";
import { refreshTool } from "../../src/dbrefresh/refresh.js";

if (process.env.NODE_ENV === "production") {
  console.error("refused: a development tool (it replaces the platform downloader)");
  process.exit(1);
}
const { values } = parseArgs({
  options: {
    work: { type: "string" },
    "trivy-db": { type: "string" },
    "osv-db": { type: "string" },
    tools: { type: "string", default: "trivy,osv-scanner" },
  },
});
const work = values.work;
if (!work || !path.isAbsolute(work)) throw new Error("--work <absolute dir> is required");
mkdirSync(path.join(work, "bundles"), { recursive: true });

const sha256 = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
const pack = (name, topDir, sourceDir) => {
  const out = path.join(work, "bundles", `${name}.tar.gz`);
  // one top-level directory (the layout of the bundle); the content is the tool's own cache directory
  const r = spawnSync(
    "tar",
    ["-czf", out, "--transform", `s,^\\.,${topDir},`, "-C", sourceDir, "."],
    {
      stdio: "inherit",
    },
  );
  if (r.status !== 0) throw new Error(`tar failed for ${name}`);
  return out;
};

const bundles = {};
if (values.tools.includes("trivy")) {
  const dir = values["trivy-db"];
  const meta = JSON.parse(readFileSync(path.join(dir, "db", "metadata.json"), "utf8"));
  const file = pack("trivy", "trivy", dir);
  bundles.trivy = {
    file,
    builtAt: new Date(meta.UpdatedAt).toISOString(),
    version: `trivy-db-v${meta.Version}`,
    sources: ["ghsa", "nvd", "osv"],
  };
}
if (values.tools.includes("osv-scanner")) {
  const dir = values["osv-db"];
  for (const eco of ["npm", "PyPI", "Go", "Maven"])
    if (!existsSync(path.join(dir, "osv-scalibr", eco, "all.zip")))
      throw new Error(`missing osv-scalibr/${eco}/all.zip`);
  const file = pack("osv", "osv", dir);
  const newest = Math.max(
    ...["npm", "PyPI", "Go", "Maven"].map(
      (e) => statSync(path.join(dir, "osv-scalibr", e, "all.zip")).mtimeMs,
    ),
  );
  bundles["osv-scanner"] = {
    file,
    builtAt: new Date(newest).toISOString(),
    version: `osv-offline-${new Date(newest).toISOString().slice(0, 10)}`,
    sources: ["osv", "ghsa", "nvd"],
  };
}

const downloader = {
  async latest({ toolId }) {
    const b = bundles[toolId];
    if (!b) throw new Error(`no local bundle for ${toolId}`);
    return {
      sha256: sha256(b.file),
      sizeBytes: statSync(b.file).size,
      builtAt: b.builtAt,
      sourceVersion: b.version,
      sources: b.sources,
    };
  },
  async download({ toolId }) {
    return createReadStream(bundles[toolId].file);
  },
};

const config = loadWorkerConfig(process.env, { workerName: "dbrefresh" });
const db = createDbClient({ datasourceUrl: config.databaseUrl });
const { deps, close } = buildDbRefreshDeps({ db, config, downloader, logger: console });
const log = {
  info: () => {},
  warn: (o, m) => console.warn(m, JSON.stringify(o)),
  error: (o, m) => console.error(m, JSON.stringify(o)),
};
let failed = false;
for (const toolId of Object.keys(bundles)) {
  const t0 = Date.now();
  const r = await refreshTool({ toolId, deps, scanDb: config.scanDb, log });
  console.log(
    JSON.stringify({
      toolId,
      outcome: r.outcome,
      reason: r.reason ?? null,
      sha256: r.sha256?.slice(0, 12),
      seconds: Math.round((Date.now() - t0) / 1000),
    }),
  );
  if (r.outcome !== "promoted" && r.outcome !== "unchanged") failed = true;
}
await close();
await db.$disconnect();
process.exit(failed ? 1 : 0);
