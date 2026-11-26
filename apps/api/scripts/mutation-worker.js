/**
 * Worker of the scan-engines mutation sweep (SPEC scan-engines 14.1 / 16.1 part M; `mutation-sweep.js` is the driver).
 * Runs the Docker-free, database-free, network-free security checks IN PROCESS (the same `run()` functions the suite
 * registers in its "Scan engines: sandbox invocation and runner" group) and stops at the first failing check.
 * Prints one JSON line: `{ ok, checks, failed?, problems? }`.
 * Env: MUTATION_ONLY (regex on the check id), MUTATION_ORDER (comma separated check-id prefixes to run first, so a killed
 * mutant ends early), MUTATION_LIST (print the ids and exit).
 */
import { SANDBOX_CHECKS } from "../test/security/helpers/sandbox-checks.js";
import { IMAGE_CATALOG_CHECKS } from "../test/security/helpers/image-catalog-checks.js";
import { ARCHIVE_CHECKS } from "../test/security/helpers/archive-checks.js";
import { ENSEMBLE_CORE_CHECKS } from "../test/security/helpers/ensemble-core-checks.js";
import { ENSEMBLE_SBOM_CHECKS } from "../test/security/helpers/ensemble-sbom-checks.js";
import { ENSEMBLE_SCA_CHECKS } from "../test/security/helpers/ensemble-sca-checks.js";
import { ENSEMBLE_SAST_CHECKS } from "../test/security/helpers/ensemble-sast-checks.js";
import { ENSEMBLE_SECRETS_CHECKS } from "../test/security/helpers/ensemble-secrets-checks.js";
import { ENSEMBLE_EVIDENCE_CHECKS } from "../test/security/helpers/ensemble-evidence-checks.js";
import { ENG_L20_CHECKS } from "../test/security/helpers/eng-l20-checks.js";
import { ENSEMBLE_ENGINE_CHECKS } from "../test/security/helpers/ensemble-engine-checks.js";
import { ENSEMBLE_YIELD_CHECKS } from "../test/security/helpers/ensemble-yield-checks.js";
import { ENSEMBLE_GUARD_CHECKS } from "../test/security/helpers/ensemble-guard-checks.js";
import { ENSEMBLE_ENV_CHECKS } from "../test/security/helpers/ensemble-env-checks.js";
import { ENSEMBLE_KILL_CHECKS } from "../test/security/helpers/ensemble-kill-checks.js";
import { ENSEMBLE_TRIAGE_CHECKS } from "../test/security/helpers/ensemble-triage-checks.js";
import { DBMIRROR_CHECKS } from "../test/security/helpers/dbmirror-checks.js";

/** `MUTATION_GROUP=findings` or `reporting` runs the checks of that module (Reporting part E reuses the Findings mechanism). */
const GROUP = process.env.MUTATION_GROUP;
const FINDINGS = GROUP === "findings" || GROUP === "reporting";
/** The checks of the module that need no database (they ignore the world); the others report NEEDS_DB and are skipped. */
const findingsChecks =
  GROUP === "findings"
    ? (await import("../test/security/helpers/findings/index.js")).FINDINGS_CHECKS
    : GROUP === "reporting"
      ? (await import("../test/security/helpers/reporting/index.js")).REPORTING_CHECKS
      : [];
const all = FINDINGS
  ? findingsChecks
  : [
      ...SANDBOX_CHECKS,
      ...IMAGE_CATALOG_CHECKS,
      ...ARCHIVE_CHECKS,
      ...ENSEMBLE_CORE_CHECKS,
      ...ENSEMBLE_SBOM_CHECKS,
      ...ENSEMBLE_SCA_CHECKS,
      ...ENSEMBLE_SAST_CHECKS,
      ...ENSEMBLE_SECRETS_CHECKS,
      ...ENSEMBLE_EVIDENCE_CHECKS,
      ...ENG_L20_CHECKS,
      ...ENSEMBLE_ENGINE_CHECKS,
      ...ENSEMBLE_YIELD_CHECKS,
      ...ENSEMBLE_GUARD_CHECKS,
      ...ENSEMBLE_ENV_CHECKS,
      ...ENSEMBLE_KILL_CHECKS,
      ...ENSEMBLE_TRIAGE_CHECKS,
      ...DBMIRROR_CHECKS,
    ];
const only = process.env.MUTATION_ONLY ? new RegExp(process.env.MUTATION_ONLY) : null;
const first = (process.env.MUTATION_ORDER ?? "").split(",").filter(Boolean);
/** @param {{ id: string }} c */
const rank = (c) => {
  const i = first.findIndex((p) => c.id.startsWith(p));
  return i === -1 ? first.length : i;
};
const list = all.filter((c) => !only || only.test(c.id)).sort((a, b) => rank(a) - rank(b));

if (process.env.MUTATION_LIST) {
  console.log(JSON.stringify({ ok: true, ids: list.map((c) => c.id) }));
  process.exit(0);
}
let ran = 0;
const needsDatabase = new Proxy(
  {},
  {
    get() {
      throw new Error("NEEDS_DB");
    },
  },
);
for (const check of list) {
  try {
    const problems = await check.run(FINDINGS ? needsDatabase : undefined);
    ran += 1;
    if (problems && problems.length > 0) {
      console.log(
        JSON.stringify({
          ok: false,
          checks: ran,
          failed: check.id,
          problems: problems.slice(0, 2),
        }),
      );
      process.exit(1);
    }
  } catch (error) {
    if (FINDINGS && String(error?.message) === "NEEDS_DB") continue; // a database check: not part of the in-memory sweep
    console.log(
      JSON.stringify({
        ok: false,
        checks: ran,
        failed: check.id,
        problems: [String(error?.message ?? error).slice(0, 200)],
      }),
    );
    process.exit(1);
  }
}
console.log(JSON.stringify({ ok: true, checks: ran }));
process.exit(0);
