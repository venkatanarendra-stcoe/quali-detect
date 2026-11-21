import { isSafeRelativePath, normalizeSeverity } from "@qmentisai/shared";
import { z } from "zod";
import { defineToolAdapter } from "../core/adapter.js";
import { canonicalPurl } from "../core/merge-keys.js";
import {
  CVSS_SOURCES,
  SCA_MAX_FIXED,
  SCA_MAX_RECORDS,
  clipped,
  cvssForProvenance,
  cweList,
  scaBody,
  storedCvssVersion,
  text,
  usableAdvisoryIds,
} from "./common.js";
import { SCA_TOOL_LIMITS, planScaTool } from "./plan.js";

/**
 * Trivy in SCA mode as a tool adapter (docs/modules/scan-engines/SPEC.md 5.2, 5.6.2, 5.7, 5.12, D-15, D-21; IMAGES.md section 7).
 * LANGUAGE ECOSYSTEMS ONLY: `--pkg-types library` switches operating-system package scanning off (so no distribution vendor advisory
 * data is used for a finding), `--scanners vuln` is the only scanner (no secret, misconfiguration or licence scanner), the database is
 * the read-only snapshot at `/db` (`TRIVY_CACHE_DIR=/db`, `--skip-db-update`, `--skip-java-db-update`, `--offline-scan`), the platform
 * configuration is `/rules/trivy.yaml` and the working directory is `/tmp`, so a `trivy.yaml` or `.trivyignore` in the repository is never
 * read. `--include-dev-deps` keeps the dependency universe equal to the SBOM's (owner decision D-24 (a): all components) and to
 * OSV-Scanner's; `--list-all-pkgs=false` keeps the document to the vulnerable packages.
 *
 * REAL RUN 2026-11-21 (ENG-G, Trivy 0.76.2, database `mirror.gcr.io/aquasec/trivy-db:2` of 2026-11-21): exit 0 with and without
 * findings (no `--exit-code`), JSON `SchemaVersion` 2, `Results[]` of Class `lang-pkgs` (Type `npm`, `pip`, `pom`, `gomod`) with a
 * lockfile `Target`; a vulnerability carries `VulnerabilityID` (CVE, or GHSA when there is no CVE), `VendorIDs` (the GHSA or Go id),
 * `PkgIdentifier.PURL`, `InstalledVersion`, `FixedVersion` (a comma separated string, several lines of a fix), `Severity`
 * (`SeveritySource` `ghsa`, or none for the Go database), `CweIDs`, `CVSS` per source (`ghsa`, `nvd`, and vendors such as `redhat` or
 * `bitnami`, whose ratings the platform does NOT keep). A tree with no lockfile gives exit 0 and no `Results`. A missing or invalid
 * database gives exit 1 and a `DB error` line (classified `db_unavailable` by the engine).
 */

export const TRIVY_SCA_ARGV = Object.freeze([
  "fs",
  "--config",
  "/rules/trivy.yaml",
  "--skip-db-update",
  "--skip-java-db-update",
  "--offline-scan",
  "--scanners",
  "vuln",
  "--pkg-types",
  "library",
  "--include-dev-deps",
  "--list-all-pkgs=false",
  "--format",
  "json",
  "/src",
]);
export const TRIVY_SCA_ENV = Object.freeze({
  TRIVY_SKIP_VERSION_CHECK: "true",
  TRIVY_DISABLE_TELEMETRY: "true",
  TRIVY_CACHE_DIR: "/db",
});

const cvssEntrySchema = z
  .object({
    source: z.enum(CVSS_SOURCES),
    version: z.enum(["3.0", "3.1", "4.0"]),
    vector: text(200),
    score: z.number().min(0).max(10).optional(),
  })
  .strict();

/** One flattened vulnerability of one lockfile result (the record the framework validates). */
export const trivyRecordSchema = z
  .object({
    target: z.string().refine(isSafeRelativePath, "unsafe path"),
    id: text(80),
    vendorIds: z.array(text(80)).max(20),
    purl: text(500).refine((p) => canonicalPurl(p) !== null, "not a package URL"),
    fixed: z.string().max(2000).optional(),
    severity: z.string().max(40),
    title: clipped(200).optional(),
    cwe: z.array(z.string().max(20)).max(20),
    cvss: z.array(cvssEntrySchema).max(8),
  })
  .strict();

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
/** The string members of an untrusted list, at most `max` of them (a member of another type is ignored, not a reason to drop the record). */
const strings = (list, max) =>
  (Array.isArray(list) ? list : []).filter((x) => typeof x === "string").slice(0, max);

/** @param {Record<string, any>} cvssMap the `CVSS` object of a vulnerability @returns {object[]} only the allowlisted sources */
function cvssEntries(cvssMap) {
  const out = [];
  if (!isObject(cvssMap)) return out;
  for (const source of CVSS_SOURCES) {
    const c = cvssMap[source];
    if (!isObject(c)) continue;
    for (const [vectorKey, scoreKey] of [
      ["V3Vector", "V3Score"],
      ["V40Vector", "V40Score"],
    ]) {
      const version = storedCvssVersion(c[vectorKey]);
      if (version === null) continue;
      out.push({
        source,
        version,
        vector: c[vectorKey],
        // a score outside 0 to 10 is not kept (the vector is): a hostile number never costs the whole finding
        ...(typeof c[scoreKey] === "number" && c[scoreKey] >= 0 && c[scoreKey] <= 10
          ? { score: c[scoreKey] }
          : {}),
      });
    }
  }
  return out;
}

/**
 * Flattens a parsed Trivy report into records. Only `lang-pkgs` results are read: a result of any other class (an operating-system
 * result would mean the language-only switches did not hold) is DROPPED and counted, never mapped.
 * @param {unknown} doc @param {{ ToolOutputError: new (reason: string, detail: string) => Error }} kit
 * @returns {(object | null)[]}
 */
export function trivyRecords(doc, kit) {
  if (!isObject(doc) || doc.SchemaVersion !== 2)
    throw new kit.ToolOutputError("output_invalid", "not a Trivy report of schema 2");
  const results = doc.Results === undefined || doc.Results === null ? [] : doc.Results;
  if (!Array.isArray(results))
    throw new kit.ToolOutputError("output_invalid", "Results is not a list");
  const out = [];
  for (const result of results) {
    if (!isObject(result)) {
      out.push(null);
      continue;
    }
    const vulns =
      result.Vulnerabilities === undefined || result.Vulnerabilities === null
        ? []
        : result.Vulnerabilities;
    if (!Array.isArray(vulns)) {
      out.push(null);
      continue;
    }
    if (result.Class !== "lang-pkgs") {
      // not a language result: every vulnerability in it is dropped and counted
      for (let i = 0; i < Math.max(1, vulns.length); i += 1) out.push(null);
      continue;
    }
    for (const v of vulns) {
      if (!isObject(v)) {
        out.push(null);
        continue;
      }
      out.push({
        target: result.Target,
        id: v.VulnerabilityID,
        vendorIds: usableAdvisoryIds(v.VendorIDs, 20),
        purl: isObject(v.PkgIdentifier) ? v.PkgIdentifier.PURL : undefined,
        fixed:
          typeof v.FixedVersion === "string" && v.FixedVersion !== "" ? v.FixedVersion : undefined,
        severity: typeof v.Severity === "string" ? v.Severity : "",
        title: typeof v.Title === "string" && v.Title !== "" ? v.Title : undefined,
        cwe: strings(v.CweIDs, 20),
        cvss: cvssEntries(v.CVSS),
      });
    }
  }
  return out;
}

/**
 * The pure mapper of a Trivy record to a vulnerability candidate body (SPEC 7.2, 5.6.2, 5.7). Severity is Trivy's own `Severity`
 * (UNKNOWN or any other word is `medium` with `severityAssumed`); the confidence is `high` (an ecosystem-native advisory id).
 * @param {z.infer<typeof trivyRecordSchema>} record
 */
export function mapTrivyRecord(record) {
  const fixed = (record.fixed ?? "").split(",").slice(0, SCA_MAX_FIXED * 3);
  const built = scaBody({
    purl: record.purl,
    advisoryIds: [record.id, ...record.vendorIds],
    primaryId: record.id,
    title: record.title ?? "",
    path: record.target,
    fixed,
    cwe: cweList(record.cwe),
  });
  if (built === null) throw new TypeError("a record without a usable purl or advisory");
  const sev = normalizeSeverity("trivy", record.severity);
  const cvss = cvssForProvenance(record.cvss);
  return {
    ...built.body,
    severity: sev.severity,
    severityAssumed: sev.assumed,
    confidence: "high",
    confidenceBasis: "tool",
    provenance: [
      {
        ruleId: record.id,
        severityRaw: record.severity.slice(0, 60),
        severityScale: "trivy",
        ...(cvss.length > 0 ? { cvss } : {}),
      },
    ],
  };
}

/** @returns {Readonly<object>} */
export function createTrivyScaAdapter() {
  return defineToolAdapter({
    toolId: "trivy",
    scanType: "sca",
    imageKey: "trivy",
    plan: (ctx) =>
      planScaTool(
        {
          toolId: "trivy",
          imageKey: "trivy",
          argv: TRIVY_SCA_ARGV,
          env: TRIVY_SCA_ENV,
          limits: SCA_TOOL_LIMITS.trivy,
        },
        ctx,
      ),
    parse: (streams, kit) => trivyRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit),
    recordSchema: trivyRecordSchema,
    map: (record) => mapTrivyRecord(record),
    maxRecords: SCA_MAX_RECORDS,
  });
}
