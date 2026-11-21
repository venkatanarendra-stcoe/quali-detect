import { isSafeRelativePath, normalizeOsvSeverity } from "@qmentisai/shared";
import { z } from "zod";
import { defineToolAdapter } from "../core/adapter.js";
import { canonicalAdvisory, canonicalPurl, normalizeAdvisoryId } from "../core/merge-keys.js";
import {
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
 * OSV-Scanner in offline mode as a tool adapter (docs/modules/scan-engines/SPEC.md 5.2, 5.6.2, 5.7, 5.12, 11.3, D-15, D-21; IMAGES.md
 * section 7). Sealed command line: `scan source --offline --offline-vulnerabilities --no-resolve --no-call-analysis=go --no-ignore
 * --config /rules/osv-scanner.toml -r /src --format json` with `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/db` (the read-only snapshot): no
 * network, no dependency resolution (nothing is fetched or built), no call analysis (it would run the Go toolchain), every
 * `osv-scanner.toml` of the repository ignored (`--no-ignore`, and the platform file is the only configuration).
 *
 * REAL RUN 2026-11-21 (ENG-G, OSV-Scanner 2.7.1, osv-scalibr 0.5.3, offline zips npm, PyPI, Go and Maven of 2026-11-21): exit 1 when
 * any vulnerability is found, 0 when none, 128 with an empty stdout when the tree has no package source ("No package sources found"),
 * 127 for a database error (`Error during extraction ... osvlocal`). JSON `results[]` of `{ source: { path: "/src/<lockfile>", type:
 * "lockfile" }, packages[] }`; a package is `{ package: { name, version, ecosystem, purl }, groups[], vulnerabilities[] }`: `groups[]` is
 * the TOOL'S OWN grouping of aliases (`ids`, `aliases`), one finding per group (SE-12: the tool itself reports them as one);
 * `vulnerabilities[]` are the full OSV records. Quirks reconciled: the Go ecosystem version has NO `v` prefix (`0.14.0`) while Trivy and
 * the purl rule use `v0.14.0`, so a Go version is written back with `v`; the npm purl carries a `?source=PUBLIC_REGISTRY` qualifier
 * (dropped by the canonical purl); a Go advisory carries no severity at all (so `severityAssumed`).
 */

export const OSV_SCA_ARGV = Object.freeze([
  "scan",
  "source",
  "--offline",
  "--offline-vulnerabilities",
  "--no-resolve",
  "--no-call-analysis=go",
  "--no-ignore",
  "--config",
  "/rules/osv-scanner.toml",
  "-r",
  "/src",
  "--format",
  "json",
]);
export const OSV_SCA_ENV = Object.freeze({ OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: "/db" });
/** Exit codes that carry a result: 0 nothing found, 1 vulnerabilities found, 128 no package source (an empty stdout). */
export const OSV_ACCEPTED_EXIT_CODES = Object.freeze([0, 1, 128]);
const SOURCE_PREFIX = "/src/";

const vulnSchema = z
  .object({
    id: text(80),
    aliases: z.array(text(80)).max(40),
    summary: clipped(200).optional(),
    label: z.string().max(40).optional(),
    vectors: z.array(text(200)).max(6),
    fixed: z.array(text(100)).max(SCA_MAX_FIXED * 3),
    cwe: z.array(z.string().max(20)).max(20),
  })
  .strict();

/** One OSV group of one package of one lockfile (the record the framework validates). */
export const osvRecordSchema = z
  .object({
    path: z.string().refine(isSafeRelativePath, "unsafe path"),
    ecosystem: text(40),
    name: text(300),
    version: text(100),
    purl: text(500).refine((p) => canonicalPurl(p) !== null, "not a package URL"),
    ids: z.array(text(80)).min(1).max(40),
    aliases: z.array(text(80)).max(40),
    vulns: z.array(vulnSchema).max(40),
  })
  .strict();

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const strings = (list, max) =>
  (Array.isArray(list) ? list : []).filter((x) => typeof x === "string").slice(0, max);

/** The fixed versions an OSV record names for one package (SEMVER and ECOSYSTEM ranges only; a GIT range holds commits, not versions). */
function fixedVersionsOf(vuln, name, ecosystem) {
  const out = [];
  for (const a of Array.isArray(vuln.affected) ? vuln.affected.slice(0, 200) : []) {
    if (
      !isObject(a) ||
      !isObject(a.package) ||
      a.package.name !== name ||
      a.package.ecosystem !== ecosystem
    )
      continue;
    for (const r of Array.isArray(a.ranges) ? a.ranges.slice(0, 20) : []) {
      if (!isObject(r) || (r.type !== "SEMVER" && r.type !== "ECOSYSTEM")) continue;
      for (const e of Array.isArray(r.events) ? r.events.slice(0, 100) : [])
        if (isObject(e) && typeof e.fixed === "string" && e.fixed !== "") out.push(e.fixed);
    }
  }
  return [...new Set(out)];
}

function flattenVuln(v, name, ecosystem) {
  const vectors = [];
  for (const s of Array.isArray(v.severity) ? v.severity.slice(0, 6) : [])
    if (isObject(s) && typeof s.score === "string" && storedCvssVersion(s.score) !== null)
      vectors.push(s.score);
  const db = isObject(v.database_specific) ? v.database_specific : {};
  return {
    id: v.id,
    aliases: usableAdvisoryIds(v.aliases, 40),
    summary: typeof v.summary === "string" && v.summary !== "" ? v.summary : undefined,
    label: typeof db.severity === "string" ? db.severity : undefined,
    vectors,
    fixed: fixedVersionsOf(v, name, ecosystem),
    cwe: strings(db.cwe_ids, 20),
  };
}

/**
 * Flattens a parsed OSV-Scanner report into one record per group of one package. A result whose source is not a lockfile under `/src/`
 * (or a package without a group) yields a null record (dropped and counted).
 * @param {unknown} doc @param {{ ToolOutputError: new (reason: string, detail: string) => Error }} kit
 * @returns {(object | null)[]}
 */
export function osvRecords(doc, kit) {
  if (!isObject(doc) || !Array.isArray(doc.results))
    throw new kit.ToolOutputError("output_invalid", "not an OSV-Scanner report");
  const out = [];
  for (const result of doc.results) {
    const src = isObject(result) && isObject(result.source) ? result.source.path : undefined;
    const path =
      typeof src === "string" && src.startsWith(SOURCE_PREFIX)
        ? src.slice(SOURCE_PREFIX.length)
        : null;
    const packages = isObject(result) && Array.isArray(result.packages) ? result.packages : null;
    if (path === null || packages === null) {
      out.push(null);
      continue;
    }
    for (const p of packages) {
      const pkg = isObject(p) && isObject(p.package) ? p.package : null;
      const groups = isObject(p) && Array.isArray(p.groups) ? p.groups : [];
      const vulns = isObject(p) && Array.isArray(p.vulnerabilities) ? p.vulnerabilities : [];
      if (pkg === null) {
        out.push(null);
        continue;
      }
      const byId = new Map();
      for (const v of vulns) if (isObject(v) && typeof v.id === "string") byId.set(v.id, v);
      for (const g of groups) {
        if (!isObject(g) || !Array.isArray(g.ids)) {
          out.push(null);
          continue;
        }
        const ids = usableAdvisoryIds(g.ids, 40);
        out.push({
          path,
          ecosystem: pkg.ecosystem,
          name: pkg.name,
          version: pkg.version,
          purl: goPurl(pkg),
          ids,
          aliases: usableAdvisoryIds(g.aliases, 40),
          vulns: ids
            .map((id) => byId.get(id))
            .filter(Boolean)
            .slice(0, 40)
            .map((v) => flattenVuln(v, pkg.name, pkg.ecosystem)),
        });
      }
    }
  }
  return out;
}

/**
 * The purl of an OSV package. Go module versions are written `v<version>` by the purl rule and by Trivy, but OSV-Scanner drops the `v`:
 * a Go version that starts with a digit gets it back, so the two tools' components are equal (SE-12: a version disagreement would
 * keep two findings for one lockfile entry).
 * @param {Record<string, any>} pkg
 */
function goPurl(pkg) {
  const purl = typeof pkg.purl === "string" ? pkg.purl : undefined;
  if (pkg.ecosystem !== "Go" || purl === undefined) return purl;
  const parsed = canonicalPurl(purl);
  if (!parsed || !parsed.version || !/^\d/.test(parsed.version)) return purl;
  return `pkg:golang/${parsed.namespace ? `${parsed.namespace}/` : ""}${parsed.name}@v${parsed.version}`;
}

/**
 * The pure mapper of an OSV group to a vulnerability candidate body. The group's severity is the highest of its advisories (a
 * `database_specific.severity` label first, else the CVSS v3 vector scored by the in-repo calculator, else `medium` assumed; a CVSS
 * v4 vector is kept in the provenance but not scored, SPEC 5.7); the confidence is `high`.
 * @param {z.infer<typeof osvRecordSchema>} record
 */
export function mapOsvRecord(record) {
  const ids = [
    ...record.ids,
    ...record.aliases,
    ...record.vulns.flatMap((v) => [v.id, ...v.aliases]),
  ];
  const primary =
    canonicalAdvisory(ids.map(normalizeAdvisoryId).filter(Boolean))?.id ?? record.ids[0];
  const first = record.vulns[0];
  const built = scaBody({
    purl: record.purl,
    advisoryIds: ids,
    primaryId: primary,
    title: first?.summary ?? "",
    path: record.path,
    fixed: record.vulns.flatMap((v) => v.fixed),
    cwe: cweList(record.vulns.flatMap((v) => v.cwe)),
  });
  if (built === null) throw new TypeError("a record without a usable purl or advisory");
  const sev = normalizeOsvSeverity(
    record.vulns.map((v) => ({ label: v.label, vectors: v.vectors })),
  );
  const cvss = cvssForProvenance(
    record.vulns.flatMap((v) =>
      v.vectors.map((vector) => ({
        version: storedCvssVersion(vector),
        vector,
        ...(sev.scores[vector] !== undefined ? { score: sev.scores[vector] } : {}),
      })),
    ),
  );
  return {
    ...built.body,
    severity: sev.severity,
    severityAssumed: sev.assumed,
    confidence: "high",
    confidenceBasis: "tool",
    provenance: [
      {
        ruleId: built.body.rule.id,
        severityRaw: sev.raw,
        severityScale: sev.scale,
        ...(cvss.length > 0 ? { cvss } : {}),
      },
    ],
  };
}

/** @returns {Readonly<object>} */
export function createOsvScannerAdapter() {
  return defineToolAdapter({
    toolId: "osv-scanner",
    scanType: "sca",
    imageKey: "osv-scanner",
    plan: (ctx) =>
      planScaTool(
        {
          toolId: "osv-scanner",
          imageKey: "osv-scanner",
          argv: OSV_SCA_ARGV,
          env: OSV_SCA_ENV,
          limits: SCA_TOOL_LIMITS["osv-scanner"],
        },
        ctx,
      ),
    parse: (streams, kit) => {
      // exit 128 ("no package sources") writes nothing: that is an honest empty result, not a malformed one
      if (streams.exitCode === 128 && Buffer.byteLength(streams.stdout ?? "") === 0) return [];
      return osvRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit);
    },
    recordSchema: osvRecordSchema,
    map: (record) => mapOsvRecord(record),
    acceptedExitCodes: OSV_ACCEPTED_EXIT_CODES,
    maxRecords: SCA_MAX_RECORDS,
  });
}
