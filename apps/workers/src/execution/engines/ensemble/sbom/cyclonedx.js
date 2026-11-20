import { isSafeRelativePath } from "@qmentisai/shared";
import { z } from "zod";
import { canonicalPurl, sbomKey } from "../core/merge-keys.js";

/**
 * CycloneDX handling of the SBOM ensemble (docs/modules/scan-engines/SPEC.md 5.6.1, 7.2, OQ-14, part E). OQ-14 decision applied:
 * both Syft and Trivy are asked for CycloneDX JSON only (`-o cyclonedx-json`, `--format cyclonedx`); SPDX is NOT parsed in v1 and
 * no raw tool document is stored by this part (the `sbom_document` artifact class exists for part K to use if the owner wants the
 * document kept). The document is UNTRUSTED: it is read by the bounded parse kit, every component passes a strict bounded schema,
 * and one RECORD is produced per canonical purl (SE-12 read strictly: a tool never reports one component twice; occurrences become
 * `paths` of the one record).
 *
 * FIDELITY WAS CHECKED AGAINST REAL OUTPUT on 2026-11-20 (ENG-L20, `docs/modules/scan-engines/ENG_L20_RESULT.md`, Syft 1.57.2 and Trivy
 * 0.76.2, CycloneDX 1.7): Syft writes `syft:location:<n>:path` with a leading slash and `syft:package:foundBy`; Trivy writes no path
 * property for these package types and gives the lockfile only as the NAME of an `application` component, reachable from a library
 * through the `dependencies` graph (for Go and Maven through the root module or project, so the walk below is transitive); Trivy writes
 * no `purl` for operating-system packages in filesystem mode (no OS family is detected), so a purl-less Trivy library is not a record.
 * Neither tool wrote `scope`, `evidence.occurrences` or `aquasecurity:trivy:FilePath` for any package of the captured trees: those
 * three readers stay (the documented formats) but are UNVERIFIED by real output. A package listed once per lockfile is a real case
 * (same purl, different `bom-ref`): repeats are folded.
 */

/** Components examined per document; more is refused (`output_too_large`) before any work is done. */
export const SBOM_MAX_SCANNED_COMPONENTS = 500_000;
/** Records an SBOM tool may report in one run (the legacy engine's component cap). */
export const SBOM_MAX_RECORDS = 50_000;
/** Occurrences kept per component (SPEC 5.6.1: cap 20, plus the exact count). */
export const SBOM_MAX_PATHS = 20;

// eslint-disable-next-line no-control-regex -- refusing control characters in untrusted text is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const text = (max, min = 1) =>
  z
    .string()
    .min(min)
    .max(max)
    .refine((s) => !CONTROL.test(s), "control characters");

const CDX_SCOPES = Object.freeze({ required: "prod", optional: "optional", excluded: "dev" });
/** The strongest scope wins when one component is listed twice (SPEC 5.6.1: prod over dev over optional). */
const SCOPE_RANK = Object.freeze({ prod: 3, dev: 2, optional: 1 });

const propertySchema = z.object({
  name: z.string().max(200),
  value: z.string().max(2000).optional(),
});

/** One CycloneDX component as read from a tool: bounded, unknown keys stripped. */
export const cdxComponentSchema = z.object({
  "bom-ref": z.string().max(1200).optional(),
  type: z.string().max(40),
  name: z.string().max(1000),
  version: z.string().max(200).optional(),
  scope: z.string().max(20).optional(),
  purl: z.string().max(2000).optional(),
  properties: z.array(propertySchema).max(200).optional(),
  evidence: z
    .object({
      occurrences: z
        .array(z.object({ location: z.string().max(1100).optional() }))
        .max(200)
        .optional(),
    })
    .optional(),
});

/** The record the adapters hand to the framework: ONE component with all its occurrences. Strict. */
export const sbomRecordSchema = z
  .object({
    purl: z
      .string()
      .min(1)
      .max(500)
      .refine((p) => canonicalPurl(p) !== null, "not a package URL"),
    scope: z.enum(["prod", "dev", "optional", "peer", "unknown"]).optional(),
    paths: z.array(z.string().refine(isSafeRelativePath, "unsafe path")).max(SBOM_MAX_PATHS),
    pathCount: z.number().int().min(0).max(10_000_000),
    foundBy: text(120).optional(),
  })
  .strict();

/**
 * A tool-reported location as a repository-relative path, or null: one leading `/` or `./` is removed (the tools print paths
 * relative to the scanned root, Syft with a leading slash), and the result must be a safe relative path.
 * @param {unknown} value
 */
export function relativeLocation(value) {
  if (typeof value !== "string") return null;
  let p = value;
  if (p.startsWith("/")) p = p.slice(1);
  while (p.startsWith("./")) p = p.slice(2);
  return isSafeRelativePath(p) ? p : null;
}

const prop = (component, pattern) =>
  (component.properties ?? []).filter((p) => pattern.test(p.name) && p.value !== undefined);

/**
 * Whether a component is a package (a record) as opposed to the tool's own bookkeeping (the scanned root, a lockfile
 * `application`, a file, an operating system). Libraries and frameworks always are; any other type only when it carries a purl.
 * @param {{ type: string, purl?: string }} c
 */
export function isPackageComponent(c) {
  if (c.type === "library" || c.type === "framework") return true;
  return c.type === "application" && typeof c.purl === "string" && c.purl.length > 0;
}

/**
 * Turns a parsed CycloneDX document into folded records. Throws the parse kit's `ToolOutputError` for a document that is not
 * CycloneDX 1.x JSON or that is too large; a component that fails its schema yields `null` (dropped and counted by the framework).
 * @param {unknown} doc
 * @param {{ ToolOutputError: new (reason: string, detail: string) => Error }} kit
 * @param {{ refPaths?: (doc: any) => Map<string, string[]>, purlOptional?: boolean }} [flavor] Trivy: the lockfile path of a library from
 *   the dependency graph; `purlOptional`: a library without a purl is skipped, not counted as invalid (real Trivy output for OS packages)
 * @returns {(object | null)[]}
 */
export function cyclonedxRecords(doc, kit, flavor = {}) {
  const bad = (reason, detail) => new kit.ToolOutputError(reason, detail);
  if (doc === null || typeof doc !== "object" || Array.isArray(doc))
    throw bad("output_invalid", "not a CycloneDX document");
  const d = /** @type {Record<string, any>} */ (doc);
  if (d.bomFormat !== "CycloneDX" || !/^1\.\d{1,2}$/.test(String(d.specVersion)))
    throw bad("output_invalid", "not a CycloneDX 1.x document");
  const components = d.components === undefined ? [] : d.components;
  if (!Array.isArray(components)) throw bad("output_invalid", "components is not a list");
  if (components.length > SBOM_MAX_SCANNED_COMPONENTS)
    throw bad("output_too_large", "too many components");
  const refPaths = flavor.refPaths ? flavor.refPaths(d) : new Map();
  /** @type {Map<string, { purl: string, scope: string | undefined, paths: Set<string>, foundBy: string | undefined }>} */
  const folded = new Map();
  /** @type {null[]} */
  const invalid = [];
  for (const raw of components) {
    const parsed = cdxComponentSchema.safeParse(raw);
    if (!parsed.success) {
      // a malformed entry is dropped and counted, unless it is clearly not a package (never a record)
      const type = raw && typeof raw === "object" ? raw.type : undefined;
      if (type === "library" || type === "framework" || type === undefined) invalid.push(null);
      continue;
    }
    const c = parsed.data;
    if (!isPackageComponent(c)) continue;
    if (flavor.purlOptional === true && (c.purl === undefined || c.purl === "")) continue;
    const canonical = typeof c.purl === "string" ? canonicalPurl(c.purl) : null;
    if (canonical === null) {
      invalid.push(null);
      continue;
    }
    const paths = [
      ...prop(c, /^syft:location:\d+:path$/).map((p) => p.value),
      ...prop(c, /^aquasecurity:trivy:FilePath$/).map((p) => p.value),
      ...(c.evidence?.occurrences ?? []).map((o) => o.location),
      ...(refPaths.get(c["bom-ref"] ?? "") ?? []),
    ]
      .map(relativeLocation)
      .filter((p) => p !== null);
    const foundBy = prop(c, /^syft:package:foundBy$/)[0]?.value;
    const entry = folded.get(canonical.canonical) ?? {
      purl: canonical.canonical,
      scope: undefined,
      paths: new Set(),
      foundBy: undefined,
    };
    for (const p of paths) entry.paths.add(p);
    const scope = c.scope === undefined ? undefined : CDX_SCOPES[c.scope];
    if (
      scope !== undefined &&
      (entry.scope === undefined || SCOPE_RANK[scope] > SCOPE_RANK[entry.scope])
    )
      entry.scope = scope;
    entry.foundBy ??=
      foundBy !== undefined && !CONTROL.test(foundBy) ? foundBy.slice(0, 120) : undefined;
    folded.set(canonical.canonical, entry);
  }
  const records = [...folded.values()]
    .sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0))
    .map((e) => {
      const sorted = [...e.paths].sort();
      return {
        purl: e.purl,
        ...(e.scope ? { scope: e.scope } : {}),
        paths: sorted.slice(0, SBOM_MAX_PATHS),
        pathCount: sorted.length,
        ...(e.foundBy ? { foundBy: e.foundBy } : {}),
      };
    });
  return [...records, ...invalid];
}

/** Most graph nodes the lockfile walks may visit in total per document (a hostile graph cannot cost more than this). */
export const TRIVY_GRAPH_VISIT_CAP = 2_000_000;

/**
 * Trivy puts a library under the `application` component of its lockfile (the component name is the lockfile path) and lists the
 * libraries in the `dependencies` graph. Real output (ENG-L20): an application lists its direct packages, but for Go and Maven it
 * lists the root module or project, which lists the dependencies, so each lockfile is walked transitively over the `dependsOn` edges,
 * never through another lockfile application (one lockfile's packages never take the path of another) and never revisiting a node.
 * Returns bom-ref of a library to the paths of the lockfiles that reach it. At most `maxVisits` (default
 * {@link TRIVY_GRAPH_VISIT_CAP}) visits in total.
 * @param {any} doc
 * @param {number} [maxVisits]
 * @returns {Map<string, string[]>}
 */
export function trivyRefPaths(doc, maxVisits = TRIVY_GRAPH_VISIT_CAP) {
  const apps = new Map();
  for (const c of Array.isArray(doc.components) ? doc.components : []) {
    if (
      c &&
      typeof c === "object" &&
      c.type === "application" &&
      typeof c.purl !== "string" &&
      typeof c["bom-ref"] === "string" &&
      typeof c.name === "string"
    ) {
      const p = relativeLocation(c.name);
      if (p !== null) apps.set(c["bom-ref"], p);
    }
  }
  /** @type {Map<string, string[]>} */
  const edges = new Map();
  for (const dep of Array.isArray(doc.dependencies) ? doc.dependencies : [])
    if (typeof dep?.ref === "string" && Array.isArray(dep.dependsOn))
      edges.set(
        dep.ref,
        dep.dependsOn.filter((r) => typeof r === "string"),
      );
  /** @type {Map<string, string[]>} */
  const out = new Map();
  let visits = 0;
  // bounded: one walk per lockfile application; each walk visits a node at most once and all walks share one visit cap
  for (const [appRef, file] of apps) {
    const seen = new Set([appRef]);
    const queue = [...(edges.get(appRef) ?? [])];
    for (let i = 0; i < queue.length; i += 1) {
      const ref = queue[i];
      if (seen.has(ref) || apps.has(ref)) continue;
      seen.add(ref);
      visits += 1;
      if (visits > maxVisits) return out;
      const list = out.get(ref) ?? [];
      if (!list.includes(file)) list.push(file);
      out.set(ref, list);
      for (const next of edges.get(ref) ?? []) queue.push(next);
    }
  }
  return out;
}

/**
 * The pure mapper of a folded record to a component candidate body (SPEC 7.2, 5.6.1). Total on a record that passed
 * {@link sbomRecordSchema}: name, version and ecosystem come from the canonical purl (so every tool agrees), the severity is `info`
 * and the confidence is the unknown-tool default `medium` (two tools agreeing raise it to `high`, SE-13).
 * @param {z.infer<typeof sbomRecordSchema>} record
 */
export function mapSbomRecord(record) {
  const p = /** @type {NonNullable<ReturnType<typeof canonicalPurl>>} */ (
    canonicalPurl(record.purl)
  );
  const name = p.namespace ? `${p.namespace}/${p.name}` : p.name;
  const title = (p.version ? `${name}@${p.version}` : name).slice(0, 200);
  return {
    kind: "component",
    dedupKey: sbomKey(p.canonical),
    title,
    severity: "info",
    severityAssumed: false,
    confidence: "medium",
    confidenceBasis: "tool",
    rule: { id: "component" },
    component: {
      purl: p.canonical,
      name: name.slice(0, 200),
      ...(p.version ? { version: p.version.slice(0, 100) } : {}),
      ecosystem: p.type,
      ...(record.scope ? { scope: record.scope } : {}),
    },
    ...(record.paths.length > 0
      ? {
          location: { path: record.paths[0] },
          locations: record.paths.map((path) => ({ path })),
          locationCount: record.pathCount,
        }
      : {}),
    provenance: [
      {
        ...(record.foundBy ? { ruleId: record.foundBy } : {}),
        severityRaw: "",
        severityScale: "none",
      },
    ],
  };
}
