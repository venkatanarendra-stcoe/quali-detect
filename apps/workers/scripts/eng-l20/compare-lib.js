/**
 * ENG-L20 offline comparison (docs/modules/scan-engines/ENG_L20_RUNBOOK.md, SPEC scan-engines 16.2 ENG-L20). Takes the captured
 * output of the real Syft and Trivy runs and checks EVERY assumption the Part E SBOM adapters make against it, with no Docker, no
 * network and no execution of anything found in the data. PURE: the caller supplies the manifest, a reader for the captured
 * files and (optionally) a tree existence probe; this module opens nothing.
 *
 * Hostile-input rules: every captured document passes the bounded parse kit (size, depth, node and forbidden-key caps); every
 * string that reaches the report passes {@link safeText} (control characters removed, length cut, credential shapes redacted);
 * property VALUES are never reported except for the three path/cataloger properties the adapters read; stderr is reported as
 * counts plus at most five redacted, cut lines; the report is deterministic (no clock, no random).
 *
 * Statuses: PASS (the capture agrees with the assumption), MISMATCH (it contradicts it; `impact` says whether the adapter
 * degrades or breaks), UNKNOWN (the capture cannot decide it: the run or the evidence is absent).
 */
import {
  ToolOutputError,
  canonicalPurl,
  mergeTaskCandidates,
  parseBoundedJson,
  runToolParse,
} from "../../src/execution/engines/ensemble/core/index.js";
import {
  SBOM_TOOL_LIMITS,
  createSyftAdapter,
  createTrivySbomAdapter,
  isPackageComponent,
  relativeLocation,
  trivyRefPaths,
} from "../../src/execution/engines/ensemble/sbom/index.js";

export const REPORT_VERSION = 1;
export const TOOLS = Object.freeze(["syft", "trivy"]);
export const MAX_TABLE_ROWS = 200;
export const MAX_EXAMPLES = 5;
/** Candidates the offline merge accepts; the merger is super-linear (about 24 s for 50000 candidates when measured). */
export const MAX_MERGE_CANDIDATES = 20_000;
export const LIMITS = Object.freeze({
  manifestBytes: 1024 * 1024,
  stdoutBytes: 64 * 1024 * 1024,
  stderrBytes: 64 * 1024,
});

/**
 * The assumptions the adapters make, ENUMERATED from `sbom/cyclonedx.js`, `syft.js`, `trivy-sbom.js` and `plan.js`. The suite
 * (`ENG-S15c`) proves each `literal` still occurs in the adapter source, so the list cannot silently drift from the code.
 */
export const ASSUMPTIONS = Object.freeze([
  { id: "A-format", literal: "CycloneDX", text: "bomFormat is CycloneDX" },
  { id: "A-spec", literal: "specVersion", text: "specVersion is 1.x" },
  {
    id: "A-components",
    literal: "components",
    text: "components is an array of component objects",
  },
  {
    id: "A-bomref",
    literal: "bom-ref",
    text: "bom-ref identifies a component (used for Trivy lockfile paths)",
  },
  { id: "A-purl", literal: "purl", text: "every package component carries a parseable purl" },
  {
    id: "A-type",
    literal: "library",
    text: "packages are type library or framework (or application with a purl)",
  },
  { id: "A-scope", literal: "excluded", text: "scope is required, optional or excluded" },
  {
    id: "A-syft-loc",
    literal: "syft:location",
    text: "Syft writes syft:location:<n>:path properties",
  },
  {
    id: "A-syft-foundby",
    literal: "syft:package:foundBy",
    text: "Syft writes syft:package:foundBy",
  },
  {
    id: "A-occurrences",
    literal: "occurrences",
    text: "CycloneDX 1.5 evidence.occurrences[].location",
  },
  {
    id: "A-trivy-path",
    literal: "aquasecurity:trivy:FilePath",
    text: "Trivy writes aquasecurity:trivy:FilePath",
  },
  {
    id: "A-trivy-graph",
    literal: "dependsOn",
    text: "Trivy lockfile application components list libraries in dependencies[].dependsOn",
  },
  {
    id: "A-path-form",
    literal: "isSafeRelativePath",
    text: "paths are relative to the scanned root, optionally with one leading slash or ./",
  },
  { id: "A-exit", literal: "acceptedExitCodes", text: "a successful run exits 0" },
]);

/* eslint-disable no-control-regex -- removing control characters from untrusted text is the point */
const CONTROL =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
/* eslint-enable no-control-regex */
const SECRET_SHAPES = [
  /gh[pousr]_[A-Za-z0-9]{20,}/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /AKIA[0-9A-Z]{12,}/g,
  /xox[abprs]-[A-Za-z0-9-]{10,}/g,
  /sk-[A-Za-z0-9_-]{20,}/g,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\b(?:token|password|passwd|secret|apikey|api_key|authorization)\s*[=:]\s*\S+/gi,
  /\b[A-Za-z0-9+_-]{40,}={0,2}\b/g,
];

/**
 * Text that is safe to print: control and bidirectional characters removed, credential shapes redacted, cut to `max`.
 * @param {unknown} value @param {number} [max]
 */
export function safeText(value, max = 160) {
  let s = typeof value === "string" ? value : String(value ?? "");
  s = s.replace(CONTROL, " ");
  for (const re of SECRET_SHAPES) s = s.replace(re, "[redacted]");
  s = s.trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

export class CompareInputError extends Error {
  /** @param {string} code a fixed word */
  constructor(code, message) {
    super(message);
    this.name = "CompareInputError";
    this.code = code;
  }
}

const ok = (id, tool, assumption, observed) => ({ id, tool, assumption, status: "PASS", observed });
const bad = (id, tool, assumption, observed, impact = "degraded") => ({
  id,
  tool,
  assumption,
  status: "MISMATCH",
  impact,
  observed,
});
const unknown = (id, tool, assumption, observed) => ({
  id,
  tool,
  assumption,
  status: "UNKNOWN",
  observed,
});
const pick = (cond, id, tool, assumption, observedOk, observedBad, impact) =>
  cond ? ok(id, tool, assumption, observedOk) : bad(id, tool, assumption, observedBad, impact);

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const asArray = (v) => (Array.isArray(v) ? v : []);
const bump = (map, key, n = 1) => map.set(key, (map.get(key) ?? 0) + n);
const sortedObject = (map) =>
  Object.fromEntries([...map.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
const first = (arr, n = MAX_EXAMPLES) => arr.slice(0, n);

// ---- manifest -----------------------------------------------------------------------------------------------------------

const RUN_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** Validates the manifest written by capture.js; throws {@link CompareInputError} for an unusable one. */
export function readManifest(manifest) {
  if (!isObj(manifest) || manifest.manifestVersion !== 1 || !Array.isArray(manifest.runs))
    throw new CompareInputError(
      "manifest_invalid",
      "manifest.json is not a version 1 capture manifest",
    );
  if (manifest.runs.length > 64) throw new CompareInputError("manifest_invalid", "too many runs");
  const runs = new Map();
  for (const r of manifest.runs) {
    if (!isObj(r) || typeof r.id !== "string" || !RUN_ID.test(r.id) || runs.has(r.id))
      throw new CompareInputError("manifest_invalid", "a run id is malformed or repeated");
    for (const f of ["stdoutFile", "stderrFile"])
      if (
        r[f] !== undefined &&
        (typeof r[f] !== "string" || r[f] !== `${r.id}.${f === "stdoutFile" ? "stdout" : "stderr"}`)
      )
        throw new CompareInputError("manifest_invalid", "a file name does not follow the run id");
    runs.set(r.id, r);
  }
  return { runs, images: isObj(manifest.images) ? manifest.images : {} };
}

// ---- document analysis --------------------------------------------------------------------------------------------------

/** Component types the adapters treat as bookkeeping by design (CycloneDX types that are not packages). */
const BOOKKEEPING_TYPES = new Set([
  "file",
  "operating-system",
  "container",
  "device",
  "firmware",
  "data",
  "platform",
  "device-driver",
  "machine-learning-model",
  "cryptographic-asset",
]);
const SYFT_LOC = /^syft:location:\d+:path$/;
const PATHY_NAME = /path|file|location|source|layer/i;

function formOf(raw) {
  if (typeof raw !== "string") return "non-string";
  if (raw.startsWith("/src/") || raw === "/src") return "container-mount-prefix";
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) return "uri-like";
  if (raw.includes("\\")) return "backslash";
  if (raw.split("/").includes("..")) return "traversal";
  if (raw.startsWith("/")) return "leading-slash";
  if (raw.startsWith("./")) return "dot-slash";
  return "bare-relative";
}

/** Explains, in fixed words, what the adapters' purl normalization changed. */
export function purlChangeTags(raw, canon) {
  if (canon === null) return ["unparseable"];
  if (raw === canon.canonical) return [];
  const tags = [];
  const m = /^pkg:([^/]+)\/(.*)$/s.exec(raw);
  const body = m ? m[2] : "";
  if (raw.includes("#")) tags.push("subpath-dropped");
  const q = raw.indexOf("?");
  if (q !== -1) {
    const rawKeys = raw
      .slice(q + 1)
      .split("#")[0]
      .split("&")
      .map((p) => p.split("=")[0].toLowerCase())
      .filter(Boolean);
    if (rawKeys.some((k) => !Object.keys(canon.qualifiers).includes(k)))
      tags.push("qualifiers-dropped");
  }
  const pathPart = body.split("?")[0].split("#")[0];
  const at = pathPart.lastIndexOf("@");
  const rawVersion = at > pathPart.lastIndexOf("/") ? decodeSafe(pathPart.slice(at + 1)) : null;
  const rawName = decodeSafe(
    (at > pathPart.lastIndexOf("/") ? pathPart.slice(0, at) : pathPart).split("/").pop() ?? "",
  );
  if (rawVersion !== null && canon.version !== null && rawVersion !== canon.version)
    tags.push("v-prefix-stripped");
  if (rawName !== null && rawName !== canon.name) {
    if (canon.type === "pypi") tags.push("pypi-name-normalized");
    else if (canon.type === "golang") tags.push("golang-lowercased");
    else tags.push(canon.type === "npm" ? "npm-lowercased" : "name-changed");
  }
  if (
    canon.type === "golang" &&
    canon.namespace !== null &&
    pathPart.split("/").slice(0, -1).join("/") !== encodeURI(canon.namespace) &&
    !tags.includes("golang-lowercased")
  )
    tags.push("golang-lowercased");
  if (tags.length === 0) tags.push("encoding-or-order");
  return tags;
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

/**
 * Reads one CycloneDX document (UNTRUSTED) into facts. Throws the parse kit's ToolOutputError for a refused document.
 * @param {Buffer} buffer @param {"syft" | "trivy"} tool
 */
export function analyzeDocument(buffer, tool) {
  const doc = parseBoundedJson(buffer);
  const facts = {
    tool,
    isObject: isObj(doc),
    bomFormat: isObj(doc) ? safeText(doc.bomFormat, 40) : null,
    specVersion: isObj(doc) ? safeText(doc.specVersion, 20) : null,
    componentsIsArray: isObj(doc) && Array.isArray(doc.components),
    hasDependencies: isObj(doc) && Array.isArray(doc.dependencies),
    dependencyCount: isObj(doc) ? asArray(doc.dependencies).length : 0,
    rootComponent:
      isObj(doc) && isObj(doc.metadata) && isObj(doc.metadata.component)
        ? {
            type: safeText(doc.metadata.component.type, 40),
            name: safeText(doc.metadata.component.name, 80),
          }
        : null,
    toolVersionInDoc: isObj(doc) && isObj(doc.metadata) ? metadataToolVersion(doc.metadata) : null,
    components: 0,
    typeCounts: new Map(),
    nonPackageWithPurl: [],
    libs: 0,
    libsWithoutPurl: 0,
    libsUnparseablePurl: 0,
    libsWithoutBomRef: 0,
    duplicateBomRefs: 0,
    duplicateRawPurls: 0,
    withHashes: 0,
    withLicenses: 0,
    scopeValues: new Map(),
    propertyNames: new Map(),
    sources: { syftLocation: 0, occurrences: 0, trivyFilePath: 0, foundBy: 0, graphLibs: 0 },
    pathyPropertyNames: new Map(),
    locations: [], // { raw, form, normalized }
    purls: [], // { raw, canonical, tags, type, namespace, name, version }
    applicationsWithoutPurl: 0,
    graphApplications: 0,
    libsWithPath: 0,
  };
  if (!facts.componentsIsArray) return { facts, doc };
  const components = doc.components;
  const bomRefs = new Set();
  const rawPurls = new Set();
  const graph = tool === "trivy" || facts.hasDependencies ? trivyRefPaths(doc) : new Map();
  for (const c of components) {
    facts.components += 1;
    if (!isObj(c)) continue;
    const type = typeof c.type === "string" ? safeText(c.type, 40) : "(none)";
    bump(facts.typeCounts, type);
    const pkg = isPackageComponent({ type: c.type, purl: c.purl });
    if (typeof c["bom-ref"] === "string") {
      if (bomRefs.has(c["bom-ref"])) facts.duplicateBomRefs += 1;
      bomRefs.add(c["bom-ref"]);
    }
    if (Array.isArray(c.hashes) && c.hashes.length > 0) facts.withHashes += 1;
    if (Array.isArray(c.licenses) && c.licenses.length > 0) facts.withLicenses += 1;
    if (typeof c.purl === "string" && !pkg && !BOOKKEEPING_TYPES.has(type))
      facts.nonPackageWithPurl.push(type);
    if (type === "application" && typeof c.purl !== "string") facts.applicationsWithoutPurl += 1;
    if (!pkg) continue;
    facts.libs += 1;
    if (typeof c["bom-ref"] !== "string") facts.libsWithoutBomRef += 1;
    if (c.scope !== undefined) bump(facts.scopeValues, safeText(c.scope, 20));
    const rawLocs = [];
    for (const p of asArray(c.properties)) {
      if (!isObj(p) || typeof p.name !== "string") continue;
      const name = safeText(p.name, 120);
      bump(facts.propertyNames, name.replace(/^(syft:location:)\d+(:)/, "$1<n>$2"));
      if (
        PATHY_NAME.test(name) &&
        !SYFT_LOC.test(p.name) &&
        p.name !== "aquasecurity:trivy:FilePath"
      )
        bump(facts.pathyPropertyNames, name);
      if (SYFT_LOC.test(p.name) && typeof p.value === "string") {
        facts.sources.syftLocation += 1;
        rawLocs.push(p.value);
      } else if (p.name === "aquasecurity:trivy:FilePath" && typeof p.value === "string") {
        facts.sources.trivyFilePath += 1;
        rawLocs.push(p.value);
      } else if (p.name === "syft:package:foundBy" && typeof p.value === "string")
        facts.sources.foundBy += 1;
    }
    if (isObj(c.evidence))
      for (const o of asArray(c.evidence.occurrences))
        if (isObj(o) && typeof o.location === "string") {
          facts.sources.occurrences += 1;
          rawLocs.push(o.location);
        }
    const viaGraph = typeof c["bom-ref"] === "string" ? (graph.get(c["bom-ref"]) ?? []) : [];
    if (viaGraph.length > 0) facts.sources.graphLibs += 1;
    for (const g of viaGraph) rawLocs.push(g);
    let any = false;
    for (const raw of rawLocs) {
      const normalized = relativeLocation(raw);
      facts.locations.push({ raw, form: formOf(raw), normalized });
      if (normalized !== null) any = true;
    }
    if (any) facts.libsWithPath += 1;
    if (typeof c.purl !== "string" || c.purl === "") {
      facts.libsWithoutPurl += 1;
      continue;
    }
    if (rawPurls.has(c.purl)) facts.duplicateRawPurls += 1;
    rawPurls.add(c.purl);
    const canon = canonicalPurl(c.purl);
    if (canon === null) facts.libsUnparseablePurl += 1;
    facts.purls.push({
      raw: c.purl,
      canonical: canon?.canonical ?? null,
      tags: purlChangeTags(c.purl, canon),
      type: canon?.type ?? null,
      namespace: canon?.namespace ?? null,
      name: canon?.name ?? null,
      version: canon?.version ?? null,
      componentVersion: typeof c.version === "string" ? c.version : null,
      componentName: typeof c.name === "string" ? c.name : null,
    });
  }
  if (tool === "trivy" || facts.hasDependencies) facts.graphApplications = graph.size;
  return { facts, doc };
}

function metadataToolVersion(metadata) {
  const tools = metadata.tools;
  const list = Array.isArray(tools) ? tools : isObj(tools) ? asArray(tools.components) : [];
  const t = list.find((x) => isObj(x) && typeof x.version === "string");
  return t ? safeText(t.version, 40) : null;
}

// ---- checks -------------------------------------------------------------------------------------------------------------

/**
 * Lines the real tools write on a successful sealed run (ENG-L20, 2026-11-20): Syft one `WARN no explicit name and version provided
 * for directory source` line; Trivy `INFO` and `WARN` lines (an ERROR or FATAL line is never benign).
 */
const BENIGN_STDERR = Object.freeze({
  syft: [/^\[\d+\]\s+WARN no explicit name and version provided for directory source\b/],
  trivy: [/^\d{4}-\d\d-\d\dT\S+\s+(INFO|WARN)\s/],
});

function stderrSummary(buffer, tool = null) {
  if (buffer === null) return null;
  const text = buffer.subarray(0, LIMITS.stderrBytes).toString("utf8");
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
  const benign = BENIGN_STDERR[tool] ?? [];
  return {
    bytes: buffer.length,
    lines: lines.length,
    unexpected: lines.filter((l) => !benign.some((re) => re.test(l))).length,
    head: first(lines).map((l) => safeText(l, 200)),
  };
}

/**
 * Compares a capture with the adapters' assumptions.
 * @param {{
 *   manifest: unknown,
 *   readOutput: (runId: string, stream: "stdout" | "stderr") => Buffer | null,
 *   lock?: { images?: { key: string, digest: string, version: string }[] },
 *   pathExists?: ((relativePath: string) => boolean) | null,
 *   devNpm?: { name: string, version: string }[]
 * }} input
 */
export function compareCapture({
  manifest,
  readOutput,
  lock = { images: [] },
  pathExists = null,
  devNpm = [],
}) {
  const { runs, images } = readManifest(manifest);
  const lockOf = (key) => asArray(lock.images).find((e) => e.key === key);
  const checks = [];
  const observations = { stderr: {}, versions: {}, documents: {}, notes: [] };
  const read = (id, stream) => {
    try {
      return readOutput(id, stream);
    } catch (error) {
      observations.notes.push(
        `${id}.${stream}: ${safeText(error?.code ?? error?.message ?? "unreadable", 60)}`,
      );
      return null;
    }
  };
  const adapters = { syft: createSyftAdapter(), trivy: createTrivySbomAdapter() };
  const docs = {};
  const candidatesByTool = {};

  for (const tool of TOOLS) {
    const entry = lockOf(tool);
    const limits = SBOM_TOOL_LIMITS[tool];
    // ---- image and version
    const img = images[tool];
    if (!isObj(img) || !entry)
      checks.push(
        unknown(
          `IMG-${tool}`,
          tool,
          "the captured image is the locked digest",
          "no image record in the manifest",
        ),
      );
    else if (img.digest !== entry.digest)
      checks.push(
        bad(
          `IMG-${tool}`,
          tool,
          "the captured image is the locked digest",
          `manifest digest ${safeText(img.digest, 80)} differs from the lock file`,
          "breaks",
        ),
      );
    else if (!Array.isArray(img.repoDigests) || img.repoDigests.length === 0)
      checks.push(
        unknown(
          `IMG-${tool}`,
          tool,
          "the captured image is the locked digest",
          "the runtime reported no RepoDigests (inspect the image by hand)",
        ),
      );
    else if (img.repoDigests.some((d) => typeof d === "string" && d.endsWith(`@${entry.digest}`)))
      checks.push(
        ok(
          `IMG-${tool}`,
          tool,
          "the captured image is the locked digest",
          entry.digest.slice(0, 19),
        ),
      );
    else
      checks.push(
        bad(
          `IMG-${tool}`,
          tool,
          "the captured image is the locked digest",
          "RepoDigests do not contain the locked digest",
          "breaks",
        ),
      );

    const vRun = runs.get(`${tool}-version`);
    const vOut = vRun ? read(vRun.id, "stdout") : null;
    if (!vRun || vOut === null || !entry)
      checks.push(
        unknown(
          `VER-${tool}`,
          tool,
          `the tool reports version ${entry?.version ?? "?"}`,
          "no version run",
        ),
      );
    else {
      const line = safeText(
        vOut
          .subarray(0, 4096)
          .toString("utf8")
          .split("\n")
          .find((l) => l.trim() !== "") ?? "",
        120,
      );
      observations.versions[tool] = line;
      const has = vOut.subarray(0, 4096).toString("utf8").includes(entry.version);
      checks.push(
        has
          ? ok(`VER-${tool}`, tool, `the tool reports version ${entry.version}`, line)
          : bad(`VER-${tool}`, tool, `the tool reports version ${entry.version}`, line, "degraded"),
      );
    }

    // ---- the sealed run: exit, time, stderr, DB
    const sealed = runs.get(`${tool}-sealed`);
    let chosen = sealed;
    if (!sealed) {
      checks.push(
        unknown(`EXIT-${tool}`, tool, "the sealed run exits 0", "no sealed run in the capture"),
      );
    } else {
      const wallS = Math.round((sealed.wallMs ?? 0) / 100) / 10;
      const clean =
        sealed.exitCode === 0 && sealed.timedOut !== true && sealed.stdoutTruncated !== true;
      checks.push(
        pick(
          clean,
          `EXIT-${tool}`,
          tool,
          "the sealed run exits 0 (adapter acceptedExitCodes = [0])",
          "exit 0, no timeout, output not cut",
          `exit ${sealed.exitCode}${sealed.signal ? ` signal ${safeText(sealed.signal, 12)}` : ""}${sealed.timedOut ? ", timed out" : ""}${sealed.stdoutTruncated ? ", output cut" : ""}`,
          "breaks",
        ),
      );
      const ratio = (sealed.wallMs ?? 0) / 1000 / limits.wallClockSeconds;
      checks.push(
        ratio >= 1
          ? bad(
              `TIME-${tool}`,
              tool,
              `the sealed run finishes inside the ${limits.wallClockSeconds} s wall clock`,
              `${wallS} s`,
              "breaks",
            )
          : ratio >= 0.5
            ? unknown(
                `TIME-${tool}`,
                tool,
                `the sealed run finishes inside the ${limits.wallClockSeconds} s wall clock`,
                `${wallS} s is over half the limit; calibrate (ENG-L10)`,
              )
            : ok(
                `TIME-${tool}`,
                tool,
                `the sealed run finishes inside the ${limits.wallClockSeconds} s wall clock`,
                `${wallS} s`,
              ),
      );
      const err = stderrSummary(read(sealed.id, "stderr"), tool);
      observations.stderr[`${tool}-sealed`] = err;
      checks.push(
        err === null
          ? unknown(
              `ERR-${tool}`,
              tool,
              "the sealed run writes nothing alarming to stderr",
              "stderr file missing",
            )
          : err.lines === 0
            ? ok(
                `ERR-${tool}`,
                tool,
                "the sealed run writes nothing alarming to stderr",
                "stderr empty",
              )
            : err.unexpected === 0
              ? ok(
                  `ERR-${tool}`,
                  tool,
                  "the sealed run writes nothing alarming to stderr",
                  `${err.lines} line(s), all of the informational kind the real ${tool} writes on a successful run`,
                )
              : unknown(
                  `ERR-${tool}`,
                  tool,
                  "the sealed run writes nothing alarming to stderr",
                  `${err.lines} line(s): read them (redacted head: ${err.head.map((l) => safeText(l, 100)).join(" | ")})`,
                ),
      );
      if (tool === "trivy") {
        if (sealed.exitCode === 0)
          checks.push(
            ok(
              "DB-trivy",
              tool,
              "Trivy SBOM mode (--scanners license) needs no vulnerability database offline",
              "sealed run succeeded with --network=none and no DB",
            ),
          );
        else {
          const fb = ["trivy-fallback-skipdb", "trivy-fallback-offline"]
            .map((id) => runs.get(id))
            .filter(Boolean);
          const worked = fb.find((r) => r.exitCode === 0);
          checks.push(
            bad(
              "DB-trivy",
              tool,
              "Trivy SBOM mode (--scanners license) needs no vulnerability database offline",
              `sealed run failed (exit ${sealed.exitCode}); ${worked ? `fallback ${worked.id} worked` : fb.length ? "fallbacks failed too" : "no fallback run"}; see stderr in the capture`,
              "breaks",
            ),
          );
          if (worked) chosen = worked;
        }
      }
    }

    // ---- configuration experiments
    const missing = runs.get(`${tool}-config-missing`);
    checks.push(
      !missing
        ? unknown(
            `CFG-read-${tool}`,
            tool,
            "the --config/-c file is actually read (a missing file is an error)",
            "no run",
          )
        : missing.exitCode !== 0 && missing.exitCode !== null
          ? ok(
              `CFG-read-${tool}`,
              tool,
              "the --config/-c file is actually read (a missing file is an error)",
              `missing config: exit ${missing.exitCode}`,
            )
          : unknown(
              `CFG-read-${tool}`,
              tool,
              "the --config/-c file is actually read (a missing file is an error)",
              "a missing config file is silently accepted: acceptance of the placeholder proves little",
            ),
    );
    const unkKey = runs.get(`${tool}-config-unknown-key`);
    checks.push(
      !unkKey
        ? unknown(
            `CFG-keys-${tool}`,
            tool,
            "the tool validates keys of the platform config (so the placeholder is parsed)",
            "no run",
          )
        : ok(
            `CFG-keys-${tool}`,
            tool,
            "an unknown key in the platform config is rejected or ignored (informational: real 1.57.2 and 0.76.2 ignore it, so only the missing-file check proves the file is read)",
            unkKey.exitCode !== 0 && unkKey.exitCode !== null
              ? `unknown key: exit ${unkKey.exitCode}`
              : "an unknown key is silently ignored (exit 0)",
          ),
    );
    const unkFlag = runs.get(`${tool}-unknown-flag`);
    if (unkFlag) {
      const e = stderrSummary(read(unkFlag.id, "stderr"));
      observations.stderr[`${tool}-unknown-flag`] = e;
    }
    checks.push(
      !unkFlag
        ? unknown(
            `FLAG-${tool}`,
            tool,
            "an unknown flag is rejected (flag spelling in the sealed argv is checked by the tool)",
            "no run",
          )
        : unkFlag.exitCode !== 0 && unkFlag.exitCode !== null
          ? ok(
              `FLAG-${tool}`,
              tool,
              "an unknown flag is rejected (flag spelling in the sealed argv is checked by the tool)",
              `unknown flag: exit ${unkFlag.exitCode}`,
            )
          : unknown(
              `FLAG-${tool}`,
              tool,
              "an unknown flag is rejected (flag spelling in the sealed argv is checked by the tool)",
              "an unknown flag is accepted: a misspelt security flag would pass unnoticed",
            ),
    );

    // ---- applicability, memory and database experiments (only when the capture has them; added after the first real run)
    const oom = runs.get(`${tool}-oom`);
    if (oom) {
      const e = stderrSummary(read(oom.id, "stderr"), tool);
      observations.stderr[`${tool}-oom`] = e;
      checks.push(
        pick(
          oom.exitCode === 137 && oom.timedOut !== true,
          `EXP-oom-${tool}`,
          tool,
          "a memory kill ends the container with exit 137 and no document",
          `exit 137, ${oom.stdoutBytes ?? 0} bytes of output, ${e === null ? "no stderr file" : `${e.lines} stderr line(s)`}`,
          `exit ${oom.exitCode}${oom.timedOut ? ", timed out" : ""}: the 137 rule does not describe this runtime`,
          "degraded",
        ),
      );
    }
    const nolock = runs.get(`${tool}-nolock`);
    if (nolock) {
      const nb = read(nolock.id, "stdout");
      let packages = null;
      try {
        packages = nb === null ? null : analyzeDocument(nb, tool).facts.libs;
      } catch {
        packages = null;
      }
      checks.push(
        pick(
          nolock.exitCode === 0 && packages === 0,
          `EXP-nolock-${tool}`,
          tool,
          "a tree with nothing to catalog gives exit 0 and a CycloneDX document without packages (an empty result, not an error)",
          "exit 0, a document without packages",
          `exit ${nolock.exitCode}, packages ${packages === null ? "unreadable" : packages}`,
          "degraded",
        ),
      );
    }
    const vuln = runs.get(`${tool}-vuln-nodb`);
    if (vuln) {
      const e = stderrSummary(read(vuln.id, "stderr"), tool);
      observations.stderr[`${tool}-vuln-nodb`] = e;
      checks.push(
        pick(
          vuln.exitCode !== 0 && vuln.exitCode !== null,
          `EXP-vulndb-${tool}`,
          tool,
          "vulnerability mode without a database fails (exit non-zero) instead of reporting nothing: only the SBOM role runs without one",
          `exit ${vuln.exitCode}, ${e === null ? "no stderr file" : `${e.lines} stderr line(s)`}`,
          "vulnerability mode exited 0 without a database: an empty vulnerability list would look like a clean scan",
          "breaks",
        ),
      );
    }

    // ---- the document
    const out = chosen ? read(chosen.id, "stdout") : null;
    if (!chosen || out === null) {
      checks.push(
        unknown(
          `DOC-parse-${tool}`,
          tool,
          "the sealed stdout is a bounded CycloneDX JSON document",
          "no stdout captured",
        ),
      );
      continue;
    }
    let analyzed;
    try {
      analyzed = analyzeDocument(out, tool);
    } catch (error) {
      const word = error instanceof ToolOutputError ? error.reason : "output_invalid";
      checks.push(
        bad(
          `DOC-parse-${tool}`,
          tool,
          "the sealed stdout is a bounded CycloneDX JSON document",
          `refused by the strict parse kit: ${word}`,
          "breaks",
        ),
      );
      continue;
    }
    const f = analyzed.facts;
    docs[tool] = f;
    checks.push(
      ok(
        `DOC-parse-${tool}`,
        tool,
        "the sealed stdout is a bounded CycloneDX JSON document",
        `${out.length} bytes`,
      ),
    );
    const fmtOk = f.bomFormat === "CycloneDX" && /^1\.\d{1,2}$/.test(f.specVersion ?? "");
    checks.push(
      pick(
        fmtOk,
        `DOC-format-${tool}`,
        tool,
        "bomFormat CycloneDX, specVersion 1.x (the hand-written fixtures use 1.6)",
        `CycloneDX ${f.specVersion}`,
        `bomFormat ${f.bomFormat}, specVersion ${f.specVersion}`,
        "breaks",
      ),
    );
    checks.push(
      pick(
        f.componentsIsArray && f.components > 0,
        `DOC-components-${tool}`,
        tool,
        "components is a non-empty array",
        `${f.components} components`,
        f.componentsIsArray ? "components is empty" : "components is not an array",
        "breaks",
      ),
    );
    const odd = f.nonPackageWithPurl;
    checks.push(
      pick(
        odd.length === 0,
        `DOC-types-${tool}`,
        tool,
        "packages are library, framework or application with a purl; nothing else carries a purl",
        `types: ${JSON.stringify(sortedObject(f.typeCounts))}`,
        `${odd.length} component(s) of type ${[...new Set(odd)].join(",")} carry a purl and would be ignored`,
        "degraded",
      ),
    );
    // real Trivy (fs mode, no OS family detected) writes no purl for operating-system packages: skipped, not invalid
    const purlLess = tool === "trivy" ? f.libsWithoutPurl : 0;
    checks.push(
      pick(
        f.libsWithoutPurl - purlLess === 0 && f.libsUnparseablePurl === 0,
        `DOC-purl-${tool}`,
        tool,
        "every package component has a parseable purl (Trivy: operating-system packages carry none and are skipped)",
        purlLess > 0
          ? `${f.libs} package components, ${purlLess} without a purl (skipped by the adapter, the real Trivy behaviour), the rest parse`
          : `${f.libs} package components, all with a purl`,
        `${f.libsWithoutPurl} without a purl, ${f.libsUnparseablePurl} unparseable (dropped by the adapter)`,
        "degraded",
      ),
    );
    const refOk = f.duplicateBomRefs === 0 && (tool === "syft" || f.libsWithoutBomRef === 0);
    checks.push(
      pick(
        refOk,
        `DOC-bomref-${tool}`,
        tool,
        "bom-ref is unique and (Trivy) present on every library",
        "unique",
        `${f.duplicateBomRefs} duplicate bom-ref(s), ${f.libsWithoutBomRef} package(s) without bom-ref`,
        tool === "trivy" ? "breaks" : "degraded",
      ),
    );
    const knownScopes = ["required", "optional", "excluded"];
    const seenScopes = [...f.scopeValues.keys()];
    checks.push(
      seenScopes.length === 0
        ? unknown(
            `DOC-scope-${tool}`,
            tool,
            "scope values are required, optional or excluded",
            "no component carries a scope: the mapping is unexercised, every component is scope unknown",
          )
        : seenScopes.every((s) => knownScopes.includes(s))
          ? ok(
              `DOC-scope-${tool}`,
              tool,
              "scope values are required, optional or excluded",
              JSON.stringify(sortedObject(f.scopeValues)),
            )
          : bad(
              `DOC-scope-${tool}`,
              tool,
              "scope values are required, optional or excluded",
              `unmapped values: ${JSON.stringify(sortedObject(f.scopeValues))}`,
              "degraded",
            ),
    );
    // path sources
    const wanted =
      tool === "syft"
        ? f.sources.syftLocation + f.sources.occurrences
        : f.sources.trivyFilePath + f.sources.graphLibs;
    const sourceText = `syft:location=${f.sources.syftLocation}, evidence.occurrences=${f.sources.occurrences}, trivy:FilePath=${f.sources.trivyFilePath}, lockfile-graph libraries=${f.sources.graphLibs}`;
    checks.push(
      wanted > 0
        ? ok(
            `PATH-src-${tool}`,
            tool,
            tool === "syft"
              ? "locations come from syft:location:<n>:path or evidence.occurrences"
              : "locations come from aquasecurity:trivy:FilePath or the lockfile application graph",
            sourceText,
          )
        : bad(
            `PATH-src-${tool}`,
            tool,
            tool === "syft"
              ? "locations come from syft:location:<n>:path or evidence.occurrences"
              : "locations come from aquasecurity:trivy:FilePath or the lockfile application graph",
            `${sourceText}; path-like property names seen: ${JSON.stringify(sortedObject(f.pathyPropertyNames))}`,
            "degraded",
          ),
    );
    checks.push(
      f.sources.foundBy > 0 || tool === "trivy"
        ? ok(
            `PROP-foundby-${tool}`,
            tool,
            "Syft writes syft:package:foundBy (provenance rule id)",
            tool === "syft" ? `${f.sources.foundBy} components` : "not applicable to Trivy",
          )
        : bad(
            `PROP-foundby-${tool}`,
            tool,
            "Syft writes syft:package:foundBy (provenance rule id)",
            "property never seen (the rule id would be empty)",
            "degraded",
          ),
    );
    if (tool === "trivy")
      checks.push(
        f.hasDependencies && f.graphApplications > 0
          ? f.libsWithPath === f.libs - purlLess
            ? ok(
                "PATH-graph-trivy",
                tool,
                "lockfile application components list their libraries in dependencies[].dependsOn",
                `${f.graphApplications} libraries reached from a lockfile application cover all ${f.libs - purlLess} libraries with a purl`,
              )
            : bad(
                "PATH-graph-trivy",
                tool,
                "lockfile application components list their libraries in dependencies[].dependsOn",
                `${f.libsWithPath} of ${f.libs - purlLess} libraries obtain a path (${f.graphApplications} reached from a lockfile application)`,
                "degraded",
              )
          : bad(
              "PATH-graph-trivy",
              tool,
              "lockfile application components list their libraries in dependencies[].dependsOn",
              `dependencies: ${f.hasDependencies ? f.dependencyCount : "absent"}, lockfile applications found by the adapter: ${f.graphApplications}, applications without purl: ${f.applicationsWithoutPurl}`,
              "degraded",
            ),
      );
    // path forms
    if (f.locations.length === 0)
      checks.push(
        unknown(
          `PATH-form-${tool}`,
          tool,
          "paths are relative to the scanned root (optional one leading / or ./)",
          "no raw locations in the document",
        ),
      );
    else {
      const forms = new Map();
      for (const l of f.locations) bump(forms, l.form);
      const dropped = f.locations.filter((l) => l.normalized === null);
      const leak = f.locations.filter((l) => l.form === "container-mount-prefix");
      checks.push(
        dropped.length === 0 && leak.length === 0
          ? ok(
              `PATH-form-${tool}`,
              tool,
              "paths are relative to the scanned root (optional one leading / or ./)",
              `${f.locations.length} locations: ${JSON.stringify(sortedObject(forms))}`,
            )
          : bad(
              `PATH-form-${tool}`,
              tool,
              "paths are relative to the scanned root (optional one leading / or ./)",
              `${dropped.length} dropped by relativeLocation, ${leak.length} start with /src; forms ${JSON.stringify(sortedObject(forms))}; e.g. ${first(
                dropped.length ? dropped : leak,
                3,
              )
                .map((l) => safeText(l.raw, 80))
                .join(" | ")}`,
              "degraded",
            ),
      );
      observations.documents[tool] = {
        ...(observations.documents[tool] ?? {}),
        pathForms: sortedObject(forms),
        examples: first(f.locations, 5).map((l) => ({
          raw: safeText(l.raw, 120),
          form: l.form,
          normalized: l.normalized === null ? null : safeText(l.normalized, 120),
        })),
      };
      if (pathExists) {
        const missingPaths = [
          ...new Set(
            f.locations
              .filter((l) => l.normalized !== null && !pathExists(l.normalized))
              .map((l) => l.normalized),
          ),
        ];
        checks.push(
          pick(
            missingPaths.length === 0,
            `PATH-exists-${tool}`,
            tool,
            "every normalized path exists in the extracted tree (a part K pathExists filter would keep it)",
            "all paths exist",
            `${missingPaths.length} path(s) do not exist, e.g. ${first(missingPaths, 3)
              .map((p) => safeText(p, 80))
              .join(" | ")}`,
            "breaks",
          ),
        );
      } else
        checks.push(
          unknown(
            `PATH-exists-${tool}`,
            tool,
            "every normalized path exists in the extracted tree",
            "no --tree given",
          ),
        );
    }
    // purls
    const unparse = f.purls.filter((p) => p.canonical === null).length;
    const idem = f.purls.filter(
      (p) => p.canonical !== null && canonicalPurl(p.canonical)?.canonical !== p.canonical,
    ).length;
    const changed = f.purls.filter((p) => p.tags.length > 0 && p.canonical !== null).length;
    checks.push(
      pick(
        unparse === 0 && idem === 0,
        `PURL-norm-${tool}`,
        tool,
        "purls parse and the normalization is idempotent",
        `${f.purls.length} purls, ${changed} changed by normalization, 0 unparseable`,
        `${unparse} unparseable, ${idem} not idempotent`,
        "degraded",
      ),
    );
    // development dependencies (owner decision 2026-11-21, SPEC D-24: ALL components are listed)
    const devWanted = devNpm
      .slice(0, MAX_EXAMPLES * 4)
      .map((d) =>
        canonicalPurl(
          `pkg:npm/${d.name.startsWith("@") ? `%40${d.name.slice(1)}` : d.name}@${d.version}`,
        ),
      )
      .filter((c) => c !== null)
      .map((c) => c.canonical);
    const seenCanonical = new Set(f.purls.map((p) => p.canonical));
    const devMissing = devWanted.filter((c) => !seenCanonical.has(c));
    checks.push(
      devWanted.length === 0
        ? unknown(
            `DEV-included-${tool}`,
            tool,
            "the npm development dependencies of the tree are listed (the include-dev setting of the sealed configuration is effective)",
            "the extracted tree has no package-lock.json entry marked dev (pass --tree)",
          )
        : pick(
            devMissing.length === 0,
            `DEV-included-${tool}`,
            tool,
            "the npm development dependencies of the tree are listed (the include-dev setting of the sealed configuration is effective)",
            `${devWanted.length} development package(s) present`,
            `${devMissing.length} of ${devWanted.length} development package(s) missing: ${devMissing.map((c) => safeText(c, 80)).join(", ")} (an unknown configuration key is silently ignored by both tools)`,
            "degraded",
          ),
    );
    const vm = f.purls.filter(
      (p) =>
        p.canonical !== null &&
        p.version !== null &&
        p.componentVersion !== null &&
        p.version !== p.componentVersion &&
        p.version !== p.componentVersion.replace(/^v/, ""),
    );
    checks.push(
      pick(
        vm.length === 0,
        `PURL-ver-${tool}`,
        tool,
        "the component version equals the purl version (the adapter reads the purl)",
        "agree",
        `${vm.length} component(s) differ, e.g. ${first(vm, 3)
          .map(
            (p) =>
              `${safeText(p.name, 40)} ${safeText(p.componentVersion, 30)} vs ${safeText(p.version, 30)}`,
          )
          .join(" | ")}`,
        "degraded",
      ),
    );
    // counts, duplicates
    const run = adapters[tool];
    const parsed = runToolParse(
      run,
      { stdout: out, exitCode: chosen.exitCode ?? 0 },
      {
        taskRef: "00000000-0000-4000-8000-000000000000",
        toolRunId: "00000000-0000-4000-8000-0000000000a1",
        toolVersion: "eng-l20",
        imageDigest: null,
      },
    );
    candidatesByTool[tool] = parsed.candidates;
    observations.documents[tool] = {
      ...(observations.documents[tool] ?? {}),
      specVersion: f.specVersion,
      components: f.components,
      types: sortedObject(f.typeCounts),
      packages: f.libs,
      records: parsed.candidates.length,
      dropped: parsed.recordsDropped,
      hashes: f.withHashes,
      licences: f.withLicenses,
      properties: sortedObject(f.propertyNames),
      rootComponent: f.rootComponent,
      toolVersionInDocument: f.toolVersionInDoc,
    };
    checks.push(
      parsed.status === "succeeded"
        ? ok(
            `ADAPTER-${tool}`,
            tool,
            "the real adapter accepts the document (runToolParse succeeded, nothing dropped)",
            `${parsed.candidates.length} records from ${f.libs} package components`,
          )
        : bad(
            `ADAPTER-${tool}`,
            tool,
            "the real adapter accepts the document (runToolParse succeeded, nothing dropped)",
            `status ${parsed.status}, reason ${parsed.reason}, ${parsed.recordsDropped} dropped of ${parsed.recordsSeen}`,
            parsed.status === "failed" ? "breaks" : "degraded",
          ),
    );
    checks.push(
      ok(
        `DUP-${tool}`,
        tool,
        "a tool may list one package once per lockfile (real output does); the adapter folds repeats into one record with all its paths",
        f.duplicateRawPurls === 0
          ? "no repeated purl"
          : `${f.duplicateRawPurls} repeated purl entr${f.duplicateRawPurls === 1 ? "y" : "ies"}, folded by the adapter (same purl in more than one lockfile)`,
      ),
    );
    checks.push(
      pick(
        parsed.candidates.length > 0 || f.libs === 0,
        `COUNT-${tool}`,
        tool,
        "package components produce records",
        `${f.libs} package components produce ${parsed.candidates.length} records`,
        `${f.libs} package components produce 0 records`,
        "breaks",
      ),
    );
  }

  // ---- planted repository configuration
  for (const tool of TOOLS) {
    const planted = runs.get(`${tool}-planted`);
    const sealed = runs.get(`${tool}-sealed`);
    const label =
      "planted repository configuration (.syft.yaml, trivy.yaml, .trivyignore) does not change the result";
    if (!planted || !sealed || !docs[tool]) {
      checks.push(unknown(`CFG-repo-${tool}`, tool, label, "no planted run or no clean document"));
      continue;
    }
    const outP = read(planted.id, "stdout");
    let factsP = null;
    if (outP !== null && planted.exitCode === 0) {
      try {
        factsP = analyzeDocument(outP, tool).facts;
      } catch {
        factsP = null;
      }
    }
    if (factsP === null) {
      checks.push(
        bad(
          `CFG-repo-${tool}`,
          tool,
          label,
          `planted run exit ${planted.exitCode}, no usable document: repository configuration changed the behaviour`,
          "breaks",
        ),
      );
      continue;
    }
    const a = docs[tool].purls
      .map((p) => p.canonical)
      .sort()
      .join("\n");
    const b = factsP.purls
      .map((p) => p.canonical)
      .sort()
      .join("\n");
    checks.push(
      pick(
        a === b,
        `CFG-repo-${tool}`,
        tool,
        label,
        `${docs[tool].purls.length} purls in both runs`,
        `clean ${docs[tool].purls.length} purls, planted ${factsP.purls.length} purls: the planted file changed the result`,
        "breaks",
      ),
    );
  }

  // ---- cross tool
  const crossLabel = "both tools normalize the same package to the same canonical purl";
  if (!docs.syft || !docs.trivy) {
    checks.push(unknown("PURL-cross", "both", crossLabel, "one of the tools has no document"));
    checks.push(
      unknown(
        "ENS-merge",
        "both",
        "two tools agreeing merge into one finding with two provenance entries",
        "one of the tools has no document",
      ),
    );
  } else {
    const key = (p) => {
      const ns = (p.namespace ?? "").toLowerCase();
      const name = (p.name ?? "").toLowerCase().replace(/[-_.]+/g, "-");
      const ver = (p.version ?? "").toLowerCase().replace(/^v(?=\d)/, "");
      return `${p.type}|${ns}|${name}|${ver}`;
    };
    const group = (f) => {
      const m = new Map();
      for (const p of f.purls)
        if (p.canonical !== null) m.set(key(p), [...(m.get(key(p)) ?? []), p]);
      return m;
    };
    const gs = group(docs.syft);
    const gt = group(docs.trivy);
    const disagreements = [];
    let shared = 0;
    const sharedRows = [];
    for (const [k, sp] of gs) {
      const tp = gt.get(k);
      if (!tp) continue;
      shared += 1;
      const sset = new Set(sp.map((p) => p.canonical));
      const tset = new Set(tp.map((p) => p.canonical));
      const same = sset.size === tset.size && [...sset].every((c) => tset.has(c));
      sharedRows.push({
        key: safeText(k, 120),
        syftRaw: safeText(sp[0].raw, 200),
        trivyRaw: safeText(tp[0].raw, 200),
        syftCanonical: safeText(sp[0].canonical, 200),
        trivyCanonical: safeText(tp[0].canonical, 200),
        agree: same,
        rawEqual: sp[0].raw === tp[0].raw,
      });
      if (!same) disagreements.push(sharedRows.at(-1));
    }
    observations.cross = {
      shared,
      onlySyft: [...gs.keys()].filter((k) => !gt.has(k)).length,
      onlyTrivy: [...gt.keys()].filter((k) => !gs.has(k)).length,
      disagreements: first(disagreements, MAX_TABLE_ROWS),
      onlySyftExamples: first(
        [...gs.keys()]
          .filter((k) => !gt.has(k))
          .map((k) => safeText(k, 100))
          .sort(),
      ),
      onlyTrivyExamples: first(
        [...gt.keys()]
          .filter((k) => !gs.has(k))
          .map((k) => safeText(k, 100))
          .sort(),
      ),
    };
    checks.push(
      shared === 0
        ? unknown(
            "PURL-cross",
            "both",
            crossLabel,
            "the tools share no package (different ecosystems or different catalogers)",
          )
        : disagreements.length === 0
          ? ok(
              "PURL-cross",
              "both",
              crossLabel,
              `${shared} shared packages, all agree after normalization`,
            )
          : bad(
              "PURL-cross",
              "both",
              crossLabel,
              `${disagreements.length} of ${shared} shared packages differ after normalization, e.g. ${disagreements[0].syftCanonical} vs ${disagreements[0].trivyCanonical}`,
              "degraded",
            ),
    );
    // OQ-5 ecosystems
    const eco = (id, label, match) => {
      const rows = sharedRows.filter((r) => match(r));
      if (rows.length === 0)
        return checks.push(unknown(id, "both", label, "no such package seen in both tools"));
      const dis = rows.filter((r) => !r.agree);
      const rawSame = rows.filter((r) => r.rawEqual).length;
      return checks.push(
        dis.length === 0
          ? ok(
              id,
              "both",
              label,
              `${rows.length} package(s) agree after normalization (${rawSame} already identical raw: the rule is ${rawSame === rows.length ? "not needed for this data" : "doing work"})`,
            )
          : bad(
              id,
              "both",
              label,
              `${dis.length} of ${rows.length} disagree, e.g. ${dis[0].syftRaw} vs ${dis[0].trivyRaw}`,
              "degraded",
            ),
      );
    };
    eco("OQ5-pypi", "OQ-5 PyPI: case, '_' and '.' map to '-' so the tools agree", (r) =>
      r.key.startsWith("pypi|"),
    );
    eco(
      "OQ5-golang",
      "OQ-5 Go: lower-casing the module path and keeping the v prefix make the tools agree",
      (r) => r.key.startsWith("golang|"),
    );
    eco("OQ5-npm", "OQ-5 npm: scope and name lower case, %40 for @", (r) =>
      r.key.startsWith("npm|"),
    );
    eco("OQ5-maven", "OQ-5 Maven: group/artifact case kept", (r) => r.key.startsWith("maven|"));
    for (const t of ["deb", "rpm", "apk"])
      eco(`OQ5-${t}`, `OQ-5 ${t}: vendor namespace and distro qualifier agree`, (r) =>
        r.key.startsWith(`${t}|`),
      );
    // v-prefix: any purl whose version starts with v for a type that strips it, or Go keeping it
    const vSeen = [...docs.syft.purls, ...docs.trivy.purls].filter(
      (p) => /^v\d/.test(p.version ?? "") || /@v\d/.test(p.raw),
    );
    observations.notes.push(`purls with a v-prefixed version (raw or canonical): ${vSeen.length}`);
    // merge
    const total = (candidatesByTool.syft?.length ?? 0) + (candidatesByTool.trivy?.length ?? 0);
    if (total > MAX_MERGE_CANDIDATES) {
      checks.push(
        unknown(
          "ENS-merge",
          "both",
          "two tools agreeing merge into one finding with two provenance entries",
          `${total} candidates exceed the offline merge cap of ${MAX_MERGE_CANDIDATES} (the merger itself is slow at this size: measure it in ENG-L10)`,
        ),
      );
      return finish();
    }
    const m = mergeTaskCandidates({
      taskRef: "00000000-0000-4000-8000-000000000000",
      scanType: "sbom",
      candidates: [...(candidatesByTool.syft ?? []), ...(candidatesByTool.trivy ?? [])],
    });
    const both = m.findings.filter((x) => x.provenance.length >= 2).length;
    observations.merge = {
      findings: m.findings.length,
      agreed: both,
      singleTool: m.findings.length - both,
    };
    checks.push(
      both > 0
        ? ok(
            "ENS-merge",
            "both",
            "two tools agreeing merge into one finding with two provenance entries",
            `${m.findings.length} findings, ${both} confirmed by both tools, ${m.findings.length - both} by one`,
          )
        : bad(
            "ENS-merge",
            "both",
            "two tools agreeing merge into one finding with two provenance entries",
            `${m.findings.length} findings and none confirmed by both tools (the merge key never matches across tools)`,
            "degraded",
          ),
    );
  }

  return finish();

  function finish() {
    // ---- purl table (before / after) for the owner
    const purlTable = [];
    for (const tool of TOOLS)
      for (const p of docs[tool]?.purls ?? []) {
        if (purlTable.length >= MAX_TABLE_ROWS) break;
        if (p.tags.length > 0)
          purlTable.push({
            tool,
            before: safeText(p.raw, 220),
            after: p.canonical === null ? null : safeText(p.canonical, 220),
            changes: p.tags,
          });
      }
    const summary = { pass: 0, mismatch: 0, unknown: 0 };
    for (const c of checks) summary[c.status.toLowerCase()] += 1;
    return {
      reportVersion: REPORT_VERSION,
      verdict: summary.mismatch > 0 ? "MISMATCH" : summary.unknown > 0 ? "UNKNOWN" : "PASS",
      summary,
      assumptions: ASSUMPTIONS.map((a) => ({ id: a.id, text: a.text })),
      checks,
      purlTable,
      observations,
    };
  }
}

/** Human-readable table of a report. */
export function renderTable(report) {
  const lines = [];
  const w = (s, n) => (s.length >= n ? s : s + " ".repeat(n - s.length));
  lines.push(
    `ENG-L20 comparison: ${report.verdict}  (PASS ${report.summary.pass}, MISMATCH ${report.summary.mismatch}, UNKNOWN ${report.summary.unknown})`,
  );
  lines.push("");
  lines.push(`${w("STATUS", 9)}${w("CHECK", 24)}${w("TOOL", 7)}ASSUMPTION  =>  OBSERVED`);
  for (const c of report.checks)
    lines.push(
      `${w(c.status, 9)}${w(c.id, 24)}${w(c.tool, 7)}${safeText(c.assumption, 150)}  =>  ${safeText(c.observed, 400)}${c.impact ? `  [impact: ${c.impact}]` : ""}`,
    );
  lines.push("");
  lines.push(`purl normalization (changed purls only, ${report.purlTable.length} row(s)):`);
  for (const r of report.purlTable)
    lines.push(
      `  ${w(r.tool, 6)}${r.before}  ->  ${r.after ?? "(unparseable)"}  [${r.changes.join(",")}]`,
    );
  return `${lines.join("\n")}\n`;
}
