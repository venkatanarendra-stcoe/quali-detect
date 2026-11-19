import {
  CONFIDENCE_RANK,
  ENSEMBLE_SCAN_TYPES,
  ENSEMBLE_TOOL_IDS,
  FINDING_LIMITS,
  GENERIC_SECRET_TYPE_CLASSES,
  SAST_LINE_TOLERANCE,
  SEVERITY_RANK,
  candidateSchema,
  findingSchema,
  highestSeverity,
  raiseConfidence,
} from "@qmentisai/shared";
import {
  canonicalAdvisory,
  canonicalPurl,
  normalizeAdvisoryId,
  normalizePathForKey,
  sastKey,
  sastRuleClass,
  scaKey,
  secretsKey,
} from "./merge-keys.js";

/**
 * The merger (docs/modules/scan-engines/SPEC.md 5.6, SE-10 to SE-15, ENG-S06): folds the candidates of ONE task attempt into
 * findings. It is a pure function with no module-level state, no clock, no randomness and no I/O; it takes no tenant, pipeline
 * or execution input beyond the task reference, and it REFUSES (throws) a candidate of another task or another scan type instead of
 * merging or dropping it. Within the task:
 * - cross-tool merging only: two candidates of the SAME tool are never merged (SE-12);
 * - scan types are never mixed (SE-15);
 * - the highest severity wins, `severityAssumed` stays true only when every candidate at that severity was assumed (D-5);
 * - one `provenance[]` entry per tool; confidence rises one step when two distinct tools agree (SE-13);
 * - output order is deterministic (SE-14).
 * A `dedupKey` is a MERGE key inside the task, never a finding identity (ADR-004, ER-26).
 */

export class MergeBoundaryError extends Error {
  /** @param {"task_mismatch" | "scan_type_mismatch" | "candidate_invalid" | "finding_invalid" | "input_invalid"} code */
  constructor(code, message) {
    super(message);
    this.name = "MergeBoundaryError";
    this.code = code;
  }
}

const toolIndex = (id) => ENSEMBLE_TOOL_IDS.indexOf(id);
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const toolOf = (c) => c.provenance[0].toolId;
const refOf = (c) => `${c.rawRef.toolRunId}:${String(c.rawRef.ordinal).padStart(10, "0")}`;
const lineOf = (c) => c.location?.startLine ?? 0;
const endOf = (c) => c.location?.endLine ?? c.location?.startLine ?? 0;
const pathOf = (c) => normalizePathForKey(c.location?.path ?? "");
const SCOPE_RANK = { prod: 3, dev: 2, optional: 1, peer: 1, unknown: 0 };

/** SE-14 order: dedupKey, tool, raw reference. */
const byKeyToolRef = (a, b) =>
  cmp(a.dedupKey, b.dedupKey) ||
  toolIndex(toolOf(a)) - toolIndex(toolOf(b)) ||
  cmp(refOf(a), refOf(b));
/** Line-bearing keys embed the line as decimal text: order numerically instead, then by tool and reference. */
const byLocation = (a, b) =>
  cmp(pathOf(a), pathOf(b)) ||
  cmp(
    a.mergeHints?.ruleClass ?? a.mergeHints?.typeClass ?? "",
    b.mergeHints?.ruleClass ?? b.mergeHints?.typeClass ?? "",
  ) ||
  lineOf(a) - lineOf(b) ||
  toolIndex(toolOf(a)) - toolIndex(toolOf(b)) ||
  cmp(refOf(a), refOf(b));

const bestOf = (members) =>
  [...members].sort(
    (a, b) =>
      CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence] ||
      toolIndex(toolOf(a)) - toolIndex(toolOf(b)) ||
      cmp(refOf(a), refOf(b)),
  )[0];

/** Greedy grouping: a candidate joins the first group that accepts it and holds no candidate of the same tool (SE-12). */
function greedy(sorted, accepts) {
  const groups = [];
  for (const c of sorted) {
    const tool = toolOf(c);
    const group = groups.find((g) => !g.tools.has(tool) && accepts(g, c));
    if (group) {
      group.members.push(c);
      group.tools.add(tool);
    } else groups.push({ first: c, members: [c], tools: new Set([tool]) });
  }
  return groups.map((g) => g.members);
}

const dirOf = (p) => (p && p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");

function groupSbom(candidates) {
  // a component with no version is redundant when a versioned one of the same (type, namespace, name) was found in the same directory
  const versioned = new Set();
  for (const c of candidates) {
    const parsed = canonicalPurl(c.component.purl);
    if (parsed?.version) versioned.add(`${parsed.unversioned}|${dirOf(c.location?.path)}`);
  }
  let redundant = 0;
  const kept = candidates.filter((c) => {
    const parsed = canonicalPurl(c.component.purl);
    if (
      parsed &&
      !parsed.version &&
      versioned.has(`${parsed.unversioned}|${dirOf(c.location?.path)}`)
    ) {
      redundant += 1;
      return false;
    }
    return true;
  });
  const key = (c) => canonicalPurl(c.component.purl)?.canonical ?? c.component.purl;
  const sorted = [...kept].sort(
    (a, b) =>
      cmp(key(a), key(b)) || toolIndex(toolOf(a)) - toolIndex(toolOf(b)) || cmp(refOf(a), refOf(b)),
  );
  return { groups: greedy(sorted, (g, c) => key(g.first) === key(c)), redundant };
}

const aliasesOf = (c) =>
  new Map(
    [
      c.rule.id,
      c.mergeHints?.primaryId,
      ...(c.mergeHints?.aliases ?? []),
      ...(c.advisories ?? []).map((a) => a.id),
    ]
      .map(normalizeAdvisoryId)
      .filter(Boolean)
      .map((a) => [a.id, a]),
  );

function groupSca(candidates) {
  const sorted = [...candidates].sort(byKeyToolRef);
  const parent = sorted.map((_, i) => i);
  const find = (i) => {
    let r = i;
    while (parent[r] !== r) r = parent[r];
    while (parent[i] !== r) [parent[i], i] = [r, parent[i]];
    return r;
  };
  const toolsOf = new Map(sorted.map((c, i) => [i, new Set([toolOf(c)])]));
  const aliasSets = sorted.map(aliasesOf);
  const compKey = sorted.map((c) => canonicalPurl(c.component.purl)?.canonical ?? c.component.purl);
  /** @type {Map<string, number[]>} */
  const byAlias = new Map();
  sorted.forEach((_, i) => {
    for (const id of aliasSets[i].keys()) {
      const k = `${compKey[i]}\u0000${id}`;
      byAlias.set(k, [...(byAlias.get(k) ?? []), i]);
    }
  });
  for (const members of byAlias.values()) {
    for (let j = 1; j < members.length; j += 1) {
      const a = find(members[0]);
      const b = find(members[j]);
      if (a === b) continue;
      const ta = /** @type {Set<string>} */ (toolsOf.get(a));
      const tb = /** @type {Set<string>} */ (toolsOf.get(b));
      // the guard: a union that would put two candidates of one tool into one finding is not performed (SE-12)
      if ([...tb].some((t) => ta.has(t))) continue;
      const [lo, hi] = a < b ? [a, b] : [b, a];
      parent[hi] = lo;
      toolsOf.set(lo, new Set([...ta, ...tb]));
    }
  }
  /** @type {Map<number, object[]>} */
  const groups = new Map();
  sorted.forEach((c, i) => {
    const r = find(i);
    groups.set(r, [...(groups.get(r) ?? []), c]);
  });
  return [...groups.values()];
}

const overlap = (a, b) => lineOf(a) <= endOf(b) && lineOf(b) <= endOf(a);
function groupSast(candidates) {
  const classOf = (c) => c.mergeHints?.ruleClass ?? sastRuleClass(c.cwe, toolOf(c), c.rule.id);
  const sorted = [...candidates]
    .map((c) => ({ ...c, mergeHints: { ...c.mergeHints, ruleClass: classOf(c) } }))
    .sort(byLocation);
  return greedy(
    sorted,
    // anchored at the FIRST member: no chaining of far lines
    (g, c) =>
      pathOf(g.first) === pathOf(c) &&
      g.first.mergeHints.ruleClass === c.mergeHints.ruleClass &&
      (overlap(g.first, c) ||
        (Boolean(g.first.mergeHints.blockId) &&
          g.first.mergeHints.blockId === c.mergeHints.blockId) ||
        Math.abs(lineOf(g.first) - lineOf(c)) <= SAST_LINE_TOLERANCE),
  );
}

const isGeneric = (t) => GENERIC_SECRET_TYPE_CLASSES.includes(t);
function groupSecrets(candidates) {
  const sorted = [...candidates].sort(byLocation);
  const groups = [];
  for (const c of sorted) {
    const tool = toolOf(c);
    const type = c.mergeHints?.typeClass ?? "other";
    const fp = c.mergeHints?.fingerprint;
    const group = groups.find((g) => {
      if (g.tools.has(tool) || pathOf(g.first) !== pathOf(c) || lineOf(g.first) !== lineOf(c))
        return false;
      const gType = g.type;
      const sameType = gType === type;
      const genericMeetsSpecific =
        (isGeneric(gType) && !isGeneric(type)) || (!isGeneric(gType) && isGeneric(type));
      if (!sameType && !genericMeetsSpecific) return false;
      // two secrets on one line with different fingerprints stay separate
      return !(fp && g.fingerprints.size > 0 && !g.fingerprints.has(fp));
    });
    if (group) {
      group.members.push(c);
      group.tools.add(tool);
      if (fp) group.fingerprints.add(fp);
      if (isGeneric(group.type) && !isGeneric(type)) group.type = type;
    } else
      groups.push({
        first: c,
        members: [c],
        tools: new Set([tool]),
        type,
        fingerprints: new Set(fp ? [fp] : []),
      });
  }
  return groups.map((g) => ({ members: g.members, type: g.type }));
}

const unionBy = (lists, keyFn) => {
  const seen = new Map();
  for (const item of lists.flat()) if (!seen.has(keyFn(item))) seen.set(keyFn(item), item);
  return [...seen.values()];
};

function buildFinding(scanType, members, extra = {}) {
  const base = bestOf(members);
  const tools = new Set(members.map(toolOf));
  const severity = highestSeverity(members.map((m) => m.severity));
  const severityAssumed = members
    .filter((m) => m.severity === severity)
    .every((m) => m.severityAssumed);
  const topConfidence = members.reduce(
    (best, m) => (CONFIDENCE_RANK[m.confidence] > CONFIDENCE_RANK[best] ? m.confidence : best),
    base.confidence,
  );
  const multi = tools.size > 1;
  const provenance = members
    .map((m) => m.provenance[0])
    .sort(
      (a, b) =>
        toolIndex(a.toolId) - toolIndex(b.toolId) ||
        cmp(a.ruleId ?? "", b.ruleId ?? "") ||
        cmp(
          `${a.rawRef.toolRunId}${String(a.rawRef.ordinal).padStart(10, "0")}`,
          `${b.rawRef.toolRunId}${String(b.rawRef.ordinal).padStart(10, "0")}`,
        ),
    )
    .slice(0, FINDING_LIMITS.provenanceEntries);
  const cwe = [...new Set(members.flatMap((m) => m.cwe ?? []))]
    .sort((a, b) => a - b)
    .slice(0, FINDING_LIMITS.cwe);
  const finding = {
    schemaVersion: 1,
    scanType,
    kind: base.kind,
    dedupKey: extra.dedupKey ?? base.dedupKey,
    title: base.title,
    severity,
    severityAssumed,
    confidence: multi ? raiseConfidence(topConfidence) : topConfidence,
    confidenceBasis: multi ? "multi_tool" : base.confidenceBasis,
    rule: extra.rule ?? base.rule,
    rawRef: base.rawRef,
    provenance,
  };
  if (cwe.length > 0) finding.cwe = cwe;
  const advisories = extra.advisories ?? base.advisories;
  if (advisories?.length) finding.advisories = advisories;
  const loc = extra.location ?? base.location;
  if (loc) finding.location = loc;
  if (base.component) finding.component = extra.component ?? base.component;
  if (extra.locations) {
    finding.locations = extra.locations.list;
    finding.locationCount = extra.locations.count;
  }
  if (extra.fix) finding.fix = extra.fix;
  for (const field of ["evidence", "scmRef", "url"]) {
    const found = [base, ...members].find((m) => m[field] !== null && m[field] !== undefined);
    if (found) finding[field] = found[field];
  }
  const scoped = [base, ...members].find((m) => m.scope);
  if (scoped)
    finding.scope = { kind: scoped.scope.kind, inScope: members.some((m) => m.scope?.inScope) };
  if (base.kind === "secret") {
    const withPreview = [base, ...members].find((m) => m.preview !== undefined);
    if (withPreview) finding.preview = withPreview.preview;
  }
  const parsed = findingSchema.safeParse(finding);
  if (!parsed.success)
    throw new MergeBoundaryError("finding_invalid", "A merged finding is not valid.");
  return parsed.data;
}

function finishSbom(members) {
  const strongest = members.reduce(
    (best, m) =>
      SCOPE_RANK[m.component.scope ?? "unknown"] > SCOPE_RANK[best]
        ? (m.component.scope ?? "unknown")
        : best,
    "unknown",
  );
  const all = unionBy(
    members.map((m) =>
      m.locations?.length ? m.locations : m.location?.path ? [{ path: m.location.path }] : [],
    ),
    (l) => `${l.path}:${l.startLine ?? ""}`,
  ).sort((a, b) => cmp(a.path, b.path) || (a.startLine ?? 0) - (b.startLine ?? 0));
  const count = Math.max(all.length, ...members.map((m) => m.locationCount ?? 0));
  const base = bestOf(members);
  const component = {
    ...base.component,
    ...(strongest === "unknown" && !base.component.scope ? {} : { scope: strongest }),
  };
  return { component, locations: { list: all.slice(0, FINDING_LIMITS.locations), count } };
}

function finishSca(members) {
  const aliases = unionBy(
    members.map((m) => [...aliasesOf(m).values()]),
    (a) => a.id,
  );
  const canonical = canonicalAdvisory(aliases);
  const base = bestOf(members);
  const purl = canonicalPurl(base.component.purl)?.canonical ?? base.component.purl;
  const ordered = [...aliases].sort((a, b) =>
    a.id === canonical.id
      ? -1
      : b.id === canonical.id
        ? 1
        : cmp(a.family, b.family) || cmp(a.id, b.id),
  );
  const fixed = [...new Set(members.flatMap((m) => m.fix?.fixedVersions ?? []))]
    .sort()
    .slice(0, FINDING_LIMITS.fixedVersions);
  return {
    dedupKey: scaKey(purl, canonical.id),
    rule: { ...base.rule, id: canonical.id },
    advisories: ordered.slice(0, FINDING_LIMITS.advisories),
    ...(fixed.length ? { fix: { fixedVersions: fixed } } : {}),
  };
}

function finishSast(members) {
  const base = bestOf(members);
  const start = Math.min(...members.map(lineOf));
  const end = Math.max(...members.map(endOf));
  const cls = members[0].mergeHints.ruleClass;
  const location = { ...base.location, startLine: start, ...(end > start ? { endLine: end } : {}) };
  if (end <= start) delete location.endLine;
  return { dedupKey: sastKey(base.location.path, cls, start), location };
}

/**
 * Merges the candidates of one task.
 * @param {{ taskRef: string, scanType: "sbom" | "sca" | "sast" | "secrets", candidates: unknown[] }} input
 * @returns {{ findings: object[], stats: { candidates: number, findings: number, merged: number, redundantComponents: number } }}
 * @throws {MergeBoundaryError} a candidate of another task or scan type, or an invalid candidate: never merged, never silently dropped
 */
export function mergeTaskCandidates({ taskRef, scanType, candidates }) {
  if (
    typeof taskRef !== "string" ||
    !ENSEMBLE_SCAN_TYPES.includes(scanType) ||
    !Array.isArray(candidates)
  )
    throw new MergeBoundaryError("input_invalid", "taskRef, scanType and candidates are required.");
  const valid = [];
  for (const raw of candidates) {
    const parsed = candidateSchema.safeParse(raw);
    if (!parsed.success)
      throw new MergeBoundaryError("candidate_invalid", "A candidate is not valid.");
    if (parsed.data.taskRef !== taskRef)
      throw new MergeBoundaryError("task_mismatch", "A candidate belongs to another task.");
    if (parsed.data.scanType !== scanType)
      throw new MergeBoundaryError(
        "scan_type_mismatch",
        "A candidate belongs to another scan type.",
      );
    valid.push(parsed.data);
  }
  let redundant = 0;
  /** @type {object[]} */
  let findings = [];
  if (scanType === "sbom") {
    const { groups, redundant: r } = groupSbom(valid);
    redundant = r;
    findings = groups.map((g) => buildFinding(scanType, g, finishSbom(g)));
  } else if (scanType === "sca")
    findings = groupSca(valid).map((g) => buildFinding(scanType, g, finishSca(g)));
  else if (scanType === "sast")
    findings = groupSast(valid).map((g) => buildFinding(scanType, g, finishSast(g)));
  else
    findings = groupSecrets(valid).map(({ members, type }) =>
      buildFinding(scanType, members, {
        dedupKey: secretsKey(members[0].location.path, lineOf(members[0]), type),
      }),
    );
  findings.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      cmp(
        normalizePathForKey(a.location?.path ?? ""),
        normalizePathForKey(b.location?.path ?? ""),
      ) ||
      (a.location?.startLine ?? 0) - (b.location?.startLine ?? 0) ||
      cmp(a.component?.purl ?? "", b.component?.purl ?? "") ||
      cmp(a.rule.id, b.rule.id) ||
      cmp(a.dedupKey, b.dedupKey),
  );
  return {
    findings: findings.map((f) => Object.freeze(f)),
    stats: {
      candidates: valid.length,
      findings: findings.length,
      merged: valid.length - redundant - findings.length,
      redundantComponents: redundant,
    },
  };
}
