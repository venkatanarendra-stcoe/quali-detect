/**
 * Merge keys of the four scan types (docs/modules/scan-engines/SPEC.md 5.6, owner decision D-5, as MERGE keys and NOT finding
 * identity, D-9, ER-26, ADR-004). A `dedupKey` is a deterministic string used only to fold candidates INSIDE one task; the Findings
 * module computes identity per pipeline. Pure functions, no state. Purl normalization rules are the SPEC's Recommended rules
 * and are marked "verify against the purl specification" there (OQ-5): they are a table here so they can be corrected in one place.
 */

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
/** Qualifiers kept in a canonical purl (SPEC 5.6.1); every other qualifier is dropped. */
export const KEPT_PURL_QUALIFIERS = Object.freeze(["arch", "classifier", "distro", "type"]);
/** Purl types whose registry never uses a leading `v` in a version (SPEC 5.6.1; verify). Never `golang`. */
const V_STRIPPED_TYPES = new Set(["npm", "pypi"]);

const decode = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
};
const encode = (s) => encodeURIComponent(s).replace(/%3A/gi, ":");

/**
 * Parses and canonicalizes a package URL. Returns null for anything over 500 characters, with a control character, without
 * `pkg:type/name`, or with an undecodable segment.
 * @param {unknown} input
 * @returns {{ type: string, namespace: string | null, name: string, version: string | null, qualifiers: Record<string, string>, canonical: string, unversioned: string } | null}
 */
export function canonicalPurl(input) {
  if (typeof input !== "string" || input.length === 0 || input.length > 500 || CONTROL.test(input))
    return null;
  if (!input.startsWith("pkg:")) return null;
  let rest = input.slice(4).replace(/^\/+/, "");
  const hash = rest.indexOf("#");
  if (hash !== -1) rest = rest.slice(0, hash); // the subpath is dropped
  let qualifierText = "";
  const q = rest.indexOf("?");
  if (q !== -1) {
    qualifierText = rest.slice(q + 1);
    rest = rest.slice(0, q);
  }
  const slash = rest.indexOf("/");
  if (slash <= 0) return null;
  const type = rest.slice(0, slash).toLowerCase();
  if (!/^[a-z][a-z0-9.+-]*$/.test(type)) return null;
  let path = rest.slice(slash + 1);
  let versionRaw = null;
  const at = path.lastIndexOf("@");
  if (at > path.lastIndexOf("/")) {
    versionRaw = path.slice(at + 1);
    path = path.slice(0, at);
  }
  const segments = path.split("/").filter((s) => s !== "");
  if (segments.length === 0) return null;
  const decoded = segments.map(decode);
  if (decoded.some((s) => s === null || s === "" || CONTROL.test(s))) return null;
  let name = /** @type {string} */ (decoded[decoded.length - 1]);
  let namespace =
    decoded.length > 1 ? /** @type {string[]} */ (decoded.slice(0, -1)).join("/") : null;
  if (type === "npm") {
    name = name.toLowerCase();
    namespace = namespace === null ? null : namespace.toLowerCase();
  } else if (type === "pypi") name = name.toLowerCase().replace(/[_.]/g, "-");
  else if (type === "golang") {
    name = name.toLowerCase();
    namespace = namespace === null ? null : namespace.toLowerCase();
  }
  let version = null;
  if (versionRaw !== null) {
    const v = decode(versionRaw);
    if (v === null || CONTROL.test(v)) return null;
    version = v.trim();
    if (version !== "" && V_STRIPPED_TYPES.has(type) && /^v\d/.test(version))
      version = version.slice(1);
    if (version === "") version = null;
  }
  /** @type {Record<string, string>} */
  const qualifiers = {};
  for (const pair of qualifierText.split("&")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const key = pair.slice(0, eq).toLowerCase();
    const value = decode(pair.slice(eq + 1));
    if (value === null || CONTROL.test(value)) return null;
    if (KEPT_PURL_QUALIFIERS.includes(key) && value !== "") qualifiers[key] = value;
  }
  const qs = Object.keys(qualifiers)
    .sort()
    .map((k) => `${k}=${encode(qualifiers[k])}`)
    .join("&");
  const base = `pkg:${type}/${namespace === null ? "" : `${namespace.split("/").map(encode).join("/")}/`}${encode(name)}`;
  const unversioned = qs ? `${base}?${qs}` : base;
  const canonical = `${base}${version === null ? "" : `@${encode(version)}`}${qs ? `?${qs}` : ""}`;
  return { type, namespace, name, version, qualifiers, canonical, unversioned };
}

/** Path as used inside a MERGE key: POSIX separators, no leading `./`, NFC. The finding keeps the exact path. */
export function normalizePathForKey(path) {
  return String(path)
    .replaceAll("\\", "/")
    .replace(/^(\.\/)+/, "")
    .normalize("NFC");
}

const ECOSYSTEM_PREFIXES = new Set(["GO", "PYSEC", "RUSTSEC"]);
const ID_OK = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,59}$/;

/**
 * Normalizes an advisory id: the family prefix upper case (`CVE-`, `GHSA-`, `GO-`, `PYSEC-`, `RUSTSEC-`, `OSV-`); a CVE id all
 * upper case; a GHSA body lower case (the form GitHub publishes); vendor ids kept as given. Returns null for an unusable id.
 * @param {unknown} id @returns {{ id: string, family: string } | null}
 */
export function normalizeAdvisoryId(id) {
  if (typeof id !== "string") return null;
  const trimmed = id.trim();
  if (!ID_OK.test(trimmed)) return null;
  const m = /^([A-Za-z]+)-(.+)$/.exec(trimmed);
  const prefix = m ? m[1].toUpperCase() : "";
  if (prefix === "CVE") return { id: trimmed.toUpperCase(), family: "CVE" };
  if (prefix === "GHSA")
    return { id: `GHSA-${/** @type {RegExpExecArray} */ (m)[2].toLowerCase()}`, family: "GHSA" };
  if (ECOSYSTEM_PREFIXES.has(prefix) || prefix === "OSV")
    return {
      id: `${prefix}-${/** @type {RegExpExecArray} */ (m)[2].toUpperCase()}`,
      family: prefix,
    };
  return { id: trimmed, family: "OTHER" };
}
const priorityOf = (family) =>
  family === "CVE"
    ? 0
    : family === "GHSA"
      ? 1
      : ECOSYSTEM_PREFIXES.has(family)
        ? 2
        : family === "OSV"
          ? 3
          : 4;

/** The canonical advisory id of an alias set: CVE, then GHSA, then an ecosystem id, then OSV, then other; ties by id. @param {{ id: string, family: string }[]} list */
export function canonicalAdvisory(list) {
  return (
    [...list].sort(
      (a, b) =>
        priorityOf(a.family) - priorityOf(b.family) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    )[0] ?? null
  );
}

/**
 * Curated equivalence table of CWE siblings (SPEC 5.6.3, Recommended starting set): the lowest member names the class. Single-CWE
 * classes of the SPEC list (deserialization 502, SSRF 918, open redirect 601) need no entry: a CWE outside every group is its own
 * class `CWE-<n>`, which is the same result.
 */
const CWE_GROUPS = Object.freeze([
  [77, 78, 88],
  [89, 564],
  [79, 80],
  [22, 23, 36],
  [259, 321, 798],
  [326, 327, 328],
  [330, 338],
]);
/**
 * `ruleClass` of a SAST candidate: the normalized CWE through the equivalence table, or `tool:<toolId>:<ruleId>` when it has none
 * (so it never merges across tools, no false merges).
 * @param {number[] | undefined} cwe @param {string} toolId @param {string} ruleId
 */
export function sastRuleClass(cwe, toolId, ruleId) {
  const first = [...(cwe ?? [])].sort((a, b) => a - b)[0];
  if (first === undefined) return `tool:${toolId}:${ruleId}`;
  const group = CWE_GROUPS.find((g) => g.includes(first));
  return `CWE-${group ? group[0] : first}`;
}

export const sbomKey = (canonical) => `sbom|${canonical}`;
export const scaKey = (canonical, advisoryId) => `sca|${canonical}|${advisoryId}`;
export const sastKey = (path, ruleClass, startLine) =>
  `sast|${normalizePathForKey(path)}|${ruleClass}|${startLine}`;
export const secretsKey = (path, startLine, typeClass) =>
  `secrets|${normalizePathForKey(path)}|${startLine}|${typeClass}`;
