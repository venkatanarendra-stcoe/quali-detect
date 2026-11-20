/**
 * Data-licence source policy of the vulnerability DB mirror (docs/modules/scan-engines/SPEC.md 5.12.1, SE-45, SE-46, SE-47, D-15,
 * D-21; legal sign-off still REQUIRED before production, OQ-26). Pure functions, a closed allowlist and a quarantine; nothing is
 * downloaded or executed here.
 *
 * Allowed in v1 (language ecosystems npm, PyPI, Go, Maven ONLY): GHSA (CC-BY-4.0, attribution mandatory), NVD (public domain), OSV
 * core records. Everything else is refused: Chainguard/Wolfi and any non-commercial-licensed record are QUARANTINED, the Grype DB is
 * never fetched (D-21), distro and OS-package data is out of scope. The record-level check is the second layer behind the source
 * allowlist of the downloader; it can only be applied to snapshots whose content is JSON records (opaque database files such as the
 * Trivy bbolt file are covered by the declared source list and by ENG-L19 in the live test, NOT by this function).
 */

/** Sources whose records may be stored (SE-45). */
export const ALLOWED_SOURCES = Object.freeze({
  ghsa: Object.freeze({
    id: "ghsa",
    licence: "CC-BY-4.0",
    attributionRequired: true,
    attribution: "ghsa-cc-by-4.0",
  }),
  nvd: Object.freeze({
    id: "nvd",
    licence: "public-domain",
    attributionRequired: false,
    attribution: null,
  }),
  osv: Object.freeze({
    id: "osv",
    licence: "osv-core",
    attributionRequired: false,
    attribution: null,
  }),
});

/** Sources that must never be downloaded, stored, mounted or shown until legal clears them (SE-46, D-21). */
export const QUARANTINED_SOURCES = Object.freeze([
  "grype-db",
  "chainguard",
  "wolfi",
  "trivy-os",
  "distro",
]);

/** The only ecosystems scanned in v1 (D-15); OSV spells them exactly like this. */
export const ALLOWED_ECOSYSTEMS = Object.freeze(["npm", "PyPI", "Go", "Maven"]);

/** Identifier prefixes of allowed records, by source. OSV core covers the language databases of osv.dev. */
const ID_SOURCES = Object.freeze([
  [/^GHSA-/, "ghsa"],
  [/^CVE-/, "nvd"],
  [/^(PYSEC|GO|OSV)-/, "osv"],
]);

/** Markers of data that is quarantined wherever they appear in an identifier, ecosystem or source field. */
const QUARANTINE_MARKER = /chainguard|wolfi|\bcgr\.dev\b|^CGA-/i;
/** A licence field that names a non-commercial term. */
const NON_COMMERCIAL_MARKER = /(?:^|[^a-z])nc(?:[^a-z]|$)|non[-\s]?commercial/i;

/** The longest string of an inspected field. A longer one is `invalid` (never cut: a marker after the cut would escape the scan). */
export const MAX_STRING_SCAN = 4096;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** @param {unknown} v */
const short = (v) => (typeof v === "string" ? v : "");

/**
 * @typedef {{ allowed: boolean, source: "ghsa" | "nvd" | "osv" | null, quarantined: boolean, reason: "ok" | "invalid" | "quarantined" | "not_allowed" }} RecordVerdict
 */

/**
 * Classifies ONE OSV-style record (SE-46 record-level check). Never throws; a value that is not a plain object, has no readable
 * identifier or lists no allowlisted ecosystem is refused. `quarantined: true` takes precedence over `not_allowed`.
 * @param {unknown} record
 * @returns {RecordVerdict}
 */
export function classifyRecord(record) {
  if (!isObject(record))
    return { allowed: false, source: null, quarantined: false, reason: "invalid" };
  const id = short(record.id);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,119}$/.test(id))
    return { allowed: false, source: null, quarantined: false, reason: "invalid" };
  const aliases = Array.isArray(record.aliases) ? record.aliases.slice(0, 50).map(short) : [];
  const affected = Array.isArray(record.affected) ? record.affected.slice(0, 200) : [];
  const ecosystems = affected.map((a) => short(a?.package?.ecosystem));
  const dbSpecific = isObject(record.database_specific) ? record.database_specific : {};
  const sourceText = [short(dbSpecific.source), short(dbSpecific.sources), short(record.source)];
  const licenceText = [short(dbSpecific.license), short(dbSpecific.licence), short(record.license)];
  if (
    [...aliases, ...ecosystems, ...sourceText, ...licenceText].some(
      (t) => t.length > MAX_STRING_SCAN,
    )
  )
    return { allowed: false, source: null, quarantined: false, reason: "invalid" };

  const quarantined =
    [id, ...aliases, ...ecosystems, ...sourceText].some((s) => QUARANTINE_MARKER.test(s)) ||
    licenceText.some((s) => s !== "" && NON_COMMERCIAL_MARKER.test(s));
  if (quarantined)
    return { allowed: false, source: null, quarantined: true, reason: "quarantined" };

  const source = ID_SOURCES.find(([pattern]) => pattern.test(id))?.[1] ?? null;
  if (source === null)
    return { allowed: false, source: null, quarantined: false, reason: "not_allowed" };
  // every listed ecosystem must be allowlisted; a NVD record may list none, any other source must list at least one
  if (ecosystems.some((e) => !ALLOWED_ECOSYSTEMS.includes(e)))
    return { allowed: false, source, quarantined: false, reason: "not_allowed" };
  if (ecosystems.length === 0 && source !== "nvd")
    return { allowed: false, source, quarantined: false, reason: "not_allowed" };
  return { allowed: true, source, quarantined: false, reason: "ok" };
}

/**
 * Checks the source list a downloader or a snapshot manifest DECLARES (SE-45, SE-46): every entry must be an allowlisted id; a
 * quarantined id is reported separately. An empty list is refused (a snapshot of unknown origin is not promoted).
 * @param {unknown} declared
 * @returns {{ ok: boolean, quarantined: string[], notAllowed: number, sources: Array<{ id: string, licence: string, attributionRequired: boolean, attribution: string | null }> }}
 */
export function checkDeclaredSources(declared) {
  const list = Array.isArray(declared) ? declared.slice(0, 50) : [];
  const quarantined = [];
  let notAllowed = list.length === 0 ? 1 : 0;
  const sources = [];
  for (const entry of list) {
    const id = typeof entry === "string" ? entry.toLowerCase().slice(0, 64) : "";
    if (Object.hasOwn(ALLOWED_SOURCES, id)) {
      if (!sources.some((s) => s.id === id)) sources.push({ ...ALLOWED_SOURCES[id] });
    } else if (QUARANTINED_SOURCES.includes(id) || QUARANTINE_MARKER.test(id)) {
      quarantined.push(QUARANTINED_SOURCES.includes(id) ? id : "quarantined");
    } else notAllowed += 1;
  }
  return { ok: quarantined.length === 0 && notAllowed === 0, quarantined, notAllowed, sources };
}
