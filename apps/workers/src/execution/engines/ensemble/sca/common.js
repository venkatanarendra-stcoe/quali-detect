import { jsonbTextBytes, parseCvssVersion } from "@qmentisai/shared";
import { z } from "zod";
import {
  canonicalAdvisory,
  canonicalPurl,
  normalizeAdvisoryId,
  scaKey,
} from "../core/merge-keys.js";
import { scrubDeep } from "../core/scrub.js";

/**
 * Pieces shared by the two SCA adapters (docs/modules/scan-engines/SPEC.md 5.6.2, 5.7, 7.2, part G). Pure.
 */

/** Findings an SCA tool may report in one run (the framework cuts a larger output to `partial` / `output_too_large`). */
export const SCA_MAX_RECORDS = 50_000;
/** Fixed versions kept per record (the finding schema keeps at most 10). */
export const SCA_MAX_FIXED = 10;
/** The advisory sources whose CVSS data the platform keeps (SPEC 5.12.1: GHSA and NVD; never a distribution vendor's rating). */
export const CVSS_SOURCES = Object.freeze(["ghsa", "nvd"]);

// eslint-disable-next-line no-control-regex -- refusing control characters in untrusted text is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
/** A bounded string without control characters (the framework scrubs what remains, `scrubDeep`). */
export const text = (max, min = 1) =>
  z
    .string()
    .min(min)
    .max(max)
    .refine((s) => !CONTROL.test(s), "control characters");
/** A bounded string that is clipped (not refused) when too long: titles of advisories are free text of the upstream database. */
export const clipped = (max) =>
  z
    .string()
    .max(100_000)
    .transform((s) => s.slice(0, max));

/** `CWE-94` or `94` to 94; anything else is not a CWE number. @param {unknown} value @returns {number | null} */
export function cweNumber(value) {
  const m = typeof value === "string" ? /^(?:CWE-)?(\d{1,6})$/i.exec(value.trim()) : null;
  const n = m ? Number(m[1]) : Number.NaN;
  return Number.isInteger(n) && n >= 1 && n <= 100000 ? n : null;
}

/**
 * The advisory ids of an untrusted list that can be normalized (a usable family prefix and body), at most `max` of them: an id that
 * cannot is skipped, never a reason to lose the finding it sits next to.
 * @param {unknown} list @param {number} max @returns {string[]}
 */
export const usableAdvisoryIds = (list, max) =>
  (Array.isArray(list) ? list : [])
    .filter((x) => typeof x === "string" && normalizeAdvisoryId(x) !== null)
    .slice(0, max);

/** @param {unknown[]} list @returns {number[]} sorted, unique, at most 10 */
export const cweList = (list) =>
  [...new Set((list ?? []).map(cweNumber).filter((n) => n !== null))]
    .sort((a, b) => a - b)
    .slice(0, 10);

/**
 * @param {unknown} vector a CVSS vector string
 * @returns {"3.0" | "3.1" | "4.0" | null} the version of a vector the platform stores (v2 and unknown are not kept)
 */
export function storedCvssVersion(vector) {
  const v = parseCvssVersion(vector);
  return v === "3.0" || v === "3.1" || v === "4.0" ? v : null;
}

/** The size budget of the CVSS list inside one provenance entry (the whole entry is capped at 600 bytes). */
const CVSS_BUDGET_BYTES = 300;

/**
 * The CVSS entries kept in a provenance entry (SPEC 5.6.2: every score and vector per tool): unique by (version, vector), v3.x before
 * v4.0, at most two, shrunk until they fit the byte budget.
 * @param {{ version: string, vector: string, score?: number }[]} list
 */
export function cvssForProvenance(list) {
  const seen = new Set();
  const unique = [];
  for (const c of list) {
    const key = `${c.version}|${c.vector}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push({
      version: c.version,
      vector: c.vector,
      ...(typeof c.score === "number" ? { score: c.score } : {}),
    });
  }
  const ordered = unique.sort(
    (a, b) => (a.version === "4.0" ? 1 : 0) - (b.version === "4.0" ? 1 : 0),
  );
  const kept = ordered.slice(0, 2);
  while (kept.length > 0 && jsonbTextBytes(kept) > CVSS_BUDGET_BYTES) kept.pop();
  return kept;
}

/**
 * Normalizes and de-duplicates the advisory ids of one record.
 * @param {unknown[]} ids @returns {{ id: string, family: string }[]} at most 20, canonical first
 */
export function advisoryList(ids) {
  const byId = new Map();
  for (const raw of ids) {
    const n = normalizeAdvisoryId(raw);
    if (n && !byId.has(n.id)) byId.set(n.id, n);
  }
  const all = [...byId.values()];
  const canonical = canonicalAdvisory(all);
  return all
    .sort((a, b) =>
      a.id === canonical?.id
        ? -1
        : b.id === canonical?.id
          ? 1
          : a.family < b.family
            ? -1
            : a.family > b.family
              ? 1
              : a.id < b.id
                ? -1
                : 1,
    )
    .slice(0, 20);
}

/**
 * The common body of an SCA candidate (kind, keys, component, advisories, fix); the adapters add severity, confidence and provenance.
 * @param {{ purl: string, advisoryIds: unknown[], primaryId: string, title: string, path: string | undefined, fixed: string[], cwe: number[], scope?: string }} input
 * @returns {{ body: object, canonical: NonNullable<ReturnType<typeof canonicalPurl>> } | null} null when the record has no usable purl or advisory
 */
export function scaBody({ purl, advisoryIds, primaryId, title, path, fixed, cwe, scope }) {
  const parsed = canonicalPurl(purl);
  const advisories = advisoryList(advisoryIds);
  const canonicalId = canonicalAdvisory(advisories);
  if (!parsed || !parsed.version || advisories.length === 0 || !canonicalId) return null;
  const name = parsed.namespace ? `${parsed.namespace}/${parsed.name}` : parsed.name;
  const fixedVersions = [
    ...new Set(fixed.map((v) => v.trim()).filter((v) => v !== "" && v.length <= 100)),
  ].slice(0, SCA_MAX_FIXED);
  const primary = normalizeAdvisoryId(primaryId)?.id ?? canonicalId.id;
  return {
    canonical: parsed,
    body: {
      kind: "vulnerability",
      dedupKey: scaKey(parsed.canonical, canonicalId.id),
      // cleaned and redacted FIRST, then clipped: the framework scrubs the candidate again (idempotent), so the length that was clipped is the final one
      title: scrubDeep(title || `${canonicalId.id} in ${name}`, []).slice(0, 200),
      rule: { id: canonicalId.id },
      ...(cwe.length > 0 ? { cwe } : {}),
      advisories,
      ...(path ? { location: { path } } : {}),
      component: {
        purl: parsed.canonical,
        name: name.slice(0, 200),
        version: parsed.version.slice(0, 100),
        ecosystem: parsed.type,
        scope: scope ?? "unknown",
      },
      ...(fixedVersions.length > 0 ? { fix: { fixedVersions } } : {}),
      mergeHints: {
        primaryId: primary,
        aliases: advisories.map((a) => a.id).slice(0, 40),
      },
    },
  };
}
