import { FINGERPRINT_DOMAIN, FINGERPRINT_VERSION } from "./constants.js";
import {
  focusLines,
  hasCredentialShape,
  normalizeContentLines,
  normalizePath,
  purlWithoutVersion,
} from "./normalize.js";
import { sha256Hex } from "./sha256.js";

/**
 * Finding identity (docs/modules/findings/SPEC.md 5.2; owner decision 2026-11-23: pipeline + rule or CVE or CWE + path (no line
 * numbers) + content hash, no fuzzy matching, a rename is "fixed plus new"). Pure functions; the pipeline id always comes from the
 * verified execution row, never from a message (ID-2).
 *
 * @typedef {object} ObservedItem one stored finding of a result, as the ingestion reads it (a join of `scan_result_items` and
 *   `scan_result_item_details`). NEVER carries a secret value; `preview` and `valueLength` are accepted on input and IGNORED.
 * @property {number} [ordinal] item ordinal inside its result (tie-break of `occ`)
 * @property {"sca" | "sast" | "secrets"} scanType
 * @property {string} ruleId
 * @property {string} [ruleName]
 * @property {string} [title]
 * @property {string} severity
 * @property {string} [confidence]
 * @property {boolean} [severityAssumed]
 * @property {number[]} [cwe]
 * @property {Array<{ id: string, family?: string }>} [advisories]
 * @property {{ purl: string, name: string, version?: string, ecosystem: string }} [component]
 * @property {{ path?: string, startLine?: number, endLine?: number }} [location]
 * @property {{ fixedVersions?: string[] }} [fix]
 * @property {{ kind?: string, language?: string, nodeKind?: string, startLine?: number, endLine?: number, focusStart?: number, focusEnd?: number, snippet?: string, truncated?: boolean } | null} [evidence]
 * @property {unknown} [scmRef]
 * @property {string | null} [url]
 * @property {string[]} [toolIds]
 * @property {string} [typeClass] secrets only: the type class of the masked marker (derived from the marker when absent)
 */

const FAMILY_RANK = { cve: 0, ghsa: 1, osv: 2 };
const familyRank = (family) => FAMILY_RANK[String(family ?? "").toLowerCase()] ?? 3;

/**
 * The canonical advisory id of an SCA item: the first advisory ordered by family (CVE, GHSA, OSV, other) then id; `rule.id` when none.
 * @param {ObservedItem} item
 * @returns {string}
 */
export function canonicalAdvisoryId(item) {
  const list = (item.advisories ?? []).filter((a) => a && typeof a.id === "string" && a.id.trim());
  if (list.length === 0) return String(item.ruleId ?? "").trim();
  return [...list]
    .sort(
      (a, b) =>
        familyRank(a.family) - familyRank(b.family) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    )[0]
    .id.trim();
}

/** The type class of a masked secret line (`[REDACTED:<class>]`), or `other`. @param {string | null} line */
const typeClassOf = (line) => /\[REDACTED:([a-z_]{1,40})\]/.exec(line ?? "")?.[1] ?? "other";

/**
 * The raw identity components of an item (everything except the pipeline id and the occurrence ordinal).
 * @param {ObservedItem} item
 * @returns {{ ok: true, inputs: { scanType: string, ruleKey: string, locationKey: string, contentKey: string }, anchorKind: string }
 *   | { ok: false, reason: "skipped_bad_path" | "skipped_invalid" }}
 */
export function buildFingerprintInputs(item) {
  const scanType = item?.scanType;
  if (scanType !== "sca" && scanType !== "sast" && scanType !== "secrets")
    return { ok: false, reason: "skipped_invalid" };
  const path = normalizePath(item.location?.path);
  if (path === null) return { ok: false, reason: "skipped_bad_path" };
  const rule = String(item.ruleId ?? "").trim();
  if (rule.length === 0) return { ok: false, reason: "skipped_invalid" };

  if (scanType === "sca") {
    const purl = purlWithoutVersion(item.component?.purl ?? "");
    if (purl === null) return { ok: false, reason: "skipped_invalid" };
    return {
      ok: true,
      inputs: {
        scanType,
        ruleKey: canonicalAdvisoryId(item),
        locationKey: `${purl}@${path}`,
        contentKey: "",
      },
      anchorKind: "component",
    };
  }

  if (scanType === "sast") {
    const ruleKey = rule.toLowerCase();
    const lines = focusLines(item.evidence ?? null);
    const normalized = lines ? normalizeContentLines(lines.join("\n")) : [];
    if (normalized.length > 0)
      return {
        ok: true,
        inputs: {
          scanType,
          ruleKey,
          locationKey: path,
          contentKey: sha256Hex(normalized.join("\n")),
        },
        anchorKind: "focus_text",
      };
    const startLine = Number.isInteger(item.location?.startLine) ? item.location?.startLine : 0;
    return {
      ok: true,
      inputs: { scanType, ruleKey, locationKey: path, contentKey: `L${startLine}` },
      anchorKind: "line",
    };
  }

  // secrets: ONLY the platform-masked line may enter the identity, and only when it carries the mask marker
  const lines = focusLines(item.evidence ?? null);
  const raw = lines && lines.length > 0 ? lines[0] : null;
  const masked =
    raw !== null && raw.includes("[REDACTED") && !hasCredentialShape(raw)
      ? (normalizeContentLines(raw)[0] ?? null)
      : null;
  const typeClass =
    item.typeClass && /^[a-z_]{1,40}$/.test(item.typeClass) ? item.typeClass : typeClassOf(masked);
  const ruleKey = `${rule.toLowerCase()}#${typeClass}`;
  return masked
    ? {
        ok: true,
        inputs: { scanType, ruleKey, locationKey: path, contentKey: sha256Hex(masked) },
        anchorKind: "masked_line",
      }
    : {
        ok: true,
        inputs: { scanType, ruleKey, locationKey: path, contentKey: "" },
        anchorKind: "ordinal",
      };
}

/** NFC and NUL-join (a component can never forge another because no component holds NUL). @param {string[]} parts */
const joinParts = (parts) =>
  parts.map((p) => String(p).normalize("NFC").replaceAll("\u0000", "")).join("\u0000");

/**
 * The digest of all components but the ordinal (the grouping key of the `occ` tie-break, SPEC 5.2.4).
 * @param {string} pipelineId
 * @param {{ scanType: string, ruleKey: string, locationKey: string, contentKey: string }} inputs
 */
export const fingerprintBaseDigest = (pipelineId, inputs) =>
  sha256Hex(
    joinParts([
      FINGERPRINT_DOMAIN,
      pipelineId,
      inputs.scanType,
      inputs.ruleKey,
      inputs.locationKey,
      inputs.contentKey,
    ]),
  );

/**
 * `fp1:` + SHA-256 over the NUL-joined components and the ordinal (SPEC 5.2).
 * @param {string} pipelineId
 * @param {{ scanType: string, ruleKey: string, locationKey: string, contentKey: string }} inputs
 * @param {number} [occ] decimal ordinal of identical items of one result (default 0)
 */
export const fingerprintFromInputs = (pipelineId, inputs, occ = 0) =>
  `fp${FINGERPRINT_VERSION}:${sha256Hex(
    joinParts([
      FINGERPRINT_DOMAIN,
      pipelineId,
      inputs.scanType,
      inputs.ruleKey,
      inputs.locationKey,
      inputs.contentKey,
      String(occ),
    ]),
  )}`;

/**
 * The fingerprint of one item in one pipeline (SPEC 5.2, ID-2). NEVER computed from a client or a message: `pipelineId` is the
 * verified execution's pipeline.
 * @param {ObservedItem} item
 * @param {string} pipelineId
 * @param {number} [occ]
 * @returns {{ ok: true, fingerprint: string, baseDigest: string, anchorKind: string }
 *   | { ok: false, reason: "skipped_bad_path" | "skipped_invalid" }}
 */
export function computeFingerprint(item, pipelineId, occ = 0) {
  const built = buildFingerprintInputs(item);
  if (!built.ok) return built;
  return {
    ok: true,
    fingerprint: fingerprintFromInputs(pipelineId, built.inputs, occ),
    baseDigest: fingerprintBaseDigest(pipelineId, built.inputs),
    anchorKind: built.anchorKind,
  };
}

/**
 * The display-only correlation key (ID-4): SHA-256 over the identity inputs WITHOUT the pipeline id and WITH the tenant id, so equal
 * values exist only inside one tenant. Never a unique key, never used to copy state.
 * @param {ObservedItem} item
 * @param {string} tenantId
 * @returns {string | null} 64 hex, or null when the item has no identity
 */
export function computeCorrelationKey(item, tenantId) {
  const built = buildFingerprintInputs(item);
  if (!built.ok) return null;
  const i = built.inputs;
  return sha256Hex(
    joinParts(["qm.finding.corr.v1", tenantId, i.scanType, i.ruleKey, i.locationKey, i.contentKey]),
  );
}

/**
 * Assigns the `occ` ordinal to every identical item of one result (SPEC 5.2.4): items with the same base digest are ranked by
 * `(startLine, ordinal)` and numbered from 0.
 * @param {ObservedItem[]} items
 * @param {string} pipelineId
 * @returns {Array<{ item: ObservedItem, fingerprint: string, baseDigest: string, anchorKind: string, occ: number }>} valid items only
 * @property dropped counts by reason (on the returned array as `.dropped`)
 */
export function fingerprintItems(items, pipelineId) {
  /** @type {Map<string, Array<{ item: ObservedItem, base: string, anchorKind: string, inputs: any, order: [number, number] }>>} */
  const groups = new Map();
  const dropped = { skipped_bad_path: 0, skipped_invalid: 0 };
  items.forEach((item, index) => {
    const built = buildFingerprintInputs(item);
    if (!built.ok) {
      dropped[built.reason] += 1;
      return;
    }
    const base = fingerprintBaseDigest(pipelineId, built.inputs);
    const list = groups.get(base) ?? [];
    list.push({
      item,
      base,
      anchorKind: built.anchorKind,
      inputs: built.inputs,
      order: [item.location?.startLine ?? 0, item.ordinal ?? index],
    });
    groups.set(base, list);
  });
  const out = [];
  for (const list of groups.values()) {
    list.sort((a, b) => a.order[0] - b.order[0] || a.order[1] - b.order[1]);
    list.forEach((e, occ) =>
      out.push({
        item: e.item,
        fingerprint: fingerprintFromInputs(pipelineId, e.inputs, occ),
        baseDigest: e.base,
        anchorKind: e.anchorKind,
        occ,
      }),
    );
  }
  return Object.assign(out, { dropped });
}
