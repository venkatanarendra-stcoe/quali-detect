import { FINDING_LIMITS, findingSchema, jsonbTextBytes } from "@qmentisai/shared";
import { findCredentials } from "@qmentisai/infra";
import { normalizeItems } from "../../../scan-handler.js";

/**
 * Projection of merged findings onto the storage rows (docs/modules/scan-engines/SPEC.md 7.1, 7.3): the list-friendly
 * `scan_result_items` row (unchanged shape, 4 KiB `data`) and its 1:1 `scan_result_item_details` row. The existing
 * {@link normalizeItems} stays the LAST gate before the database (control characters stripped, credential-shaped text redacted,
 * lengths capped, a secret item keeps at most 4 leading characters); an item it rejects drops its finding, so the detail rows
 * keep the SAME ordinals as the stored items. Pure; no I/O.
 */

/**
 * The size the database CHECK measures for a detail row: the key and url as text, every jsonb part as `jsonb::text` (so the
 * application and the database agree to the byte). At most {@link FINDING_LIMITS.detailRowBytes}.
 * @param {ReturnType<typeof findingToDetail>} d
 */
export function detailRowBytes(d) {
  return (
    Buffer.byteLength(d.dedupKey) +
    jsonbTextBytes(d.provenance) +
    jsonbTextBytes(d.advisories) +
    (d.evidence === null ? 0 : jsonbTextBytes(d.evidence)) +
    (d.scmRef === null ? 0 : jsonbTextBytes(d.scmRef)) +
    (d.url === null ? 0 : Buffer.byteLength(d.url)) +
    jsonbTextBytes(d.scope) +
    jsonbTextBytes(d.extra)
  );
}

/** @param {object} finding @returns {object} the item candidate for normalizeItems */
export function findingToItem(finding) {
  return {
    kind: finding.kind,
    ruleId: finding.rule.id,
    severity: finding.severity,
    title: finding.title,
    path: finding.location?.path ?? null,
    startLine: finding.location?.startLine ?? null,
    endLine: finding.location?.endLine ?? null,
    componentPurl: finding.component?.purl ?? null,
    componentVersion: finding.component?.version ?? null,
    data:
      finding.kind === "secret" && finding.preview !== undefined
        ? { preview: finding.preview }
        : {},
  };
}

/**
 * The detail row of a finding (without the keys of its item, which the repository adds). What the SPEC table has no column for
 * (component, locations, fix, rule name, value-length bucket, raw reference) goes to `extra`.
 * @param {object} finding
 */
export function findingToDetail(finding) {
  const extra = {};
  if (finding.component) extra.component = finding.component;
  if (finding.locations) extra.locations = finding.locations;
  if (finding.locationCount !== undefined) extra.locationCount = finding.locationCount;
  if (finding.fix) extra.fix = finding.fix;
  if (finding.rule.name) extra.ruleName = finding.rule.name;
  if (finding.valueLengthBucket) extra.valueLengthBucket = finding.valueLengthBucket;
  extra.ruleTool = finding.rule.tool;
  extra.rawRef = finding.rawRef;
  return {
    schemaVersion: finding.schemaVersion,
    dedupKey: finding.dedupKey,
    confidence: finding.confidence,
    confidenceBasis: finding.confidenceBasis,
    severityAssumed: finding.severityAssumed,
    provenance: finding.provenance,
    advisories: finding.advisories ?? [],
    cwe: finding.cwe ?? [],
    evidence: finding.evidence ?? null,
    scmRef: finding.scmRef ?? null,
    url: finding.url ?? null,
    scope: finding.scope ?? { kind: "full", inScope: true },
    extra,
  };
}

/**
 * @param {unknown[]} findings merged findings (re-validated here: the storage boundary trusts nothing)
 * @param {number} cap the most items a result may hold (`maxResultItemsPerTask`)
 * @returns {{ items: object[], details: object[], truncated: boolean, dropped: number, severityCounts: Record<string, number> }}
 */
export function toStorageRows(findings, cap) {
  const items = [];
  const details = [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let dropped = 0;
  let truncated = false;
  for (const raw of findings) {
    const parsed = findingSchema.safeParse(raw);
    if (!parsed.success) {
      dropped += 1;
      continue;
    }
    if (items.length >= cap) {
      truncated = true;
      break;
    }
    const finding = parsed.data;
    const normalized = normalizeItems([findingToItem(finding)], 1);
    if (normalized.items.length !== 1) {
      dropped += 1;
      continue;
    }
    let detail = findingToDetail(finding);
    if (detailRowBytes(detail) > FINDING_LIMITS.detailRowBytes)
      detail = { ...detail, evidence: null };
    if (
      detailRowBytes(detail) > FINDING_LIMITS.detailRowBytes ||
      findCredentials(detail).length > 0
    ) {
      dropped += 1;
      continue;
    }
    items.push(normalized.items[0]);
    details.push(detail);
    severityCounts[finding.severity] += 1;
  }
  return { items, details, truncated, dropped, severityCounts };
}
