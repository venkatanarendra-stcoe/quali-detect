import {
  FINDING_LIMITS,
  detailExtraSchema,
  findingSchema,
  jsonbTextBytes,
} from "@qmentisai/shared";
import { findCredentials } from "@qmentisai/infra";
import { normalizeItems } from "../../../scan-handler.js";
import { scrubDeep } from "./scrub.js";
import { runSync, runYielding } from "./yield.js";

/**
 * Projection of merged findings onto the storage rows (docs/modules/scan-engines/SPEC.md 7.1, 7.3): the list-friendly
 * `scan_result_items` row (unchanged shape, 4 KiB `data`) and its 1:1 `scan_result_item_details` row. The existing
 * {@link normalizeItems} stays the LAST gate before the database (control characters stripped, credential-shaped text redacted,
 * lengths capped, a secret item keeps at most 4 leading characters); an item it rejects drops its finding, so the detail rows
 * keep the SAME ordinals as the stored items. Pure; no I/O. Checkpointed like the merger (one checkpoint per finding): the
 * synchronous {@link toStorageRows} is the reference, {@link toStorageRowsAsync} gives the event loop a turn every few milliseconds.
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
 * (component, locations, fix, rule name, raw reference) goes to `extra`.
 * @param {object} finding
 */
export function findingToDetail(finding) {
  const extra = {};
  if (finding.component) extra.component = finding.component;
  if (finding.locations) extra.locations = finding.locations;
  if (finding.locationCount !== undefined) extra.locationCount = finding.locationCount;
  if (finding.fix) extra.fix = finding.fix;
  if (finding.rule.name) extra.ruleName = finding.rule.name;
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
 * @returns {Generator<void, { items: object[], details: object[], truncated: boolean, dropped: number, severityCounts: Record<string, number> }, void>}
 */
function* storageSteps(findings, cap) {
  const items = [];
  const details = [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let dropped = 0;
  let truncated = false;
  for (const raw of findings) {
    yield;
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
    // `extra` is validated at write time: scrubbed like every other untrusted text, then strict, bounded and credential-free
    const extra = detailExtraSchema.safeParse(scrubDeep(detail.extra, []));
    if (!extra.success) {
      dropped += 1;
      continue;
    }
    detail = { ...detail, extra: extra.data };
    // an excerpt that still looks like a credential is not stored (the finding keeps its location); an oversized one is dropped too
    if (
      detail.evidence !== null &&
      (findCredentials(detail.evidence).length > 0 ||
        detailRowBytes(detail) > FINDING_LIMITS.detailRowBytes)
    )
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

/**
 * @param {unknown[]} findings @param {number} cap
 * @returns {{ items: object[], details: object[], truncated: boolean, dropped: number, severityCounts: Record<string, number> }}
 */
export function toStorageRows(findings, cap) {
  return runSync(storageSteps(findings, cap));
}

/**
 * The same projection, yielding to the event loop every few milliseconds.
 * @param {unknown[]} findings @param {number} cap @param {Parameters<typeof runYielding>[1]} [options]
 */
export function toStorageRowsAsync(findings, cap, options) {
  return runYielding(storageSteps(findings, cap), options);
}
