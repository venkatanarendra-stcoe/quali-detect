import {
  FINDING_SORTS,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  FINDING_SCAN_TYPES,
  SAVED_VIEW_IDS,
  FINDINGS_LIMITS,
} from "@qmentisai/shared";

/**
 * Filters of the Findings screens live in the URL (SCREENS 1): this reads them defensively (an unknown value is dropped, never
 * sent to the API, which answers 400 for unknown filters) and turns them into the API's query parameters.
 */

const list = (value, allowed) =>
  (value ?? "")
    .split(",")
    .map((v) => v.trim())
    .filter((v) => allowed.includes(v));
const SLA_FILTERS = ["on_track", "due_soon", "breached", "none"];
const AI_FILTERS = ["likely_true_positive", "likely_false_positive", "uncertain", "none"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** @param {URLSearchParams} params */
export function readFindingFilters(params) {
  const q = (params.get("q") ?? "").trim().slice(0, FINDINGS_LIMITS.queryMax);
  const assignee = params.get("assignee") ?? "";
  const [sortField, sortDir] = (params.get("sort") ?? "").split(":");
  return {
    view: SAVED_VIEW_IDS.includes(params.get("view") ?? "") ? params.get("view") : "",
    severity: list(params.get("severity"), FINDING_SEVERITIES),
    status: list(params.get("status"), FINDING_STATUSES),
    scanType: list(params.get("scanType"), FINDING_SCAN_TYPES),
    pipeline: UUID.test(params.get("pipeline") ?? "") ? params.get("pipeline") : "",
    repository: UUID.test(params.get("repository") ?? "") ? params.get("repository") : "",
    assignee: ["me", "unassigned"].includes(assignee) || UUID.test(assignee) ? assignee : "",
    sla: list(params.get("sla"), SLA_FILTERS),
    ai: AI_FILTERS.includes(params.get("ai") ?? "") ? params.get("ai") : "",
    q: q.length >= FINDINGS_LIMITS.queryMin ? q : "",
    qRaw: q,
    sort: FINDING_SORTS.includes(sortField) ? sortField : "severity",
    dir:
      sortDir === "asc" || sortDir === "desc"
        ? sortDir
        : sortField === "slaDueAt" || sortField === "title"
          ? "asc"
          : "desc",
  };
}

/** The URL value of a sort (`field:dir`), empty for the default (severity, high first). */
export const sortParam = (field, dir) =>
  field === "severity" && dir === "desc" ? "" : `${field}:${dir}`;

/** Number of active facet filters (not the saved view, not the sort). @param {ReturnType<typeof readFindingFilters>} f */
export const activeFilterCount = (f) =>
  [
    f.severity.length,
    f.status.length,
    f.scanType.length,
    f.pipeline,
    f.repository,
    f.assignee,
    f.sla.length,
    f.ai,
    f.q,
  ].filter(Boolean).length;

/** API query (without `workspaceId`, `page`, `pageSize`). @param {ReturnType<typeof readFindingFilters>} f @param {string} view */
export function toListQuery(f, view) {
  return {
    // an explicit status filter replaces the saved view (otherwise "Verified fixed" could never be listed under "All open")
    view: f.status.length ? undefined : view || undefined,
    severity: f.severity.join(",") || undefined,
    status: f.status.join(",") || undefined,
    scanType: f.scanType.join(",") || undefined,
    pipelineId: f.pipeline || undefined,
    repositoryId: f.repository || undefined,
    assignee: f.assignee || undefined,
    sla: f.sla.join(",") || undefined,
    aiSuggestion: f.ai || undefined,
    q: f.q || undefined,
    sort: f.sort,
    direction: f.dir,
  };
}

/** Parses `?finding=<uuid>` style selection ids defensively. @param {string | null} value */
export const readId = (value) => (value && UUID.test(value) ? value : "");
