import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef } from "react";
import { toast } from "sonner";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { useRealtime } from "@/features/executions/hooks/use-realtime.js";
import { useCursorList } from "@/hooks/use-cursor-list.js";
import { describeError, isApiError } from "@/lib/api/index.js";
import {
  HINT_DEBOUNCE_MS,
  POLL_MS,
  REPORT_POLL_MS,
  REPORTS_PAGE_SIZE,
} from "../constants/index.js";
import {
  REPORTING_MOCK_ENABLED,
  newIdempotencyKey,
  reportingService,
} from "../services/reporting-service.js";

/** Keys start with tenant, workspace, `reporting` (SCREENS 1): nothing crosses tenants or workspaces. */
export const reportingKeys = {
  workspace: (tenantId, workspaceId) => ["tenant", tenantId, "workspace", workspaceId, "reporting"],
  metric: (t, w, route, query) => [...reportingKeys.workspace(t, w), "metric", route, query],
  overview: (t, query) => ["tenant", t, "reporting", "overview", query],
  reports: (t, w, filters) => [...reportingKeys.workspace(t, w), "reports", filters],
  report: (t, w, id) => [...reportingKeys.workspace(t, w), "report", id],
};

/** A 4xx is an answer (403 hides or explains a section), never retried. */
export const retryTransient = (count, error) =>
  !(isApiError(error) && error.status >= 400 && error.status < 500) && count < 1;

/**
 * One reporting read: `{ data, meta }`, polled every 60 s while the tab is visible (TanStack pauses it in the background),
 * refetched on focus, and invalidated by the realtime hint. `route` is a key of `REPORTING_ROUTE_SCHEMAS`.
 * @param {string} route @param {string | null} workspaceId @param {Record<string, string | undefined>} query
 * @param {{ enabled?: boolean }} [options]
 */
export function useMetric(route, workspaceId, query, { enabled = true } = {}) {
  const tenantId = useTenantId();
  const full = workspaceId ? { workspaceId, ...query } : query;
  return useQuery({
    queryKey: workspaceId
      ? reportingKeys.metric(tenantId, workspaceId, route, query)
      : reportingKeys.overview(tenantId, query),
    queryFn: ({ signal }) => reportingService.read(route, full, { signal }),
    enabled: enabled && (workspaceId === null || Boolean(workspaceId)),
    refetchInterval: POLL_MS,
    staleTime: 15_000,
    retry: retryTransient,
  });
}

export const usePosture = (w, query, o) => useMetric("GET /reporting/posture", w, query, o);
export const useTrends = (w, query, o) => useMetric("GET /reporting/trends", w, query, o);
export const useRemediation = (w, query, o) => useMetric("GET /reporting/remediation", w, query, o);
export const useSla = (w, o) => useMetric("GET /reporting/sla", w, {}, o);
export const useAging = (w, o) => useMetric("GET /reporting/aging", w, {}, o);
export const useScanActivity = (w, query, o) =>
  useMetric("GET /reporting/scan-activity", w, query, o);
export const useCoverage = (w, o) => useMetric("GET /reporting/coverage", w, {}, o);
export const useSbom = (w, query, o) => useMetric("GET /reporting/sbom", w, query, o);
export const useQuality = (w, query, o) => useMetric("GET /reporting/quality", w, query, o);
export const useBreakdown = (w, query, o) => useMetric("GET /reporting/breakdown", w, query, o);
export const useTopRisk = (w, query, o) => useMetric("GET /reporting/top-risk", w, query, o);
export const useWorkload = (w, o) => useMetric("GET /reporting/workload", w, {}, o);
/** The Organization Overview has no workspace (a supplied one is a 400). */
export const useReportingOverview = (query, o) =>
  useMetric("GET /reporting/overview", null, query, o);

/**
 * Joins the EXISTING findings room of the workspace (the same `{ findingsWorkspaceId }` room the Findings screens use; no new
 * room) and invalidates the workspace's reporting queries when a `finding.changed` hint arrives, debounced by 5 s. The hint is ids
 * and enums only and is never shown: the screens refetch through the API. Polling stays as the fallback. With the mock, no socket.
 * @param {string | undefined} workspaceId @param {{ enabled?: boolean }} [options] @returns {{ live: boolean }}
 */
export function useReportingRealtime(workspaceId, { enabled = true } = {}) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  const timer = useRef(null);
  useEffect(() => () => clearTimeout(timer.current), []);
  const onHint = useCallback(
    (name) => {
      if (name !== "finding.changed" || !workspaceId) return;
      clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: reportingKeys.workspace(tenantId, workspaceId) });
      }, HINT_DEBOUNCE_MS);
    },
    [queryClient, tenantId, workspaceId],
  );
  return useRealtime({
    scope: "findings",
    id: workspaceId,
    enabled: enabled && Boolean(workspaceId) && !REPORTING_MOCK_ENABLED,
    onHint,
  });
}

/** The Refresh icon: refetches every reporting query of the scope and says whether one is running. @param {string | null} workspaceId */
export function useReportingRefresh(workspaceId) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  const filters = workspaceId
    ? { queryKey: reportingKeys.workspace(tenantId, workspaceId) }
    : {
        predicate: (query) =>
          query.queryKey[1] === tenantId && query.queryKey.includes("reporting"),
      };
  const fetching = useIsFetching(filters) > 0;
  const refresh = () => queryClient.invalidateQueries(filters);
  return { refresh, fetching };
}

const FINAL = new Set(["ready", "failed", "expired"]);
export const isFinalReport = (report) => FINAL.has(report.status);

/**
 * Generated reports of a workspace, cursor paged. A row that is queued or running is polled every 5 s, otherwise every 60 s.
 * @param {string} workspaceId @param {{ status?: string }} filters
 */
export function useReportsList(workspaceId, filters, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useCursorList({
    queryKey: reportingKeys.reports(tenantId, workspaceId, filters),
    fetchPage: async (cursor, signal) => {
      const page = await reportingService.listReports(
        { workspaceId, status: filters.status, limit: REPORTS_PAGE_SIZE, cursor },
        { signal },
      );
      return { items: page.items, pagination: { nextCursor: page.nextCursor } };
    },
    enabled,
    refetchInterval: (query) => {
      const pages = query.state.data?.pages ?? [];
      return pages.some((p) => p.items.some((r) => !isFinalReport(r))) ? REPORT_POLL_MS : POLL_MS;
    },
  });
}

/** One run (the details sheet); polled every 5 s until it is final. */
export function useReport(workspaceId, id) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: reportingKeys.report(tenantId, workspaceId, id),
    queryFn: ({ signal }) => reportingService.getReport(id, { signal }),
    enabled: Boolean(id),
    refetchInterval: (query) =>
      query.state.data && isFinalReport(query.state.data) ? false : REPORT_POLL_MS,
    retry: retryTransient,
  });
}

/** Saves a blob through an anchor and releases the object URL. @param {Blob} blob @param {string} fileName */
export function saveBlob(blob, fileName) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Generate: one idempotency key per dialog opening (a retry of the same action reuses it). @param {string | undefined} workspaceId */
export function useGenerateReport(workspaceId) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  const key = useRef(newIdempotencyKey());
  return {
    ...useMutation({
      mutationFn: (body) => reportingService.createReport(body, key.current),
      onSuccess: () => {
        key.current = newIdempotencyKey();
        toast.success("Report queued");
        queryClient.invalidateQueries({ queryKey: reportingKeys.workspace(tenantId, workspaceId) });
      },
    }),
    newKey: () => {
      key.current = newIdempotencyKey();
    },
  };
}

/** Download through an authenticated request (never a copyable URL). */
export function useDownloadReport() {
  return useMutation({
    mutationFn: async (id) => {
      const { blob, fileName } = await reportingService.downloadReport(id);
      saveBlob(blob, fileName);
    },
    onError: (error) =>
      toast.error(
        isApiError(error) && error.code === "REPORT_EXPIRED"
          ? "The report has expired. Generate it again."
          : describeError(error),
      ),
  });
}

export function useDeleteReport(workspaceId) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: (id) => reportingService.deleteReport(id),
    onSuccess: () => {
      toast.success("Report deleted");
      queryClient.invalidateQueries({ queryKey: reportingKeys.workspace(tenantId, workspaceId) });
    },
    onError: (error) => toast.error(describeError(error)),
  });
}
