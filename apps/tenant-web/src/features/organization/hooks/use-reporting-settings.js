import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef } from "react";
import { toast } from "sonner";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { describeError } from "@/lib/api/index.js";
import { reportingSettingsService } from "../services/reporting-settings-service.js";

/** While a rebuild requested by a zone change runs, the settings are read again at this interval. */
export const RECOMPUTING_POLL_MS = 5000;

/** The tenant id is part of the key: nothing crosses tenants. */
export const reportingSettingsKey = (tenantId) => ["tenant", tenantId, "settings", "reporting"];

/** @param {{ enabled?: boolean }} [options] `enabled` is false without `tenant_settings.view` (no request is made) */
export function useReportingSettings({ enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: reportingSettingsKey(tenantId),
    queryFn: ({ signal }) => reportingSettingsService.get({ signal }),
    enabled,
    // a 404 is the module being off for this deployment: not worth retrying
    retry: (count, error) => error?.status !== 404 && count < 2,
    refetchInterval: (query) => (query.state.data?.recomputing ? RECOMPUTING_POLL_MS : false),
  });
}

/**
 * Saves the reporting time zone. The server answer replaces the cache (no optimistic write). One Idempotency-Key per chosen zone, so
 * pressing Save twice or a network retry cannot queue two rebuilds; when the cached reports of the old zone are stale the report queries
 * are invalidated.
 */
export function useUpdateReportingSettings() {
  const tenantId = useTenantId();
  const queryClient = useQueryClient();
  const key = useRef({ zone: null, id: null });
  return useMutation({
    /** @param {{ reportingTimezone: string }} body */
    mutationFn: (body) => {
      if (key.current.zone !== body.reportingTimezone)
        key.current = { zone: body.reportingTimezone, id: crypto.randomUUID() };
      return reportingSettingsService.update(body, key.current.id);
    },
    onSuccess: (stored, body) => {
      key.current = { zone: null, id: null };
      queryClient.setQueryData(reportingSettingsKey(tenantId), stored);
      queryClient.invalidateQueries({
        predicate: (query) =>
          query.queryKey[1] === tenantId &&
          query.queryKey.includes("reporting") &&
          !query.queryKey.includes("settings"),
      });
      toast.success(
        stored.recomputing
          ? `Reporting time zone set to ${body.reportingTimezone}.`
          : "Reporting time zone saved.",
        {
          description: stored.recomputing
            ? "Trends and daily counts are being recomputed. The change is recorded in the audit log."
            : "The change is recorded in the audit log.",
        },
      );
    },
    onError: (error) =>
      toast.error("Could not save the time zone.", { description: describeError(error) }),
  });
}
