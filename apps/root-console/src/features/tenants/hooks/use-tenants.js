import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCursorList } from "@/hooks/use-cursor-list.js";
import { tenantsService } from "../services/tenants-service.js";

export const tenantKeys = {
  all: ["platform", "tenants"],
  list: (params) => ["platform", "tenants", "list", params],
  detail: (tenantId) => ["platform", "tenants", tenantId, "detail"],
  plans: ["platform", "plans"],
};

/** "Load more" tenant list; `params` are the filters, sort and `limit` (never a cursor or page). */
export function useTenantList(params) {
  return useCursorList({
    queryKey: tenantKeys.list(params),
    fetchPage: (cursor, signal) => tenantsService.list({ ...params, cursor }, { signal }),
  });
}

export function useTenantDetail(tenantId) {
  return useQuery({
    queryKey: tenantKeys.detail(tenantId),
    queryFn: ({ signal }) => tenantsService.get(tenantId, { signal }),
  });
}

/** Published plan versions (needs `platform.plan.view`; pass `enabled: false` without it). */
export function usePlans({ enabled = true } = {}) {
  return useQuery({
    queryKey: tenantKeys.plans,
    queryFn: ({ signal }) => tenantsService.plans({ signal }),
    enabled,
    staleTime: 60_000,
  });
}

export function useProvisionTenant() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: tenantsService.provision,
    onSuccess: (detail) => {
      queryClient.setQueryData(tenantKeys.detail(detail.tenant.id), detail);
      return queryClient.invalidateQueries({ queryKey: [...tenantKeys.all, "list"] });
    },
  });
}

/** suspend / reactivate / deactivate; the response is the fresh detail, so the page updates without a refetch. */
export function useTenantLifecycle(tenantId) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ action, ...body }) => tenantsService.changeLifecycle(tenantId, action, body),
    onSuccess: (detail) => {
      queryClient.setQueryData(tenantKeys.detail(tenantId), detail);
      return queryClient.invalidateQueries({ queryKey: [...tenantKeys.all, "list"] });
    },
  });
}
