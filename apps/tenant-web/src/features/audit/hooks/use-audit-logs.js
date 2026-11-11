import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { auditService } from "../services/audit-service.js";

/** Cache keys start with the tenant, so entries never leak across tenants. */
export const auditKeys = { list: (tenantId, params) => ["tenant", tenantId, "audit-logs", params] };

export function useAuditLogs(params) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: auditKeys.list(tenantId, params),
    queryFn: ({ signal }) => auditService.list(params, { signal }),
    placeholderData: keepPreviousData,
  });
}
