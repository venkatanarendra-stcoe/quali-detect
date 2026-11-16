import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { usePageList } from "@/hooks/use-page-list.js";
import { auditService } from "../services/audit-service.js";

/** Cache keys start with the tenant, so entries never leak across tenants. */
export const auditKeys = { list: (tenantId, params) => ["tenant", tenantId, "audit-logs", params] };

/** Numbered audit list; `params` are the filters and sort, `paging` the URL page state of `useListParams`. */
export function useAuditLogs(params, paging) {
  const tenantId = useTenantId();
  return usePageList({
    queryKey: auditKeys.list(tenantId, params),
    fetchPage: ({ page, pageSize }, signal) =>
      auditService.list({ ...params, page, pageSize }, { signal }),
    ...paging,
  });
}
