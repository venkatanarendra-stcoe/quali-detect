import { usePageList } from "@/hooks/use-page-list.js";
import { auditService } from "../services/audit-service.js";

export const auditKeys = { list: (params) => ["platform", "audit-logs", params] };

/** Numbered platform audit list; `params` are the filters and sort, `paging` the URL page state of `useListParams`. */
export function useAuditLogs(params, paging) {
  return usePageList({
    queryKey: auditKeys.list(params),
    fetchPage: ({ page, pageSize }, signal) =>
      auditService.list({ ...params, page, pageSize }, { signal }),
    ...paging,
  });
}
