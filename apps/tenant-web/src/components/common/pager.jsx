import { Pagination } from "@qmentisai/ui";
import { cn } from "@/lib/cn.js";

/**
 * Compact pager for small lists that keep their page in component state (webhook deliveries, allow list, repository
 * picker): the shared numbered `Pagination` without a page-size select. Hidden when there is one page or none.
 * @param {{ pagination: object | null, onPage: (page: number) => void, className?: string }} props
 */
export function Pager({ pagination, onPage, className }) {
  if (!pagination || pagination.totalPages <= 1) return null;
  const { page, totalPages, totalItems, pageSize } = pagination;
  return (
    <div className={cn(className ?? "mt-3")}>
      <Pagination
        page={page}
        totalPages={totalPages}
        totalItems={totalItems}
        pageSize={pageSize ?? 0}
        onPageChange={onPage}
      />
    </div>
  );
}
