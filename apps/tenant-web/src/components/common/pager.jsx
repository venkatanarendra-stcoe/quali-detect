import { Button } from "@/components/ui/button.jsx";
import { cn } from "@/lib/cn.js";

/** Previous/next controls with the item range. @param {{ pagination: object | null, onPage: (page: number) => void, className?: string }} props */
export function Pager({ pagination, onPage, className }) {
  if (!pagination || pagination.totalPages <= 1) return null;
  const { page, totalPages, totalItems } = pagination;
  return (
    <nav
      aria-label="Pagination"
      className={cn(
        "flex items-center justify-between text-sm text-muted-foreground",
        className ?? "mt-3",
      )}
    >
      <span>
        {totalItems} items · page {page} of {totalPages}
      </span>
      <div className="flex gap-2">
        <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          Previous
        </Button>
        <Button
          size="sm"
          variant="secondary"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
        >
          Next
        </Button>
      </div>
    </nav>
  );
}
