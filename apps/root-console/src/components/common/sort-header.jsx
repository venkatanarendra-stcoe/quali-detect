import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";

/**
 * Sortable column header. `sort` is the URL value (`field:asc|desc`); clicking toggles. Announces `aria-sort`.
 * @param {{ label: string, field: string, sort: string, onSort: (next: string) => void }} props
 */
export function SortHeader({ label, field, sort, onSort }) {
  const [activeField, direction] = (sort ?? "").split(":");
  const active = activeField === field;
  const Icon = !active ? ChevronsUpDown : direction === "desc" ? ArrowDown : ArrowUp;
  return (
    <th
      scope="col"
      aria-sort={active ? (direction === "desc" ? "descending" : "ascending") : "none"}
      className="px-3 py-2 font-medium"
    >
      <button
        type="button"
        onClick={() => onSort(`${field}:${active && direction !== "desc" ? "desc" : "asc"}`)}
        className="inline-flex items-center gap-1 rounded-sm outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
      >
        {label}
        <Icon aria-hidden="true" className="size-3.5" />
      </button>
    </th>
  );
}
