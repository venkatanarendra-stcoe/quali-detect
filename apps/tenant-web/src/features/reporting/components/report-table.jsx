import { ArrowDown, ArrowUp } from "lucide-react";
import { useMemo, useState } from "react";
import { cn } from "@/lib/cn.js";

/**
 * A small semantic table for the cards and the Table view of a chart: `scope="col"` headers, a sticky header, an internal scroll
 * (max 320 px, as T-21) that is itself focusable, and header buttons that sort with the keyboard. Cells are React nodes, so every
 * untrusted string is escaped text. Row ids are never shown to the person except through the cell content.
 * @param {{ caption: string, columns: Array<{ key: string, header: string, cell: (row: any) => import("react").ReactNode,
 *   sortValue?: (row: any) => number | string, align?: "right", className?: string }>, rows: any[], getRowId: (row: any) => string,
 *   maxHeight?: string, defaultSort?: { key: string, desc?: boolean }, empty?: string, footerRow?: import("react").ReactNode }} props
 */
export function ReportTable({
  caption,
  columns,
  rows,
  getRowId,
  maxHeight = "20rem",
  defaultSort,
  empty = "Nothing to show.",
  footerRow,
}) {
  const [sort, setSort] = useState(defaultSort ?? null);
  const sorted = useMemo(() => {
    const column = columns.find((c) => c.key === sort?.key);
    if (!column?.sortValue) return rows;
    const factor = sort.desc ? -1 : 1;
    return [...rows].sort((a, b) => {
      const x = column.sortValue(a);
      const y = column.sortValue(b);
      return (x < y ? -1 : x > y ? 1 : 0) * factor;
    });
  }, [rows, columns, sort]);
  const toggle = (column) =>
    setSort((current) =>
      current?.key === column.key
        ? { key: column.key, desc: !current.desc }
        : { key: column.key, desc: false },
    );
  return (
    <div
      className="qm-scroll overflow-auto rounded-md border border-border"
      style={{ maxHeight }}
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
      tabIndex={0}
      role="region"
      aria-label={`${caption} (scrollable)`}
    >
      <table className="w-full border-separate border-spacing-0 text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => {
              const active = sort?.key === column.key;
              return (
                <th
                  key={column.key}
                  scope="col"
                  aria-sort={active ? (sort.desc ? "descending" : "ascending") : undefined}
                  className={cn(
                    "sticky top-0 z-10 border-b border-border bg-card px-3 py-2 text-left text-xs font-medium whitespace-nowrap text-muted-foreground",
                    column.align === "right" && "text-right",
                  )}
                >
                  {column.sortValue ? (
                    <button
                      type="button"
                      onClick={() => toggle(column)}
                      className="-mx-1 inline-flex items-center gap-1 rounded-sm px-1 outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      {column.header}
                      {active ? (
                        sort.desc ? (
                          <ArrowDown aria-hidden="true" className="size-3.5" />
                        ) : (
                          <ArrowUp aria-hidden="true" className="size-3.5" />
                        )
                      ) : null}
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="px-3 py-6 text-center text-sm text-muted-foreground"
              >
                {empty}
              </td>
            </tr>
          ) : (
            sorted.map((row) => (
              <tr key={getRowId(row)} className="hover:bg-secondary/50">
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={cn(
                      "border-b border-border px-3 py-2 align-top tabular-nums",
                      column.align === "right" && "text-right",
                      column.className,
                    )}
                  >
                    {column.cell(row)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
        {footerRow ? <tfoot>{footerRow}</tfoot> : null}
      </table>
    </div>
  );
}
