import {
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronsLeftIcon,
  ChevronsRightIcon,
} from "./icons.jsx";

/** "1 repository", "2 repositories": the singular of a regular English plural (items, entries, executions...). */
const singular = (noun) =>
  noun.endsWith("ies") ? `${noun.slice(0, -3)}y` : noun.endsWith("s") ? noun.slice(0, -1) : noun;

const join = (...parts) => parts.filter(Boolean).join(" ");

/** The default page sizes of every list (the executions API accepts exactly these). */
export const DEFAULT_PAGE_SIZES = Object.freeze([25, 50, 100]);

/**
 * The page numbers to render: always the first and last page, the current page and one neighbour each side, with `"gap"`
 * where pages are skipped. Seven or fewer pages show every number. A gap that would hide a single page shows that page.
 * @param {number} page current page, 1-based
 * @param {number} totalPages
 * @returns {Array<number | "gap">}
 */
export function pageWindow(page, totalPages) {
  if (totalPages <= 7) return Array.from({ length: Math.max(totalPages, 0) }, (_, i) => i + 1);
  const wanted = new Set([1, totalPages, page - 1, page, page + 1]);
  if (page <= 3) [2, 3, 4].forEach((n) => wanted.add(n));
  if (page >= totalPages - 2)
    [totalPages - 3, totalPages - 2, totalPages - 1].forEach((n) => wanted.add(n));
  const pages = [...wanted].filter((n) => n >= 1 && n <= totalPages).sort((a, b) => a - b);
  const out = [];
  pages.forEach((n, i) => {
    if (i > 0 && n - pages[i - 1] > 1) out.push("gap");
    out.push(n);
  });
  return out;
}

const button =
  "inline-flex h-8 min-w-8 items-center justify-center gap-1 rounded-sm border px-2 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0";
const idle = "border-border-strong bg-secondary hover:bg-accent disabled:hover:bg-secondary";
const current = "border-primary bg-primary text-primary-foreground hover:bg-primary-hover";
const cls = (active) => join(button, active ? current : idle);

/**
 * Numbered, page-based pagination shared by both apps (the owner-approved replacement of "Load more"). A `nav` landmark named
 * "Pagination" with real buttons: first, previous, numbered pages with ellipses (the current one has `aria-current="page"`),
 * next, last, a page-size select, and the text "Page X of Y" with the total (the total appears only here). The active page
 * uses the theme's primary colour (mint in the Tenant Application, violet in the Root Console); every control has a visible
 * focus ring. The component is controlled: the URL (page and limit) is the source of truth, owned by the caller.
 * @param {{ page: number, totalPages: number, totalItems: number, pageSize: number,
 *   onPageChange: (page: number) => void, onPageSizeChange?: (size: number) => void,
 *   pageSizes?: readonly number[], itemNoun?: string, note?: import("react").ReactNode, className?: string }} props
 *   `itemNoun` (plural, default "items") words the total. `note` is an extra sentence, e.g. that the list is capped.
 */
export function Pagination({
  page,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizes = DEFAULT_PAGE_SIZES,
  itemNoun = "items",
  note,
  className,
}) {
  const pages = Math.max(totalPages, 1);
  const here = Math.min(Math.max(page, 1), pages);
  const go = (n) => () => onPageChange(n);
  const label = (n) => `Go to page ${n}`;
  return (
    <nav
      aria-label="Pagination"
      className={join(
        "flex w-full flex-wrap items-center justify-between gap-x-4 gap-y-2 text-sm text-muted-foreground",
        className,
      )}
    >
      <p aria-live="polite" className="whitespace-nowrap">
        Page {here} of {pages} <span aria-hidden="true">·</span> {totalItems.toLocaleString()}{" "}
        {totalItems === 1 ? singular(itemNoun) : itemNoun}
        {note ? <span className="ml-2">{note}</span> : null}
      </p>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        {onPageSizeChange ? (
          <label className="flex items-center gap-2">
            <span>Rows per page</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="h-8 rounded-sm border border-border-strong bg-secondary px-2 text-sm text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {(pageSizes.includes(pageSize)
                ? pageSizes
                : [...pageSizes, pageSize].sort((a, b) => a - b)
              ).map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <ul className="flex flex-wrap items-center gap-1">
          <li>
            <button
              type="button"
              className={cls(false)}
              aria-label="First page"
              disabled={here <= 1}
              onClick={go(1)}
            >
              <ChevronsLeftIcon />
            </button>
          </li>
          <li>
            <button
              type="button"
              className={cls(false)}
              aria-label="Previous page"
              disabled={here <= 1}
              onClick={go(here - 1)}
            >
              <ChevronLeftIcon />
            </button>
          </li>
          {pageWindow(here, pages).map((n, i) =>
            n === "gap" ? (
              <li key={`gap-${i}`} aria-hidden="true" className="px-1">
                …
              </li>
            ) : (
              <li key={n}>
                <button
                  type="button"
                  className={cls(n === here)}
                  aria-label={n === here ? `Page ${n}, current page` : label(n)}
                  aria-current={n === here ? "page" : undefined}
                  onClick={n === here ? undefined : go(n)}
                >
                  {n}
                </button>
              </li>
            ),
          )}
          <li>
            <button
              type="button"
              className={cls(false)}
              aria-label="Next page"
              disabled={here >= pages}
              onClick={go(here + 1)}
            >
              <ChevronRightIcon />
            </button>
          </li>
          <li>
            <button
              type="button"
              className={cls(false)}
              aria-label="Last page"
              disabled={here >= pages}
              onClick={go(pages)}
            >
              <ChevronsRightIcon />
            </button>
          </li>
        </ul>
      </div>
    </nav>
  );
}
