import { useEffect, useRef, useState } from "react";
import { AlertIcon, ArrowDownIcon, ArrowUpIcon, CheckIcon, LockIcon, XIcon } from "./icons.jsx";
import { useScrollActivity } from "./use-scroll-activity.js";

const join = (...parts) => parts.filter(Boolean).join(" ");
const RESULT_TONES = {
  success: { Icon: CheckIcon, label: "success" },
  failure: { Icon: XIcon, label: "failure" },
  denied: { Icon: AlertIcon, label: "denied" },
};

/**
 * Result marker for a terminal row: icon AND text label, coloured by the status tokens (never colour alone).
 * @param {{ tone: "success" | "failure" | "denied" }} props
 */
export function TerminalResult({ tone }) {
  const { Icon, label } = RESULT_TONES[tone] ?? RESULT_TONES.success;
  return (
    <span className="qm-terminal-result" data-tone={tone in RESULT_TONES ? tone : "success"}>
      <Icon />
      {label}
    </span>
  );
}

/**
 * Message block for a terminal state slot (empty, error, unauthorized, ...).
 * @param {{ title: import("react").ReactNode, icon?: "alert" | "lock" | null, role?: string, children?: import("react").ReactNode }} props
 */
export function TerminalMessage({ title, icon = null, role, children }) {
  return (
    <div className="qm-terminal-message" role={role}>
      <p className="qm-terminal-message-title">
        {icon === "alert" ? <AlertIcon /> : icon === "lock" ? <LockIcon /> : null}
        {title}
      </p>
      {children ? <div className="qm-terminal-muted">{children}</div> : null}
    </div>
  );
}

/**
 * Audit-log terminal (owner-approved exception, DESIGN_SYSTEM.md "Audit-log terminal exception"): a log of rows in
 * monospace on an always-dark panel, in both app themes. Real text (selectable and copyable), no ASCII art or canvas.
 *
 * Semantics: a native `<table>` styled as a log (not role=list), so every cell keeps its column header for screen
 * readers; rows form a roving-tabindex set (one tab stop). ArrowUp/ArrowDown move between rows, Home/End jump to the
 * first/last, Enter or Space activates (`onRowActivate`). A single click activates too (after a 220 ms wait), but not while the user is selecting text (drag, double or triple click). `onRowActivate(row, rowElement)` also receives the row element so the opener can return focus to it.
 * The prompt line and the column header stay put while the rows scroll INSIDE the panel (thin fading scrollbar).
 * There is no "Load more": lists page with the shared numbered `Pagination`, rendered by the caller below the (always-dark)
 * panel in the normal app theme (owner decision 2026-11-16). State precedence: unauthorized > error > loading (no rows yet) > empty > rows.
 * Colour never carries meaning alone: use `TerminalResult` (icon + label) for outcomes.
 *
 * @param {{ promptLabel: string, rows: Array<object>, columns: Array<{ id: string, header: string, width?: string,
 *   sortKey?: string, cell: (row: any) => import("react").ReactNode, title?: (row: any) => string | undefined }>,
 *   getRowId: (row: any) => string, ariaLabel: string, command?: string, onRowActivate?: (row: any, element: HTMLElement) => void,
 *   selectedId?: string | null, rowLabel?: (row: any) => string, sort?: string, onSort?: (next: string) => void,
 *   loading?: boolean, error?: import("react").ReactNode, unauthorized?: import("react").ReactNode,
 *   empty?: import("react").ReactNode,
 *   className?: string }} props
 *   `promptLabel` is the prompt text (e.g. `acme@qmentisai:~$`); `command` is the muted text after it. `error`,
 *   `unauthorized` and `empty` are nodes (use `TerminalMessage`); passing `error`/`unauthorized` shows that state.
 *   `columns[].width` is a CSS width for the fixed table layout; `sortKey` makes the header a sort button
 *   (`sort` like `"createdAt:desc"`, `onSort` receives the next value). Long values wrap; `title` adds a tooltip.
 */
export function AuditTerminal({
  promptLabel,
  command = "tail -f audit.log",
  rows,
  columns,
  getRowId,
  ariaLabel,
  onRowActivate,
  selectedId = null,
  rowLabel,
  sort,
  onSort,
  loading = false,
  error,
  unauthorized,
  empty,
  className,
}) {
  const scrollRef = useRef(null);
  const bodyRef = useRef(null);
  const [active, setActive] = useState(0);
  useScrollActivity(scrollRef);

  const tabStop = Math.min(active, Math.max(rows.length - 1, 0));
  const rowEls = () => Array.from(bodyRef.current?.querySelectorAll("tr[data-row]") ?? []);
  const focusRow = (index) => {
    const els = rowEls();
    const next = Math.max(0, Math.min(index, els.length - 1));
    setActive(next);
    els[next]?.focus();
  };

  const clickTimer = useRef(null);
  useEffect(() => () => clearTimeout(clickTimer.current), []);
  const activate = (row, element) => onRowActivate?.(row, element);
  const onKeyDown = (event, index, row) => {
    if (event.target !== event.currentTarget) return;
    const keys = {
      ArrowDown: () => focusRow(index + 1),
      ArrowUp: () => focusRow(index - 1),
      Home: () => focusRow(0),
      End: () => focusRow(rows.length - 1),
      Enter: () => activate(row, event.currentTarget),
      " ": () => activate(row, event.currentTarget),
    };
    if (keys[event.key]) {
      event.preventDefault();
      keys[event.key]();
    }
  };

  const body = unauthorized
    ? "unauthorized"
    : error
      ? "error"
      : loading && rows.length === 0
        ? "loading"
        : rows.length === 0
          ? "empty"
          : "rows";
  const slot =
    body === "unauthorized"
      ? unauthorized
      : body === "error"
        ? error
        : body === "empty"
          ? (empty ?? <TerminalMessage title="No entries" />)
          : null;
  const [sortKey, sortDir] = (sort ?? "").split(":");

  return (
    <div data-audit-terminal="" className={join("qm-terminal", className)}>
      <div className="qm-terminal-prompt">
        <span className="qm-terminal-prompt-label">
          {promptLabel}
          {"\u00a0"}
        </span>
        <span className="qm-terminal-prompt-cmd">{command}</span>
      </div>
      <div
        ref={scrollRef}
        className="qm-scroll qm-terminal-scroll"
        tabIndex={rows.length === 0 ? 0 : undefined}
        role="region"
        aria-label={`${ariaLabel} (scrollable)`}
      >
        <table aria-label={ariaLabel} aria-busy={loading || undefined}>
          <thead>
            <tr>
              {columns.map((col) => {
                const sorted = col.sortKey && sortKey === col.sortKey;
                return (
                  <th
                    key={col.id}
                    scope="col"
                    style={col.width ? { width: col.width } : undefined}
                    aria-sort={
                      sorted ? (sortDir === "desc" ? "descending" : "ascending") : undefined
                    }
                  >
                    {col.sortKey && onSort ? (
                      <button
                        type="button"
                        onClick={() =>
                          onSort(`${col.sortKey}:${sorted && sortDir === "asc" ? "desc" : "asc"}`)
                        }
                      >
                        {col.header}
                        {sorted ? (
                          sortDir === "desc" ? (
                            <ArrowDownIcon className="size-3.5" />
                          ) : (
                            <ArrowUpIcon className="size-3.5" />
                          )
                        ) : null}
                      </button>
                    ) : (
                      col.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody ref={bodyRef}>
            {body === "loading" ? (
              <tr aria-hidden="true">
                <td colSpan={columns.length}>
                  <div style={{ display: "grid", gap: "0.75rem", padding: "0.5rem 0" }}>
                    {Array.from({ length: 6 }, (_, i) => (
                      <div
                        key={i}
                        className="qm-terminal-skeleton"
                        style={{ width: `${90 - i * 8}%` }}
                      />
                    ))}
                  </div>
                </td>
              </tr>
            ) : null}
            {slot ? (
              <tr>
                <td colSpan={columns.length}>{slot}</td>
              </tr>
            ) : null}
            {body === "rows"
              ? rows.map((row, index) => {
                  const id = getRowId(row);
                  return (
                    <tr
                      key={id}
                      data-row=""
                      tabIndex={index === tabStop ? 0 : -1}
                      aria-selected={onRowActivate ? id === selectedId : undefined}
                      aria-label={rowLabel?.(row)}
                      onFocus={() => setActive(index)}
                      onKeyDown={(e) => onKeyDown(e, index, row)}
                      onClick={(event) => {
                        // selecting text must not open the detail: skip drags, and wait out double/triple clicks (word/line select)
                        const element = event.currentTarget;
                        clearTimeout(clickTimer.current);
                        if (window.getSelection()?.isCollapsed === false || event.detail > 1)
                          return;
                        setActive(index);
                        clickTimer.current = setTimeout(() => {
                          if (window.getSelection()?.isCollapsed === false) return;
                          activate(row, element);
                        }, 220);
                      }}
                    >
                      {columns.map((col) => (
                        <td key={col.id} title={col.title?.(row)}>
                          {col.cell(row)}
                        </td>
                      ))}
                    </tr>
                  );
                })
              : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
