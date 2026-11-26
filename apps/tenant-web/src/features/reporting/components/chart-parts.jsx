import { useId } from "react";
import { Link } from "react-router";
import { cn } from "@/lib/cn.js";

/**
 * Shared chart pieces (DESIGN_SYSTEM 2.4, UX 9): SVG pattern fills so colour is never the only signal, a legend whose items are
 * links, toggles or plain labels, and one tooltip. Colours are CSS variables read at paint time, so the dark and light themes and
 * the selected accent switch without re-rendering the charts.
 */

export const AXIS = Object.freeze({
  tick: { fill: "var(--subtle-foreground)", fontSize: 12 },
  stroke: "var(--chart-grid)",
  tickLine: false,
});
export const GRID_STROKE = "var(--chart-grid)";

/** A unique, CSS-safe id prefix (React ids contain colons). */
export function useSafeId(prefix = "rc") {
  return `${prefix}${useId().replace(/[^a-zA-Z0-9]/g, "")}`;
}

const SIZE = 6;
function PatternMarks({ kind }) {
  const mark = { stroke: "var(--card)", strokeOpacity: 0.6, strokeWidth: 1.4, fill: "none" };
  if (kind === "stripe") return <path d="M-1,1 l2,-2 M0,6 l6,-6 M5,7 l2,-2" {...mark} />;
  if (kind === "dots")
    return <circle cx="3" cy="3" r="1.1" style={{ fill: "var(--card)", fillOpacity: 0.7 }} />;
  if (kind === "cross") return <path d="M-1,1 l2,-2 M0,6 l6,-6 M5,7 l2,-2 M0,0 l6,6" {...mark} />;
  if (kind === "lines") return <path d="M0,3 h6" {...mark} />;
  return null;
}

/** `<pattern>` definitions to place inside a chart's `<defs>`; reference them with `patternFill`. @param {{ id: string, items: Array<{ key: string, fill: string, pattern: string }> }} props */
export function PatternDefs({ id, items }) {
  return (
    <defs>
      {items.map((item) => (
        <pattern
          key={item.key}
          id={`${id}-${item.key}`}
          patternUnits="userSpaceOnUse"
          width={SIZE}
          height={SIZE}
        >
          <rect width={SIZE} height={SIZE} style={{ fill: item.fill }} />
          <PatternMarks kind={item.pattern} />
        </pattern>
      ))}
    </defs>
  );
}
export const patternFill = (id, key) => `url(#${id}-${key})`;

/** A small legend swatch drawn with the same pattern as the series. */
export function Swatch({ fill, pattern = "solid", className }) {
  const id = useSafeId("sw");
  return (
    <svg
      aria-hidden="true"
      width="14"
      height="14"
      className={cn("shrink-0 rounded-[3px]", className)}
    >
      <PatternDefs id={id} items={[{ key: "s", fill, pattern }]} />
      <rect width="14" height="14" fill={`url(#${id}-s)`} />
    </svg>
  );
}

/**
 * Legend and direct labels in one: every item shows its swatch, its words and (optionally) its value, so a person who cannot tell
 * the colours apart still reads the series. An item with `href` is a link (drill-down), with `onToggle` a toggle button.
 * @param {{ items: Array<{ key: string, label: string, value?: string | number, fill: string, pattern?: string, href?: string, off?: boolean }>,
 *   onToggle?: (key: string) => void, label?: string, className?: string }} props
 */
export function Legend({ items, onToggle, label = "Legend", className }) {
  return (
    <ul aria-label={label} className={cn("flex flex-wrap gap-x-4 gap-y-1.5 text-xs", className)}>
      {items.map((item) => {
        const body = (
          <>
            <Swatch
              fill={item.fill}
              pattern={item.pattern}
              className={item.off ? "opacity-40" : undefined}
            />
            <span className={cn(item.off && "text-subtle-foreground line-through")}>
              {item.label}
            </span>
            {item.value !== undefined ? (
              <span className="font-medium text-foreground tabular-nums">{item.value}</span>
            ) : null}
          </>
        );
        const base =
          "inline-flex items-center gap-1.5 rounded-sm text-muted-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring";
        return (
          <li key={item.key}>
            {item.href ? (
              <Link to={item.href} className={cn(base, "hover:text-foreground hover:underline")}>
                {body}
              </Link>
            ) : onToggle ? (
              <button
                type="button"
                aria-pressed={!item.off}
                onClick={() => onToggle(item.key)}
                className={cn(base, "hover:text-foreground")}
              >
                {body}
              </button>
            ) : (
              <span className={base}>{body}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * The one tooltip. A series without a value shows "no data" (a zero is never drawn for a day without data); it is reachable by
 * keyboard focus because the charts keep Recharts' accessibility layer (arrow keys move through the points).
 * @param {{ active?: boolean, payload?: any[], label?: any, labelFormatter?: (label: any) => string,
 *   valueFormatter?: (value: number, entry: any) => string, hideZero?: boolean }} props
 */
export function ChartTooltip({ active, payload, label, labelFormatter, valueFormatter }) {
  if (!active || !payload?.length) return null;
  const head = labelFormatter ? labelFormatter(label) : String(label ?? "");
  return (
    <div
      role="status"
      className="rounded-md border border-border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-[var(--shadow-popover)]"
    >
      <p className="mb-1 font-medium">{head}</p>
      <ul className="space-y-0.5">
        {payload.map((entry) => (
          <li key={entry.dataKey ?? entry.name} className="flex items-center justify-between gap-4">
            <span className="inline-flex items-center gap-1.5 text-muted-foreground">
              <Swatch fill={entry.color ?? "var(--chart-2)"} />
              {entry.name}
            </span>
            <span className="font-medium tabular-nums">
              {entry.value === null || entry.value === undefined
                ? "no data"
                : valueFormatter
                  ? valueFormatter(entry.value, entry)
                  : String(entry.value)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
