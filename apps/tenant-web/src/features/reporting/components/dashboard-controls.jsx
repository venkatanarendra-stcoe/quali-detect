import { BarChart3, Table2 } from "lucide-react";
import { cn } from "@/lib/cn.js";
import {
  SEVERITY_FILL,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  SEVERITY_PATTERN,
} from "../constants/index.js";
import { Swatch } from "./chart-parts.jsx";

/** Severity toggle chips: on or off, kept in the URL as `sev` (T-20, T-21). @param {{ params: any }} props */
export function SeverityFilter({ params }) {
  const { severities, toggleSeverity, clearSeverities } = params;
  return (
    <div
      className="flex flex-wrap items-center gap-1.5"
      role="group"
      aria-label="Filter by severity"
    >
      {SEVERITY_ORDER.map((s) => {
        const on = severities.includes(s);
        return (
          <button
            key={s}
            type="button"
            aria-pressed={on}
            onClick={() => toggleSeverity(s)}
            className={cn(
              "inline-flex h-7 items-center gap-1.5 rounded-sm border px-2 text-xs font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring",
              on
                ? "border-border-strong bg-secondary text-foreground"
                : "border-border text-muted-foreground hover:bg-accent",
            )}
          >
            <Swatch fill={SEVERITY_FILL[s]} pattern={SEVERITY_PATTERN[s]} />
            {SEVERITY_LABELS[s]}
          </button>
        );
      })}
      {severities.length ? (
        <button
          type="button"
          onClick={clearSeverities}
          className="rounded-sm px-1.5 text-xs text-primary-text underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
        >
          Clear
        </button>
      ) : null}
    </div>
  );
}

/** The whole dashboard as charts or tables (`view` in the URL: T-20 and T-21). @param {{ params: any }} props */
export function DashboardViewToggle({ params }) {
  const common =
    "inline-flex h-8 items-center gap-1.5 px-3 text-sm font-medium outline-none focus-visible:z-10 focus-visible:ring-2 focus-visible:ring-ring";
  return (
    <div
      role="group"
      aria-label="Dashboard view"
      className="inline-flex overflow-hidden rounded-sm border border-border-strong"
    >
      <button
        type="button"
        aria-pressed={params.view === "chart"}
        onClick={() => params.setView("chart")}
        className={cn(
          common,
          params.view === "chart"
            ? "bg-secondary text-foreground"
            : "text-muted-foreground hover:bg-accent",
        )}
      >
        <BarChart3 aria-hidden="true" className="size-4" />
        Charts
      </button>
      <button
        type="button"
        aria-pressed={params.view === "table"}
        onClick={() => params.setView("table")}
        className={cn(
          common,
          "border-l border-border-strong",
          params.view === "table"
            ? "bg-secondary text-foreground"
            : "text-muted-foreground hover:bg-accent",
        )}
      >
        <Table2 aria-hidden="true" className="size-4" />
        Tables
      </button>
    </div>
  );
}
