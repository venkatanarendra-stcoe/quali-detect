import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { SEVERITY_FILL, SEVERITY_LABELS } from "../constants/index.js";
import { AXIS, GRID_STROKE, PatternDefs, patternFill, useSafeId } from "./chart-parts.jsx";
import { SEVERITY_ORDER, SEVERITY_PATTERN } from "../constants/index.js";

/** The tooltip of the range bars: the median AND the p90 in words (a range bar is not a mean-only bar). */
function RangeTooltip({ active, payload }) {
  const row = active ? payload?.[0]?.payload : null;
  if (!row) return null;
  return (
    <div
      role="status"
      className="rounded-md border border-border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-[var(--shadow-popover)]"
    >
      <p className="mb-1 font-medium">{row.label}</p>
      <p className="tabular-nums">Median {row.median} d</p>
      <p className="tabular-nums">p90 {row.p90} d</p>
      <p className="text-muted-foreground tabular-nums">n = {row.count}</p>
    </div>
  );
}

/**
 * Time to remediate by severity as range bars: a solid bar up to the median and a lighter extension up to the p90 (the "box-style"
 * range of SCREENS T-47). `rows` = `[{ severity, median, p90, count }]`; a severity with no fixed findings is left out by the caller.
 * Colours are the `--sev-*` tokens with a pattern per severity.
 */
export function RangeBarsChart({ rows, height = 220 }) {
  const id = useSafeId();
  const data = rows.map((r) => ({
    ...r,
    label: SEVERITY_LABELS[r.severity],
    toP90: Math.max(0, Math.round((r.p90 - r.median) * 10) / 10),
  }));
  return (
    <ResponsiveContainer width="100%" height={height} minWidth={0}>
      <BarChart
        data={data}
        layout="vertical"
        margin={{ top: 8, right: 56, bottom: 0, left: 0 }}
        accessibilityLayer
      >
        <PatternDefs
          id={id}
          items={SEVERITY_ORDER.map((s) => ({
            key: s,
            fill: SEVERITY_FILL[s],
            pattern: SEVERITY_PATTERN[s],
          }))}
        />
        <CartesianGrid horizontal={false} stroke={GRID_STROKE} />
        <XAxis type="number" unit=" d" {...AXIS} />
        <YAxis type="category" dataKey="label" width={64} {...AXIS} />
        <Tooltip cursor={{ fill: "var(--muted)", fillOpacity: 0.4 }} content={<RangeTooltip />} />
        <Bar dataKey="median" name="Median" stackId="range" isAnimationActive={false}>
          {data.map((d) => (
            <Cell
              key={d.severity}
              fill={patternFill(id, d.severity)}
              stroke={SEVERITY_FILL[d.severity]}
            />
          ))}
        </Bar>
        <Bar dataKey="toP90" name="To p90" stackId="range" isAnimationActive={false}>
          {data.map((d) => (
            <Cell
              key={d.severity}
              fill={SEVERITY_FILL[d.severity]}
              fillOpacity={0.3}
              stroke={SEVERITY_FILL[d.severity]}
            />
          ))}
          <LabelList
            dataKey="p90"
            position="right"
            formatter={(v) => `p90 ${v} d`}
            style={{ fill: "var(--muted-foreground)", fontSize: 11 }}
          />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
