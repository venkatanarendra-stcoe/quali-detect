import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  LabelList,
  Line,
  LineChart,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  GROUP_LABELS,
  GROUP_STYLE,
  SEVERITY_FILL,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  SEVERITY_PATTERN,
} from "../constants/index.js";
import { LIFECYCLE_GROUP_IDS } from "@qmentisai/shared";
import { dayLabel, dayLong } from "../schemas/format.js";
import {
  AXIS,
  ChartTooltip,
  GRID_STROKE,
  PatternDefs,
  patternFill,
  useSafeId,
} from "./chart-parts.jsx";

/**
 * Recharts compositions of the reporting screens. Every chart keeps Recharts' accessibility layer (the plot takes keyboard focus and
 * the arrow keys move point by point, the tooltip follows), draws severity series with the `--sev-*` tokens in the fixed order
 * Critical to Info and a pattern per series, uses `--chart-1` (the selected accent) for the one primary series, and has a Table
 * view next to it (the card). No 3D, no gradients, no hard-coded colour.
 */

const MARGIN = { top: 8, right: 12, bottom: 0, left: 0 };
const dayTick = (day) => dayLabel(day);
const animation = { isAnimationActive: false };

const severityItems = () =>
  SEVERITY_ORDER.map((s) => ({ key: s, fill: SEVERITY_FILL[s], pattern: SEVERITY_PATTERN[s] }));

/** A shaded band over the days before the first rollup day: "no data" is a gap, never a zero. */
function NoDataBand({ points, dataFrom }) {
  if (!points.length) return null;
  const first = points[0].day;
  const missing =
    dataFrom === null
      ? points[points.length - 1].day
      : points.filter((p) => p.day < dataFrom).at(-1)?.day;
  if (!missing || missing < first) return null;
  return (
    <ReferenceArea
      x1={first}
      x2={missing}
      fill="var(--muted)"
      fillOpacity={0.7}
      ifOverflow="visible"
      label={{
        value: "no data",
        fill: "var(--subtle-foreground)",
        fontSize: 11,
        position: "insideTop",
      }}
    />
  );
}

/** Findings by severity: vertical bars, a bar toggles the `sev` filter (selected bars keep full strength). */
export function SeverityBarsChart({ counts, selected, onSelect }) {
  const id = useSafeId();
  const data = SEVERITY_ORDER.map((severity) => ({
    severity,
    label: SEVERITY_LABELS[severity],
    count: counts[severity] ?? 0,
  }));
  return (
    <ResponsiveContainer width="100%" height={224} minWidth={0}>
      <BarChart data={data} margin={MARGIN} accessibilityLayer>
        <PatternDefs id={id} items={severityItems()} />
        <CartesianGrid vertical={false} stroke={GRID_STROKE} />
        <XAxis dataKey="label" {...AXIS} />
        <YAxis allowDecimals={false} width={36} {...AXIS} />
        <Tooltip
          cursor={{ fill: "var(--muted)", fillOpacity: 0.5 }}
          content={<ChartTooltip labelFormatter={(l) => l} />}
        />
        <Bar
          dataKey="count"
          name="Open findings"
          cursor={onSelect ? "pointer" : undefined}
          onClick={onSelect ? (bar) => onSelect((bar.payload ?? bar).severity) : undefined}
          {...animation}
        >
          {data.map((d) => (
            <Cell
              key={d.severity}
              fill={patternFill(id, d.severity)}
              stroke={SEVERITY_FILL[d.severity]}
              fillOpacity={selected.length > 0 && !selected.includes(d.severity) ? 0.3 : 1}
            />
          ))}
          <LabelList
            dataKey="count"
            position="top"
            style={{ fill: "var(--foreground)", fontSize: 12 }}
          />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
/** The seven lifecycle groups as ONE stacked horizontal bar; every segment is named and counted in the legend beside it. */
export function LifecycleChart({ byGroup }) {
  const id = useSafeId();
  const row = { name: "Findings", ...byGroup };
  return (
    <ResponsiveContainer width="100%" height={92} minWidth={0}>
      <BarChart
        data={[row]}
        layout="vertical"
        margin={{ top: 4, right: 12, bottom: 0, left: 0 }}
        accessibilityLayer
      >
        <PatternDefs
          id={id}
          items={LIFECYCLE_GROUP_IDS.map((g) => ({ key: g, ...GROUP_STYLE[g] }))}
        />
        <XAxis type="number" allowDecimals={false} {...AXIS} />
        <YAxis type="category" dataKey="name" hide />
        <Tooltip
          cursor={{ fill: "var(--muted)", fillOpacity: 0.4 }}
          content={<ChartTooltip labelFormatter={() => "Findings by lifecycle group"} />}
        />
        {LIFECYCLE_GROUP_IDS.map((g) => (
          <Bar
            key={g}
            dataKey={g}
            name={GROUP_LABELS[g]}
            stackId="life"
            fill={patternFill(id, g)}
            stroke="var(--card)"
            {...animation}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Open findings by severity per day, stacked areas, Critical at the base. `hidden` = severities switched off. */
export function SeverityAreaChart({ points, dataFrom, hidden = [], height = 240 }) {
  const id = useSafeId();
  const data = points.map((p) => ({ day: p.day, ...(p.openBySeverity ?? {}) }));
  const shown = SEVERITY_ORDER.filter((s) => !hidden.includes(s));
  return (
    <ResponsiveContainer width="100%" height={height} minWidth={0}>
      <AreaChart data={data} margin={MARGIN} accessibilityLayer>
        <PatternDefs id={id} items={severityItems()} />
        <CartesianGrid vertical={false} stroke={GRID_STROKE} />
        <NoDataBand points={points} dataFrom={dataFrom} />
        <XAxis dataKey="day" tickFormatter={dayTick} minTickGap={28} {...AXIS} />
        <YAxis allowDecimals={false} width={36} {...AXIS} />
        <Tooltip content={<ChartTooltip labelFormatter={dayLong} />} />
        {shown.map((s) => (
          <Area
            key={s}
            type="linear"
            dataKey={s}
            name={SEVERITY_LABELS[s]}
            stackId="sev"
            stroke={SEVERITY_FILL[s]}
            fill={patternFill(id, s)}
            fillOpacity={1}
            connectNulls={false}
            {...animation}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

/**
 * New, fixed, closed without a fix and reopened per day. `combo`: bars for new, closed without a fix and reopened (hatched) and
 * the fixed line in the accent (`--chart-1`, the one primary series). `grouped`: the same four as grouped bars.
 */
export function FlowChart({ points, dataFrom, variant = "combo", hidden = [], height = 240 }) {
  const id = useSafeId();
  const data = points.map((p) => ({
    day: p.day,
    new: p.new ?? null,
    fixed: p.fixed ?? null,
    closedWithoutFix: p.closedWithoutFix ?? null,
    reopened: p.reopened ?? null,
  }));
  const on = (key) => !hidden.includes(key);
  return (
    <ResponsiveContainer width="100%" height={height} minWidth={0}>
      <ComposedChart data={data} margin={MARGIN} barGap={0} barCategoryGap="12%" accessibilityLayer>
        <PatternDefs
          id={id}
          items={[
            { key: "new", fill: "var(--chart-2)", pattern: "solid" },
            { key: "closed", fill: "var(--chart-3)", pattern: "solid" },
            { key: "reopened", fill: "var(--chart-4)", pattern: "stripe" },
            { key: "fixed", fill: "var(--chart-1)", pattern: "solid" },
          ]}
        />
        <CartesianGrid vertical={false} stroke={GRID_STROKE} />
        <NoDataBand points={points} dataFrom={dataFrom} />
        <XAxis dataKey="day" tickFormatter={dayTick} minTickGap={28} {...AXIS} />
        <YAxis allowDecimals={false} width={36} {...AXIS} />
        <Tooltip
          cursor={{ fill: "var(--muted)", fillOpacity: 0.4 }}
          content={<ChartTooltip labelFormatter={dayLong} />}
        />
        {on("new") ? (
          <Bar dataKey="new" name="New" fill={patternFill(id, "new")} {...animation} />
        ) : null}
        {on("closedWithoutFix") ? (
          <Bar
            dataKey="closedWithoutFix"
            name="Closed without a fix"
            fill={patternFill(id, "closed")}
            {...animation}
          />
        ) : null}
        {on("reopened") ? (
          <Bar
            dataKey="reopened"
            name="Reopened"
            fill={patternFill(id, "reopened")}
            {...animation}
          />
        ) : null}
        {variant === "grouped" && on("fixed") ? (
          <Bar dataKey="fixed" name="Fixed" fill={patternFill(id, "fixed")} {...animation} />
        ) : null}
        {variant === "combo" && on("fixed") ? (
          <Line
            type="linear"
            dataKey="fixed"
            name="Fixed"
            stroke="var(--chart-1)"
            strokeWidth={2}
            dot={false}
            connectNulls={false}
            {...animation}
          />
        ) : null}
      </ComposedChart>
    </ResponsiveContainer>
  );
}

/**
 * Lines over days: `series` = `[{ key, label, stroke, dash?, width? }]`. Used for the execution trend, the burn-down with its dashed
 * estimate, awaiting verification and the SBOM trend. A missing value stays a gap.
 */
export function LinesChart({
  data,
  series,
  dataFrom,
  points,
  height = 220,
  valueFormatter,
  yWidth = 36,
  xKey = "day",
  xFormatter = dayTick,
  labelFormatter = dayLong,
}) {
  return (
    <ResponsiveContainer width="100%" height={height} minWidth={0}>
      <LineChart data={data} margin={MARGIN} accessibilityLayer>
        <CartesianGrid vertical={false} stroke={GRID_STROKE} />
        {points ? <NoDataBand points={points} dataFrom={dataFrom} /> : null}
        <XAxis dataKey={xKey} tickFormatter={xFormatter} minTickGap={28} {...AXIS} />
        <YAxis allowDecimals={false} width={yWidth} {...AXIS} />
        <Tooltip
          content={<ChartTooltip labelFormatter={labelFormatter} valueFormatter={valueFormatter} />}
        />
        {series.map((s) => (
          <Line
            key={s.key}
            type="linear"
            dataKey={s.key}
            name={s.label}
            stroke={s.stroke}
            strokeWidth={s.width ?? 2}
            strokeDasharray={s.dash}
            dot={s.dot ?? false}
            connectNulls={false}
            {...animation}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

/**
 * Stacked or plain bars. `series` = `[{ key, label, fill, pattern }]`; `horizontal` puts the categories on the Y axis.
 */
export function BarsChart({
  data,
  series,
  xKey = "day",
  xFormatter,
  labelFormatter = (l) => l,
  horizontal = false,
  stacked = true,
  height = 240,
  dataFrom,
  points,
  yWidth = 36,
  valueFormatter,
  showLabels = false,
  tooltip,
}) {
  const id = useSafeId();
  return (
    <ResponsiveContainer width="100%" height={height} minWidth={0}>
      <BarChart
        data={data}
        layout={horizontal ? "vertical" : "horizontal"}
        margin={MARGIN}
        accessibilityLayer
      >
        <PatternDefs
          id={id}
          items={series.map((s) => ({ key: s.key, fill: s.fill, pattern: s.pattern ?? "solid" }))}
        />
        <CartesianGrid vertical={horizontal} horizontal={!horizontal} stroke={GRID_STROKE} />
        {points && !horizontal ? <NoDataBand points={points} dataFrom={dataFrom} /> : null}
        {horizontal ? (
          <>
            <XAxis type="number" allowDecimals={false} {...AXIS} />
            <YAxis
              type="category"
              dataKey={xKey}
              width={yWidth}
              tickFormatter={xFormatter}
              {...AXIS}
            />
          </>
        ) : (
          <>
            <XAxis dataKey={xKey} tickFormatter={xFormatter} minTickGap={28} {...AXIS} />
            <YAxis allowDecimals={false} width={yWidth} {...AXIS} />
          </>
        )}
        <Tooltip
          cursor={{ fill: "var(--muted)", fillOpacity: 0.4 }}
          content={
            tooltip ?? (
              <ChartTooltip labelFormatter={labelFormatter} valueFormatter={valueFormatter} />
            )
          }
        />
        {series.map((s) => (
          <Bar
            key={s.key}
            dataKey={s.key}
            name={s.label}
            stackId={stacked ? "a" : undefined}
            fill={patternFill(id, s.key)}
            {...animation}
          >
            {showLabels ? (
              <LabelList
                dataKey={s.key}
                position={horizontal ? "right" : "top"}
                style={{ fill: "var(--foreground)", fontSize: 12 }}
              />
            ) : null}
          </Bar>
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}
