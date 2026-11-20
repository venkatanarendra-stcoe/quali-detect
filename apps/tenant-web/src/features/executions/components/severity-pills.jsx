import { CircleAlert, CircleDot, Info, ShieldAlert, TriangleAlert } from "lucide-react";

export const SEVERITIES = [
  ["critical", "Critical", ShieldAlert],
  ["high", "High", TriangleAlert],
  ["medium", "Medium", CircleAlert],
  ["low", "Low", Info],
  ["info", "Info", CircleDot],
];
const SEVERITY_CLASS = {
  critical: "bg-sev-critical-bg text-sev-critical-fg",
  high: "bg-sev-high-bg text-sev-high-fg",
  medium: "bg-sev-medium-bg text-sev-medium-fg",
  low: "bg-sev-low-bg text-sev-low-fg",
  info: "bg-sev-info-bg text-sev-info-fg",
};

/** Severity pill: tinted fill + icon + label (never colour alone). The severity tokens are independent of the accent. */
export function SeverityPill({ severity, label, icon: Icon, count }) {
  return (
    <span
      className={`inline-flex h-5 items-center gap-1 rounded-full px-2 text-xs font-medium ${SEVERITY_CLASS[severity]}`}
    >
      <Icon aria-hidden="true" className="size-3" />
      {label} {count}
    </span>
  );
}

/**
 * The non-zero counts of a severity record as a list of pills (reads "High 3"). Renders nothing when every count is zero.
 * @param {{ counts?: Record<string, number>, label: string }} props
 */
export function SeverityPills({ counts, label }) {
  const shown = SEVERITIES.filter(([key]) => (counts?.[key] ?? 0) > 0);
  if (!shown.length) return null;
  return (
    <ul className="flex flex-wrap gap-1" aria-label={label}>
      {shown.map(([key, text, icon]) => (
        <li key={key}>
          <SeverityPill severity={key} label={text} icon={icon} count={counts[key]} />
        </li>
      ))}
    </ul>
  );
}
