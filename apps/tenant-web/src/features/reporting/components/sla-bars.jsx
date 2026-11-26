import { Link } from "react-router";
import { SLA_STATE_STYLE } from "../constants/index.js";
import { slaFindingsUrl } from "../schemas/drilldown.js";
import { formatCount } from "../schemas/format.js";
import { Swatch } from "./chart-parts.jsx";

/**
 * SLA status of open findings as three progress bars (On track, Due soon, Breached): no donut (SPEC 13). The state names, counts and
 * share are text; the bar carries a pattern for Due soon. Each count is a drill-down link into the Findings list when the person may
 * see findings (otherwise plain text). The 25 percent rule is the server's.
 * @param {{ total: { onTrack: number, dueSoon: number, breached: number }, workspaceId: string, canDrill: boolean }} props
 */
export function SlaBars({ total, workspaceId, canDrill }) {
  const all = total.onTrack + total.dueSoon + total.breached;
  return (
    <ul className="space-y-3">
      {Object.entries(SLA_STATE_STYLE).map(([key, style]) => {
        const count = total[key];
        const share = all ? Math.round((count / all) * 100) : 0;
        const label = (
          <span className="tabular-nums">
            <span className="font-medium">{formatCount(count)}</span>{" "}
            <span className="text-muted-foreground">({share}%)</span>
          </span>
        );
        return (
          <li key={key}>
            <div className="mb-1 flex items-center justify-between gap-2 text-sm">
              <span className="inline-flex items-center gap-1.5">
                <Swatch fill={style.fill} pattern={style.pattern} />
                {style.label}
              </span>
              {canDrill && count > 0 ? (
                <Link
                  to={slaFindingsUrl(workspaceId, style.filter)}
                  className="rounded-sm underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
                  aria-label={`${style.label}: ${count} open findings. Open in Findings`}
                >
                  {label}
                </Link>
              ) : (
                label
              )}
            </div>
            <div
              role="progressbar"
              aria-label={`${style.label} share of open findings with an SLA`}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={share}
              className="h-2.5 overflow-hidden rounded-full bg-muted"
            >
              <div
                className="h-full rounded-full"
                style={{
                  width: `${share}%`,
                  background:
                    style.pattern === "stripe"
                      ? `repeating-linear-gradient(135deg, ${style.fill} 0 4px, color-mix(in srgb, ${style.fill} 45%, var(--card)) 4px 8px)`
                      : style.fill,
                }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}
