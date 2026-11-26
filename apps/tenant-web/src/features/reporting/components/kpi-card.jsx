import { ArrowDown, ArrowUp, Minus } from "lucide-react";
import { Link } from "react-router";
import { Card } from "@/components/ui/card.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { describeError, isApiError } from "@/lib/api/index.js";
import { cn } from "@/lib/cn.js";
import { changeWords } from "../schemas/format.js";

/** A change since the start of the period: an arrow icon AND words, never colour alone. @param {{ delta: number | null, since?: string }} props */
export function Change({ delta, since = "since the start of the period" }) {
  if (delta === null || delta === undefined) return null;
  const Icon = delta === 0 ? Minus : delta < 0 ? ArrowDown : ArrowUp;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
      <Icon aria-hidden="true" className="size-3" />
      {changeWords(delta)} {since}
    </span>
  );
}

/**
 * One KPI tile. A tile with `href` is a link with a visible focus ring (a person without the permission of the target gets plain
 * text: the screen passes no `href`). Loading, error and value states are per tile, so one failure never blanks the page.
 * @param {{ id: string, label: string, query?: { isPending: boolean, isError: boolean, error: unknown, refetch: () => void },
 *   value?: import("react").ReactNode, sub?: import("react").ReactNode, change?: number | null, href?: string, tone?: "critical" | "danger",
 *   icon?: any, unavailable?: string }} props
 */
export function KpiCard({
  id,
  label,
  query,
  value,
  sub,
  change,
  href,
  tone,
  icon: Icon,
  unavailable,
  title,
}) {
  const pending = query?.isPending;
  const failed = query?.isError;
  const body = (
    <div className="space-y-1 p-4">
      <p className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        {Icon ? (
          <Icon
            aria-hidden="true"
            className={cn(
              "size-3.5",
              tone === "critical" && "text-sev-critical-fg",
              tone === "danger" && "text-status-danger",
            )}
          />
        ) : null}
        {label}
      </p>
      {pending ? <Skeleton className="h-8 w-20" /> : null}
      {failed ? (
        <p role="alert" className="text-sm text-muted-foreground">
          {isApiError(query.error) && query.error.status === 403
            ? "Not available to you."
            : describeError(query.error)}
          {isApiError(query.error) && query.error.status === 403 ? null : (
            <>
              {" "}
              <button type="button" className="underline" onClick={() => query.refetch()}>
                Retry
              </button>
            </>
          )}
        </p>
      ) : null}
      {!pending && !failed ? (
        <>
          <p
            className={cn(
              "text-[28px] leading-8 font-semibold tabular-nums",
              tone === "critical" && "text-sev-critical-fg",
              tone === "danger" && "text-status-danger",
            )}
          >
            {unavailable ? (
              <span className="text-sm font-normal text-muted-foreground">{unavailable}</span>
            ) : (
              value
            )}
          </p>
          {sub ? <p className="text-xs text-muted-foreground">{sub}</p> : null}
          {change !== undefined ? <Change delta={change} /> : null}
        </>
      ) : null}
    </div>
  );
  return (
    <Card data-testid={`kpi-${id}`} title={title} className="min-w-0 overflow-hidden">
      {href && !pending && !failed ? (
        <Link
          to={href}
          className="block rounded-lg outline-none hover:bg-secondary/60 focus-visible:ring-2 focus-visible:ring-ring"
        >
          {body}
        </Link>
      ) : (
        body
      )}
    </Card>
  );
}
