import { Eye, TimerOff } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { useNow } from "@/hooks/use-now.js";
import { cn } from "@/lib/cn.js";

const MINUTE = 60_000;

/** "42 min", "1 h 05 min", "35 s". Pure; exported for reuse and checks. @param {number} ms */
export function formatRemaining(ms) {
  if (ms <= 0) return "0 s";
  if (ms < MINUTE) return `${Math.ceil(ms / 1000)} s`;
  const minutes = Math.ceil(ms / MINUTE);
  if (minutes < 60) return `${minutes} min`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m === 0 ? `${h} h` : `${h} h ${String(m).padStart(2, "0")} min`;
}

/**
 * Tenant drill-in banner (docs/design/ROOT_CONSOLE_DESIGN.md §1): while a platform user views a tenant through a support
 * access grant, a bar under the top bar names the tenant, the stated reason and the time left. Grants are scoped,
 * time-limited, read-only by default and audited (docs/AUTHORIZATION.md §5.10). This component only PRESENTS a grant;
 * the server decides whether access exists, and it refuses requests the moment the grant expires.
 *
 * States: active (neutral) -> expiring (last 10 minutes, warning) -> expired (danger, announced with role="alert").
 * @param {{
 *   tenantName: string,
 *   reason: string,
 *   expiresAt: Date | string | number,
 *   readOnly?: boolean,
 *   onEnd?: () => void,
 *   expiringSoonMinutes?: number,
 * }} props
 */
export function SupportAccessBanner({
  tenantName,
  reason,
  expiresAt,
  readOnly = true,
  onEnd,
  expiringSoonMinutes = 10,
}) {
  const expires = new Date(expiresAt).getTime();
  const now = useNow(1000);
  const remaining = expires - now;
  const expired = remaining <= 0;
  const expiring = !expired && remaining <= expiringSoonMinutes * MINUTE;
  const Icon = expired ? TimerOff : Eye;
  return (
    <div
      role={expired ? "alert" : "status"}
      data-state={expired ? "expired" : expiring ? "expiring" : "active"}
      className={cn(
        "flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-4 py-2 text-sm",
        expired
          ? "bg-[color-mix(in_oklab,var(--status-danger)_14%,var(--background))]"
          : expiring
            ? "bg-[color-mix(in_oklab,var(--status-warning)_14%,var(--background))]"
            : "bg-primary-tint",
      )}
    >
      <Icon
        aria-hidden="true"
        className={cn(
          "size-4 shrink-0",
          expired ? "text-status-danger" : expiring ? "text-status-warning" : "text-primary-text",
        )}
        strokeWidth={1.75}
      />
      <p className="min-w-0 flex-1">
        <span className="font-medium">{expired ? "Support access ended" : "Support access"}</span>
        {" to "}
        <span className="font-medium">{tenantName}</span>
        {readOnly ? <span className="text-muted-foreground"> · read-only</span> : null}
        <span className="text-muted-foreground"> · Reason: {reason}</span>
      </p>
      <p
        className={cn(
          "text-xs",
          expired
            ? "text-status-danger"
            : expiring
              ? "text-status-warning"
              : "text-muted-foreground",
        )}
      >
        {expired
          ? "Expired. Requests for this tenant are refused."
          : `Expires in ${formatRemaining(remaining)}`}
        <span className="text-subtle-foreground"> · All actions are audited</span>
      </p>
      {onEnd ? (
        <Button size="sm" variant="secondary" onClick={onEnd}>
          {expired ? "Close" : "End access"}
        </Button>
      ) : null}
    </div>
  );
}
