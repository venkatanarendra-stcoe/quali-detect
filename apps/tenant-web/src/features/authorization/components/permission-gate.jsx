import { cloneElement, isValidElement } from "react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { useCan } from "../hooks/use-permissions.js";

/**
 * Renders the single child element DISABLED with an explanatory tooltip when `reason` is set, and unchanged otherwise.
 * The tooltip sits on a focusable wrapper because disabled buttons receive no pointer or focus events. Use it directly for
 * conditions that are not a single permission (several permissions, archived workspace, quota).
 * @param {{ reason?: string | null, children: any }} props
 */
export function DisabledWithReason({ reason, children }) {
  if (!reason || !isValidElement(children)) return children;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          role="button"
          aria-disabled="true"
          tabIndex={0}
          className="inline-flex rounded-sm"
          aria-label={`Unavailable: ${reason}`}
        >
          {cloneElement(children, { disabled: true, "aria-hidden": true, tabIndex: -1 })}
        </span>
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  );
}

/**
 * Shows `children` only when the user holds `permission` (usability aid; the backend enforces).
 * - mode "hide" (default): renders `fallback` (nothing by default) when not permitted.
 * - mode "disable": renders the child disabled with a tooltip explaining why (`reason`).
 * `scope` is optional; see `useCan`.
 * @param {{ permission: string, scope?: object, mode?: "hide" | "disable", reason?: string, fallback?: any, children: any }} props
 */
export function PermissionGate({
  permission,
  scope,
  mode = "hide",
  reason,
  fallback = null,
  children,
}) {
  const can = useCan();
  if (can(permission, scope)) return children;
  if (mode === "hide" || !isValidElement(children)) return fallback;
  return (
    <DisabledWithReason reason={reason ?? "You don't have permission to do this."}>
      {children}
    </DisabledWithReason>
  );
}
