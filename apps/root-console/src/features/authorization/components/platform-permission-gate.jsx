import { cloneElement, isValidElement } from "react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { useCanPlatform } from "../hooks/use-platform-permissions.js";

/**
 * Renders the single child DISABLED with an explanatory tooltip when `reason` is set, unchanged otherwise. The tooltip sits
 * on a focusable wrapper because disabled buttons receive no pointer or focus events.
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
 * Shows `children` only when the platform user holds the `platform.*` permission. mode "hide" (default) renders
 * `fallback`; mode "disable" renders the single child disabled with an explanatory tooltip.
 * @param {{ permission: string, mode?: "hide" | "disable", reason?: string, fallback?: any, children: any }} props
 */
export function PlatformPermissionGate({
  permission,
  mode = "hide",
  reason,
  fallback = null,
  children,
}) {
  const can = useCanPlatform();
  if (can(permission)) return children;
  if (mode === "hide" || !isValidElement(children)) return fallback;
  return (
    <DisabledWithReason reason={reason ?? "Your platform role does not include this action."}>
      {children}
    </DisabledWithReason>
  );
}
