import { Bell } from "lucide-react";
import { useRef } from "react";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet.jsx";
import { cn } from "@/lib/cn.js";

/**
 * Unread notification count. There is no notifications API yet (T-04 is a Recommended screen), so this is the single
 * place to wire it later; the badge renders only for a positive count.
 * @returns {number}
 */
export function useUnreadNotificationCount() {
  return 0;
}

/**
 * Sidebar "Notifications" item with its unread badge; opens the notifications drawer (right sheet, focus trap, Escape
 * closes, focus returns to this item).
 * @param {{ open: boolean, onOpenChange: (open: boolean) => void, itemClassName: string }} props
 */
export function NotificationsItem({ open, onOpenChange, itemClassName }) {
  const unread = useUnreadNotificationCount();
  const buttonRef = useRef(null);
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="dialog"
        aria-label={unread > 0 ? `Notifications, ${unread} unread` : "Notifications"}
        onClick={() => onOpenChange(true)}
        className={cn(itemClassName)}
      >
        <Bell
          aria-hidden="true"
          className="size-4 shrink-0 text-muted-foreground"
          strokeWidth={1.75}
        />
        <span className="flex-1 truncate text-left">Notifications</span>
        {unread > 0 ? (
          <span
            aria-hidden="true"
            data-testid="unread-badge"
            className="min-w-5 rounded-full bg-status-danger px-1.5 text-center text-[11px] leading-5 font-semibold text-white"
          >
            {unread > 99 ? "99+" : unread}
          </span>
        ) : null}
      </button>
      <SheetContent
        className="max-w-sm"
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          buttonRef.current?.focus();
        }}
      >
        <SheetTitle className="text-base font-semibold">Notifications</SheetTitle>
        <SheetDescription className="text-sm text-muted-foreground">
          Approvals, failed executions and assignments will appear here.
        </SheetDescription>
        <p
          role="status"
          className="rounded-md border border-border p-4 text-sm text-muted-foreground"
        >
          You have no notifications.
        </p>
      </SheetContent>
    </Sheet>
  );
}
