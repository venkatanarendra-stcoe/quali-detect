import { LayoutDashboard } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";

/**
 * Live preview of the three places the accent appears: primary action, active navigation, keyboard focus. Scoped to the
 * chosen accent with `data-accent-preview`, so it updates instantly and does not touch the rest of the page.
 * @param {{ accent: string }} props
 */
export function AccentPreview({ accent }) {
  return (
    <div
      data-accent-preview={accent}
      className="grid gap-4 rounded-md border border-border bg-card p-4 sm:grid-cols-3"
    >
      <div className="space-y-2">
        <p className="text-xs font-medium text-muted-foreground">Primary action</p>
        <Button tabIndex={-1} aria-label="Primary button sample">
          Primary action
        </Button>
      </div>
      <div className="space-y-2">
        <p className="text-xs font-medium text-muted-foreground">Active navigation</p>
        <div className="relative flex h-8 items-center gap-2.5 rounded-sm bg-sidebar-active px-2 text-sm font-medium text-sidebar-active-foreground before:absolute before:inset-y-1 before:left-0 before:w-0.5 before:rounded-full before:bg-primary">
          <LayoutDashboard aria-hidden="true" className="size-4" strokeWidth={1.75} />
          Overview
        </div>
      </div>
      <div className="space-y-2">
        <p className="text-xs font-medium text-muted-foreground">Keyboard focus</p>
        <div className="flex h-8 items-center justify-center rounded-sm border border-border-strong text-sm outline-2 outline-offset-2 outline-ring">
          Focused control
        </div>
      </div>
    </div>
  );
}
