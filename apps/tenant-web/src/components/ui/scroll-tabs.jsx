import { useScrollActivity } from "@qmentisai/ui";
import { useRef } from "react";
import { Tabs, TabsContent } from "@/components/ui/tabs.jsx";
import { cn } from "@/lib/cn.js";

/**
 * Tabs for a page inside `AppPageLayout scroll={false}`: the tab bar (`TabsList`) stays fixed under the page header and
 * only the active panel (`ScrollTabsContent`) scrolls, with the thin fading scrollbar.
 */
export function ScrollTabs({ className, ...props }) {
  return <Tabs className={cn("flex min-h-0 flex-1 flex-col", className)} {...props} />;
}

/** Scrolling tab panel (see `ScrollTabs`). Put `flex flex-col` in `className` for a panel that hosts a filling table. */
export function ScrollTabsContent({ className, ...props }) {
  const ref = useRef(null);
  useScrollActivity(ref);
  return (
    <TabsContent
      ref={ref}
      className={cn("qm-scroll min-h-0 flex-1 overflow-y-auto pr-1 pb-4", className)}
      {...props}
    />
  );
}
