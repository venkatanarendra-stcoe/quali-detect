import { cn } from "@/lib/cn.js";
import { environment } from "@/lib/environment.js";

const TONE = {
  neutral: "bg-secondary text-muted-foreground",
  warning:
    "bg-[color-mix(in_oklab,var(--status-warning)_16%,var(--background))] text-status-warning",
  danger: "bg-[color-mix(in_oklab,var(--status-danger)_16%,var(--background))] text-status-danger",
};

/**
 * Thin strip across the top of every screen (including sign-in) naming the environment, so an operator always knows
 * whether they are touching development, staging or production. Text, not color alone.
 * @param {{ env?: typeof environment }} props
 */
export function EnvironmentStrip({ env = environment }) {
  return (
    <div
      role="note"
      aria-label={`Environment: ${env.label}`}
      data-environment={env.id}
      className={cn(
        "sticky top-0 z-40 flex h-6 shrink-0 items-center justify-center gap-2 border-b border-border text-[11px] font-semibold tracking-wider uppercase",
        TONE[env.tone],
      )}
    >
      <span>{env.label}</span>
      <span aria-hidden="true">·</span>
      <span className="font-normal tracking-normal normal-case">{env.note}</span>
    </div>
  );
}
