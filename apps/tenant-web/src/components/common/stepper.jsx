import { Check } from "lucide-react";
import { cn } from "@/lib/cn.js";

/**
 * Horizontal stepper (wizard pattern): completed = check icon, current = foreground text with a 2px underline,
 * upcoming = muted. Never mint/violet. @param {{ steps: string[], current: number }} props
 */
export function Stepper({ steps, current }) {
  return (
    <ol
      aria-label="Progress"
      className="mb-6 flex flex-wrap gap-x-6 gap-y-2 border-b border-border"
    >
      {steps.map((label, index) => {
        const done = index < current;
        const active = index === current;
        return (
          <li
            key={label}
            aria-current={active ? "step" : undefined}
            className={cn(
              "-mb-px flex items-center gap-2 border-b-2 pb-2 text-sm",
              active
                ? "border-foreground font-medium text-foreground"
                : "border-transparent text-muted-foreground",
            )}
          >
            <span
              className={cn(
                "flex size-5 items-center justify-center rounded-full border text-xs",
                done ? "border-status-success text-status-success" : "border-border-strong",
              )}
            >
              {done ? <Check aria-hidden="true" className="size-3" /> : index + 1}
            </span>
            {label}
            {done ? <span className="sr-only"> (completed)</span> : null}
          </li>
        );
      })}
    </ol>
  );
}
