import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/cn.js";

/** Native select (accessible by default) styled like Input. Children are <option>s. */
function Select({ className, children, ...props }) {
  return (
    <div className="relative">
      <select
        data-slot="select"
        className={cn(
          "h-9 w-full appearance-none rounded-sm border border-input bg-secondary pr-8 pl-3 text-sm text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive",
          className,
        )}
        {...props}
      >
        {children}
      </select>
      <ChevronDown
        aria-hidden="true"
        className="pointer-events-none absolute top-2.5 right-2.5 size-4 text-muted-foreground"
      />
    </div>
  );
}

export { Select };
