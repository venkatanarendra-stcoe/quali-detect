import { cn } from "@/lib/cn.js";

/**
 * Accessible on/off switch (native button with role="switch", no extra dependency). Always give it an accessible name
 * (`aria-label` or `aria-labelledby`). Mint is allowed for the on state: it is a primary control state, not decoration.
 * @param {{ checked: boolean, onCheckedChange?: (next: boolean) => void } & Omit<import("react").ComponentProps<"button">, "onChange">} props
 */
function Switch({ checked, onCheckedChange, className, disabled, ...props }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      data-slot="switch"
      disabled={disabled}
      onClick={() => onCheckedChange?.(!checked)}
      className={cn(
        "inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-border-strong p-0.5 transition-colors outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "bg-primary" : "bg-secondary",
        className,
      )}
      {...props}
    >
      <span
        aria-hidden="true"
        className={cn(
          "block size-3.5 rounded-full bg-foreground transition-transform",
          checked ? "translate-x-4 bg-primary-foreground" : "translate-x-0",
        )}
      />
    </button>
  );
}

export { Switch };
