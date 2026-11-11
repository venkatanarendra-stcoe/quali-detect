import { cva } from "class-variance-authority";
import { cn } from "@/lib/cn.js";

// Status chips are OUTLINED with a leading icon; tone colors only the icon and (danger/warning) text (DESIGN_SYSTEM.md §10).
const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap [&_svg]:size-3",
  {
    variants: {
      tone: {
        neutral: "border-border-strong text-foreground [&_svg]:text-status-neutral",
        success: "border-border-strong text-foreground [&_svg]:text-status-success",
        warning: "border-border-strong text-status-warning [&_svg]:text-status-warning",
        danger: "border-border-strong text-status-danger [&_svg]:text-status-danger",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

function Badge({ className, tone, ...props }) {
  return <span data-slot="badge" className={cn(badgeVariants({ tone }), className)} {...props} />;
}

export { Badge, badgeVariants };
