import { Slot } from "@radix-ui/react-slot";
import { cva } from "class-variance-authority";
import { cn } from "@/lib/cn.js";

// One mint `default` button per view; everything else is secondary/outline/ghost (DESIGN_SYSTEM.md §6).
const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 rounded-sm text-sm font-medium whitespace-nowrap transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary-hover",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-accent border border-border-strong",
        outline: "border border-border-strong bg-transparent hover:bg-accent",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        destructive: "bg-destructive text-destructive-foreground hover:opacity-90",
        link: "text-primary-text underline-offset-4 hover:underline",
      },
      size: { default: "h-8 px-3", sm: "h-7 px-2.5 text-[13px]", lg: "h-9 px-4", icon: "size-8" },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

/** @param {{ asChild?: boolean, variant?: string, size?: string } & import("react").ComponentProps<"button">} props */
function Button({ className, variant, size, asChild = false, type = "button", ...props }) {
  const Comp = asChild ? Slot : "button";
  return (
    <Comp
      data-slot="button"
      type={asChild ? undefined : type}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  );
}

export { Button, buttonVariants };
