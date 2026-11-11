import * as LabelPrimitive from "@radix-ui/react-label";
import { cn } from "@/lib/cn.js";

function Label({ className, ...props }) {
  return (
    <LabelPrimitive.Root
      data-slot="label"
      className={cn("text-sm leading-none font-medium select-none", className)}
      {...props}
    />
  );
}

export { Label };
