import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/cn.js";

const Sheet = DialogPrimitive.Root;
const SheetTitle = DialogPrimitive.Title;
const SheetDescription = DialogPrimitive.Description;

/**
 * Right-hand side sheet on the Radix dialog: focus trap, Escape and overlay click close it, and focus returns to the
 * element that was focused when it opened (for example the table row). It keeps the normal Root Console theme.
 */
function SheetContent({ className, children, ...props }) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay
        data-slot="sheet-overlay"
        className="fixed inset-0 z-50 bg-black/60"
      />
      <DialogPrimitive.Content
        data-slot="sheet-content"
        className={cn(
          "fixed inset-y-0 right-0 z-50 flex w-full max-w-lg flex-col gap-4 overflow-y-auto border-l border-border bg-popover p-6 text-popover-foreground shadow-[var(--shadow-popover)]",
          className,
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close
          aria-label="Close"
          className="absolute top-3 right-3 flex size-7 items-center justify-center rounded-sm text-muted-foreground outline-none hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X aria-hidden="true" className="size-4" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export { Sheet, SheetContent, SheetDescription, SheetTitle };
