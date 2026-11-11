import { cn } from "@/lib/cn.js";

/** Shared frame of the deliberate full-section states (empty, error, unauthorized, not found). */
export function StateLayout({ icon: Icon, title, children, actions, fullPage = false, role }) {
  return (
    <div
      className={cn(
        "flex items-center justify-center p-6",
        fullPage ? "min-h-screen bg-background" : "min-h-[40vh]",
      )}
    >
      <div role={role} className="flex max-w-md flex-col items-center gap-3 text-center">
        {Icon ? (
          <Icon aria-hidden="true" className="size-8 text-muted-foreground" strokeWidth={1.75} />
        ) : null}
        <h1 className="text-xl leading-7 font-semibold">{title}</h1>
        <div className="space-y-2 text-sm text-muted-foreground">{children}</div>
        {actions ? (
          <div className="mt-2 flex flex-wrap items-center justify-center gap-2">{actions}</div>
        ) : null}
      </div>
    </div>
  );
}
