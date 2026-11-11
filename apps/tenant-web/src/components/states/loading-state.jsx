import { Skeleton } from "@/components/ui/skeleton.jsx";

/** Generic table/list skeleton. @param {{ rows?: number, label?: string }} props */
export function LoadingState({ rows = 5, label = "Loading" }) {
  return (
    <div role="status" aria-live="polite" aria-busy="true" className="space-y-2">
      <span className="sr-only">{label}…</span>
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
    </div>
  );
}

/** Full-screen skeleton while the session is being resolved. */
export function FullPageSkeleton() {
  return (
    <div
      role="status"
      aria-busy="true"
      className="flex min-h-screen items-center justify-center bg-background"
    >
      <span className="sr-only">Loading…</span>
      <div className="w-64 space-y-3">
        <Skeleton className="h-6 w-32" />
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-9 w-full" />
      </div>
    </div>
  );
}
