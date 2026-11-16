import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/index.js";
import { cn } from "@/lib/cn.js";

/**
 * Sidebar system-status indicator (moved from the top bar). It reports only what this console can prove: whether the
 * platform API answers its public `/info` probe (polled every 60 s). Per-service health belongs to System monitoring
 * (planned). Text and dot together, never colour alone.
 */
export function SystemStatus() {
  const probe = useQuery({
    queryKey: ["platform", "system-status"],
    queryFn: ({ signal }) => api.get("/info", { signal, skipUnauthenticatedHandler: true }),
    refetchInterval: 60_000,
    retry: false,
    staleTime: 30_000,
  });
  const state = probe.isPending ? "checking" : probe.isError ? "down" : "up";
  const label = {
    checking: "Checking API status…",
    up: "API reachable",
    down: "API unreachable",
  }[state];
  return (
    <p
      role="status"
      data-state={state}
      className="flex items-center gap-2 px-2 text-xs text-sidebar-muted"
    >
      <span
        aria-hidden="true"
        className={cn(
          "size-2 shrink-0 rounded-full",
          state === "up" && "bg-status-success",
          state === "down" && "bg-status-danger",
          state === "checking" && "bg-sidebar-muted",
        )}
      />
      {label}
    </p>
  );
}
