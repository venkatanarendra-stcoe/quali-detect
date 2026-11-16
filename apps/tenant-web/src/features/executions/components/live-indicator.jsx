import { Radio, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { clockTime } from "./execution-bits.jsx";

/**
 * Live-update state in words: "Live" (icon + text) when hints flow, otherwise a muted "paused" / "Reconnecting" text and the
 * page polls (the status, never the socket, is the truth). `compact` is the list form ("Live updates paused" + Retry); the
 * detail form says "Reconnecting, last update 12:03". Nothing is shown while the first connection is being made.
 * @param {{ state: { live: boolean, connection: string, subscription: string, lastLiveAt: string | null, retry: () => void },
 *   lastUpdate?: string | null, variant?: "list" | "detail", hidden?: boolean }} props
 */
export function LiveIndicator({ state, lastUpdate, variant = "list", hidden = false }) {
  if (hidden) return null;
  if (state.live)
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
        <Radio aria-hidden="true" className="size-3.5" />
        Live
      </span>
    );
  if (state.connection === "idle" || state.connection === "connecting") return null;
  const gaveUp = state.connection === "unavailable" || state.subscription === "denied";
  const since = lastUpdate ?? state.lastLiveAt;
  const text =
    variant === "detail"
      ? `${gaveUp ? "Live updates paused" : "Reconnecting"}${since ? `, last update ${clockTime(since)}` : ""}`
      : gaveUp
        ? "Live updates paused"
        : "Reconnecting";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
      <WifiOff aria-hidden="true" className="size-3.5" />
      {text}
      {gaveUp && state.connection === "unavailable" ? (
        <Button variant="ghost" size="sm" className="h-6 px-1.5 text-xs" onClick={state.retry}>
          Retry
        </Button>
      ) : null}
    </span>
  );
}
