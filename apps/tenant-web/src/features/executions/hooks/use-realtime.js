import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { realtime } from "../services/realtime-client.js";

/**
 * Subscribes the component to the hints of one workspace or execution while it is mounted and `enabled`. `onHint(name, hint)`
 * must refetch through the API; hints are never data. `live` is true only when the socket is connected AND the server accepted
 * the join: any other state means the page polls (the status, never the socket, is the truth).
 * @param {{ scope: "workspace" | "execution" | "findings", id?: string, enabled?: boolean,
 *   onHint?: (name: string, hint: any) => void }} options
 * @returns {{ live: boolean, connection: string, subscription: string, lastLiveAt: string | null, retry: () => void }}
 */
export function useRealtime({ scope, id, enabled = true, onHint }) {
  const connection = useSyncExternalStore(realtime.watch, realtime.getSnapshot);
  const [joined, setJoined] = useState({ key: "", state: "pending" });
  const handler = useRef(onHint);
  useEffect(() => {
    handler.current = onHint;
  });
  const key = `${scope}:${id}`;
  useEffect(() => {
    if (!enabled || !id) return undefined;
    return realtime.subscribe({
      scope,
      id,
      onHint: (name, hint) => handler.current?.(name, hint),
      onState: (state) => setJoined({ key, state }),
    });
  }, [scope, id, enabled, key]);
  const subscription = enabled && id && joined.key === key ? joined.state : "pending";
  return {
    live: enabled && Boolean(id) && connection.connection === "live" && subscription === "joined",
    connection: connection.connection,
    subscription,
    lastLiveAt: connection.lastLiveAt,
    retry: realtime.retry,
  };
}
