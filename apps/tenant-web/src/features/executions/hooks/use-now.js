import { useEffect, useState } from "react";

/** The current time, ticking every second while `enabled` (the live duration of a running execution). */
export function useNow(enabled) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [enabled]);
  return now;
}
