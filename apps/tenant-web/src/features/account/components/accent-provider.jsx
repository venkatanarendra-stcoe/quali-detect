import { DEFAULT_ACCENT } from "@qmentisai/shared";
import { useLayoutEffect } from "react";
import { useSession } from "@/features/auth/hooks/use-session.js";
import {
  applyAccent,
  clearCachedAccent,
  isAccentKey,
  readCachedAccent,
  writeCachedAccent,
} from "@/lib/accent.js";
import { usePreferences } from "../hooks/use-preferences.js";

/**
 * Applies the signed-in user's accent to <html data-accent>. It lives in tenant-web (not packages/ui) because it needs the
 * query client and the session. The dark/light mechanism is separate (`.dark` on <html>, see providers.jsx); the accent
 * CSS reacts to both. Behaviour:
 * - before the session/preferences resolve, the cached accent (applied pre-paint by index.html) is kept: no flash;
 * - authenticated: the fetched (or optimistically updated) accent wins and refreshes the cache;
 * - preferences fetch failed: mint (the default); unauthenticated: mint, cache cleared.
 */
export function AccentProvider({ children }) {
  const { status } = useSession();
  const authenticated = status === "authenticated";
  const preferences = usePreferences({ enabled: authenticated });
  const fetched = preferences.data?.accent;

  useLayoutEffect(() => {
    if (status === "loading") return; // keep what index.html applied from the cache
    if (!authenticated) {
      clearCachedAccent();
      applyAccent(DEFAULT_ACCENT);
      return;
    }
    if (isAccentKey(fetched)) {
      applyAccent(fetched);
      writeCachedAccent(fetched);
    } else if (preferences.isError) {
      applyAccent(DEFAULT_ACCENT);
    } else {
      applyAccent(readCachedAccent()); // preferences still loading
    }
  }, [status, authenticated, fetched, preferences.isError]);

  return children;
}
