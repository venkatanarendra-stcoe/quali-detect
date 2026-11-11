import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ErrorBoundary } from "@/components/states/error-boundary.jsx";
import { Toaster } from "@/components/ui/sonner.jsx";
import { TooltipProvider } from "@/components/ui/tooltip.jsx";
import { endSessionInCache } from "@/features/auth/services/session-cache.js";
import { isApiError, setUnauthenticatedHandler } from "@/lib/api/index.js";
import { useUiStore } from "./stores/ui-store.js";

/** 4xx responses are final; transport and 5xx failures retry twice. */
const shouldRetry = (failureCount, error) =>
  isApiError(error) && error.status >= 400 && error.status < 500 ? false : failureCount < 2;

function createQueryClient() {
  const client = new QueryClient({
    // networkMode "always": when the browser reports offline, requests still run and fail visibly (error state with retry)
    // instead of pausing forever behind a loading skeleton.
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        retry: shouldRetry,
        refetchOnWindowFocus: false,
        networkMode: "always",
      },
      mutations: { networkMode: "always" },
    },
  });
  return client;
}

function useResolvedTheme() {
  const theme = useUiStore((s) => s.theme);
  const [systemDark, setSystemDark] = useState(
    () => window.matchMedia("(prefers-color-scheme: dark)").matches,
  );
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e) => setSystemDark(e.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);
  return theme === "system" ? (systemDark ? "dark" : "light") : theme;
}

export function Providers({ children }) {
  const [queryClient] = useState(createQueryClient);
  // A 401 from a protected call means the session ended: drop cached data and let the route guards return to sign-in.
  // Registered in an effect, bound to the client React actually keeps (StrictMode runs the factory twice in development).
  useEffect(() => {
    setUnauthenticatedHandler(() => endSessionInCache(queryClient));
    return () => setUnauthenticatedHandler(() => {});
  }, [queryClient]);
  const resolvedTheme = useResolvedTheme();
  useEffect(() => {
    document.documentElement.classList.toggle("dark", resolvedTheme === "dark");
  }, [resolvedTheme]);
  return (
    <ErrorBoundary fullPage>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          {children}
          <Toaster theme={resolvedTheme} />
        </TooltipProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
