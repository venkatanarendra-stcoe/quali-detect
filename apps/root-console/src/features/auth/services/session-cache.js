import { PLATFORM_ME_KEY } from "./platform-auth-service.js";

/**
 * Discards every cached platform query EXCEPT the session query, whose Query object must survive: mounted route guards
 * observe it, and `queryClient.clear()` would leave them attached to a removed query that never updates.
 * @param {import("@tanstack/react-query").QueryClient} queryClient
 */
export function discardCacheKeepingSession(queryClient) {
  queryClient.removeQueries({
    predicate: (query) => query.queryKey.join("/") !== PLATFORM_ME_KEY.join("/"),
  });
}

/** Marks the session as ended (signed out); route guards redirect to sign-in. @param {import("@tanstack/react-query").QueryClient} queryClient */
export function endSessionInCache(queryClient) {
  discardCacheKeepingSession(queryClient);
  queryClient.setQueryData(PLATFORM_ME_KEY, null);
}
