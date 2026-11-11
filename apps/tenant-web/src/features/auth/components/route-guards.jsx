import { Navigate, Outlet, useLocation } from "react-router";
import { ErrorState } from "@/components/states/error-state.jsx";
import { FullPageSkeleton } from "@/components/states/loading-state.jsx";
import { TenantBlockedPage } from "../pages/tenant-blocked-page.jsx";
import { useSession } from "../hooks/use-session.js";

/** Keeps `next` a same-origin app path (no open redirect). @param {string | null} next */
export function safeNextPath(next) {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/login"))
    return "/";
  return next;
}

/** Protected routes: signed in, otherwise to the login page (remembering where the user was going). */
export function RequireAuth() {
  const { status, error, refetch } = useSession();
  const location = useLocation();
  if (status === "loading") return <FullPageSkeleton />;
  if (status === "anonymous") {
    const next = `${location.pathname}${location.search}`;
    return (
      <Navigate to={next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`} replace />
    );
  }
  if (status === "tenant-blocked") return <TenantBlockedPage />;
  if (status === "error") return <ErrorState fullPage error={error} onRetry={refetch} />;
  return <Outlet />;
}

/** Application routes need an active tenant; users without one choose it first. */
export function RequireTenant() {
  const { me } = useSession();
  if (!me?.tenant) return <Navigate to="/select-tenant" replace />;
  return <Outlet />;
}

/** The login page is only for signed-out visitors; signed-in visitors continue to `next` (or the landing page). */
export function PublicOnly({ children }) {
  const { status } = useSession();
  const location = useLocation();
  if (status === "loading") return <FullPageSkeleton />;
  if (status === "authenticated") {
    return <Navigate to={safeNextPath(new URLSearchParams(location.search).get("next"))} replace />;
  }
  return children;
}
