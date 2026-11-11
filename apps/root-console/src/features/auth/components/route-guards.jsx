import { Navigate, Outlet, useLocation } from "react-router";
import { ErrorState } from "@/components/states/error-state.jsx";
import { FullPageSkeleton } from "@/components/states/loading-state.jsx";
import { usePlatformSession } from "../hooks/use-platform-session.js";

/** Keeps `next` a same-origin app path (no open redirect). @param {string | null} next */
export function safeNextPath(next) {
  if (!next || !next.startsWith("/") || next.startsWith("//") || /^\/(login|mfa)(\/|$)/.test(next))
    return "/";
  return next;
}

const withNext = (path, location) => {
  const next = `${location.pathname}${location.search}`;
  return next === "/" ? path : `${path}?next=${encodeURIComponent(next)}`;
};

/** Protected routes: a signed-in AND MFA-verified platform session, otherwise login or the MFA screen. */
export function RequirePlatformAuth() {
  const { status, error, refetch } = usePlatformSession();
  const location = useLocation();
  if (status === "loading") return <FullPageSkeleton />;
  if (status === "anonymous") return <Navigate to={withNext("/login", location)} replace />;
  if (status === "mfa-required") return <Navigate to={withNext("/mfa", location)} replace />;
  if (status === "error") return <ErrorState fullPage error={error} onRetry={refetch} />;
  return <Outlet />;
}

/** The login page is for signed-out visitors; an MFA-pending visitor continues to /mfa. */
export function PublicOnly({ children }) {
  const { status } = usePlatformSession();
  const location = useLocation();
  const next = safeNextPath(new URLSearchParams(location.search).get("next"));
  if (status === "loading") return <FullPageSkeleton />;
  if (status === "authenticated") return <Navigate to={next} replace />;
  if (status === "mfa-required")
    return (
      <Navigate to={next === "/" ? "/mfa" : `/mfa?next=${encodeURIComponent(next)}`} replace />
    );
  return children;
}

/** The MFA screen exists only between password sign-in and verification. */
export function MfaOnly({ children }) {
  const { status } = usePlatformSession();
  const location = useLocation();
  const next = safeNextPath(new URLSearchParams(location.search).get("next"));
  if (status === "loading") return <FullPageSkeleton />;
  if (status === "authenticated") return <Navigate to={next} replace />;
  if (status === "anonymous") return <Navigate to="/login" replace />;
  return children;
}
