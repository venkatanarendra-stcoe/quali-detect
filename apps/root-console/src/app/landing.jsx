import { Navigate } from "react-router";
import { evaluatePlatformNavigation } from "@qmentisai/shared/platform";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { usePlatformPermissions } from "@/features/authorization/hooks/use-platform-permissions.js";
import { NAV_ITEMS } from "@/components/layout/nav.js";
import { isRouteAvailable } from "./routes.jsx";
import { ShieldOff } from "lucide-react";

/** `/`: the first page the platform role may open (normally the dashboard), else a "no access" state. */
export function LandingRedirect() {
  const permissions = usePlatformPermissions();
  const first = evaluatePlatformNavigation({ permissions, isRouteAvailable })[0]?.items[0];
  if (first) return <Navigate to={NAV_ITEMS[first.id].to} replace />;
  return (
    <EmptyState
      icon={ShieldOff}
      title="No access yet"
      description="Your platform role does not include any available page. Contact a platform administrator."
    />
  );
}
