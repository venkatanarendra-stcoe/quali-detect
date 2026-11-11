import { UnauthorizedState } from "@/components/states/unauthorized-state.jsx";
import { useCanPlatform } from "../hooks/use-platform-permissions.js";

/** Route guard: the page renders only with the `platform.*` permission, otherwise the 403 state. */
export function RequirePlatformPermission({ permission, children }) {
  const can = useCanPlatform();
  return can(permission) ? children : <UnauthorizedState />;
}
