import { canPlatform } from "@qmentisai/shared/platform";
import { usePlatformSession } from "@/features/auth/hooks/use-platform-session.js";

const NONE = Object.freeze([]);

/** The `platform.*` permission keys of the signed-in platform user (from `GET /platform/me`). */
export function usePlatformPermissions() {
  const { me } = usePlatformSession();
  return me?.permissions ?? NONE;
}

/** `(permissionKey) => boolean` for `platform.*` keys only; usability aid (the API enforces). */
export function useCanPlatform() {
  const permissions = usePlatformPermissions();
  return (permissionKey) => canPlatform(permissions, permissionKey);
}
