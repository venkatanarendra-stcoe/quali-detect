import { describeError, isApiError } from "@/lib/api/index.js";

export const LINKING_DISABLED_MESSAGE =
  "Your organization has turned off linking source control from workspaces. Ask an organization administrator to turn it on.";

/** Message for a failed link/start/authorize call: the setting-off 403 gets the organization's wording. */
export function linkErrorMessage(error) {
  if (
    isApiError(error) &&
    error.status === 403 &&
    error.details?.reason === "workspace_linking_disabled"
  )
    return LINKING_DISABLED_MESSAGE;
  return describeError(error);
}
