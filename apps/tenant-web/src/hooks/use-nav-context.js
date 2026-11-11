import { useLocation } from "react-router";

const WORKSPACE_PATH = /^\/workspaces\/([^/]+)(?:\/([^/]+))?/;

/**
 * Chooses the layout from the URL (T-00a / T-00b): inside `/workspaces/:workspaceId/...` the Workspace layout applies,
 * everywhere else the Organization layout. `/workspaces/new` is an organization page, not a workspace id.
 * @param {string} pathname
 * @returns {{ layout: "organization" | "workspace", workspaceId: string | null, section: string | null }}
 */
export function parseNavContext(pathname) {
  const match = WORKSPACE_PATH.exec(pathname);
  if (match && match[1] !== "new")
    return { layout: "workspace", workspaceId: match[1], section: match[2] ?? null };
  return { layout: "organization", workspaceId: null, section: null };
}

/** React hook form of `parseNavContext` for the current location. */
export function useNavContext() {
  const { pathname } = useLocation();
  return parseNavContext(pathname);
}
