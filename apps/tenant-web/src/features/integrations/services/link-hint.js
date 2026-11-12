const KEY = "qmentisai.github-link-workspace";

/**
 * The workspace that started a GitHub link is remembered in session storage so the global setup and callback pages know
 * where to continue. It is only a hint: the API takes the workspace from its own stored state and re-checks the permission.
 */
export const linkHint = {
  read() {
    try {
      return window.sessionStorage.getItem(KEY) || null;
    } catch {
      return null;
    }
  },
  write(workspaceId) {
    try {
      window.sessionStorage.setItem(KEY, workspaceId);
    } catch {
      /* storage unavailable: the setup page asks for the workspace */
    }
  },
  clear() {
    try {
      window.sessionStorage.removeItem(KEY);
    } catch {
      /* nothing to clear */
    }
  },
};
