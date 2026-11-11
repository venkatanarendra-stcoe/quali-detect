import { createApiClient } from "./api-client.js";

export { ApiError, describeError, isApiError } from "./api-error.js";

let onUnauthenticated = () => {};

/** Registers what happens on a 401 from a protected endpoint (set once by the providers). @param {() => void} handler */
export const setUnauthenticatedHandler = (handler) => {
  onUnauthenticated = handler;
};

/** The Root Console's API client. It only talks to `/platform/*` endpoints (paths are given by the services). */
export const api = createApiClient({
  baseUrl: import.meta.env.VITE_API_BASE_URL || "/api/v1",
  onUnauthenticated: () => onUnauthenticated(),
});
