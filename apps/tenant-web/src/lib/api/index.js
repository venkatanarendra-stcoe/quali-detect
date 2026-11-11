import { createApiClient } from "./api-client.js";

export { createApiClient } from "./api-client.js";
export { ApiError, describeError, isApiError } from "./api-error.js";

let onUnauthenticated = () => {};

/** Registers what happens on a 401 from a protected endpoint (set once by the providers). @param {() => void} handler */
export const setUnauthenticatedHandler = (handler) => {
  onUnauthenticated = handler;
};

/** The app's API client (single instance; holds no tenant or user state). */
export const api = createApiClient({
  baseUrl: import.meta.env.VITE_API_BASE_URL || "/api/v1",
  onUnauthenticated: () => onUnauthenticated(),
});
