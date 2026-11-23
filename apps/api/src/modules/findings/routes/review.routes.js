/**
 * Findings routes, part B: claim, review, withdraw, reopen-review, the Reviews queue and bulk claim (SPEC 8). EMPTY in the contract freeze (Part A0): the owning part fills
 * this file and builds its own controller, service and repository wiring INSIDE it from `deps`, so the module index and the other
 * route files never change. The route keys and their permissions are frozen in `PERMISSION_BY_ROUTE` of `@qmentisai/shared`.
 * @param {import("./index.js").FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsReviewRoutes = (deps) =>
  async function register(app) {
    void deps;
    void app;
  };
