/** Entitlement keys used by metered operations. A key absent from the entitlement catalog is ungoverned (unlimited). */
export const ENTITLEMENT_KEYS = Object.freeze({
  WORKSPACES_MAX: "workspaces.max",
  USERS_MAX: "users.max",
  REPOSITORIES_MAX: "repositories.max",
});
