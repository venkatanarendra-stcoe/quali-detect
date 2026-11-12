/** Entitlement keys used by metered operations. A key absent from the entitlement catalog is ungoverned (unlimited). */
export const ENTITLEMENT_KEYS = Object.freeze({
  WORKSPACES_MAX: "workspaces.max",
  USERS_MAX: "users.max",
  REPOSITORIES_MAX: "repositories.max",
  PIPELINES_MAX: "pipelines.max",
});

/** Consumable quota keys (quota definitions). `scans.monthly` is metered per UTC month (periodKey `YYYY-MM`). */
export const QUOTA_KEYS = Object.freeze({
  SCANS_MONTHLY: "scans.monthly",
});
