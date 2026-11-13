export const MODULE_NAME = "repositories";
export const API_PREFIX = "/api/v1";
export const OPENAPI_TAG = "Repositories";
export const SORTABLE_FIELDS = Object.freeze(["fullName", "connectedAt", "lastEventAt"]);

/** Keyset terms of the list sort fields (`fullName` and `connectedAt` are never null; `lastEventAt` is). `id` breaks ties. */
export const REPOSITORY_KEY_SPECS = Object.freeze({
  fullName: { type: "string" },
  connectedAt: { type: "date" },
  lastEventAt: { type: "date", nullable: true },
});
export const REPOSITORY_TIE = "asc";
